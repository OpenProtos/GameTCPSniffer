import asyncio
from typing import Any, List, Sequence 
import queue
import threading
import logging

import aiofiles
import aiosqlite
from textual.app import App, ComposeResult
from textual.widgets import Static, Input, RichLog
from textual.events import Key
from textual.containers import Vertical, Horizontal
from scapy.all import sniff, Packet

from src.parser import CommandProcessor, create_runtime_parser, create_start_config_from_args 
from src.servers import get_game_servers, generate_packet_handler
from src.decoder import TCPDecoder
from src.database import get_database_worker, get_last_session_id
from src.utils import Message, TCP_Message, ConfigItem


class TCPSnifferApp(App[None]):
    BINDINGS = [
        ("up,k", "history(-1)", "Previous statement"),  


        ("down,j", "history(1)", "Following statement"),
    ]


    def __init__(self, history: List[str] = []) -> None:
        super().__init__()
        self._restart_requested = False
        self._new_args: Sequence[str] = []
        self.logger = logging.getLogger("tcp_sniffer")
        self.history = history
        self.history_index = len(self.history)


    async def initialize(self, arguments: Sequence[str]) -> bool:
        self.logger.info("Initializing app...")

        printer = self.add_message
        printer_display = self.add_display
        self._used_args = arguments
        self.config = create_start_config_from_args(arguments)
        self.runtime_parser = create_runtime_parser()

        self.add_message_and_log(f"{'Monitoring ports':<35}: {self.config.ports}")
        self.add_message_and_log(f"{'Capturing protos':<35}: {self.config.protos}")
        self.add_message_and_log(f"{'Ignoring protos':<35}: {self.config.blacklist}")
        self.add_message_and_log(f"{'Magic bytes used to decode protos':<35}: {self.config.magic_bytes!r}")
        self.add_message_and_log("Getting servers...")

        servs = get_game_servers(self.config.ports, printer)
        if not servs:
            self.logger.error(f"Script is closing, no servers on port {self.config.ports} were found.")
            raise RuntimeError(f"Script is closing, no servers on port {self.config.ports} were found.")
        self.add_message_and_log(f"Starting packet capture for {servs} servers...")
        self.ip_servs = [ip for (ip, _) in servs]

        async with aiosqlite.connect(self.config.db_path / "tcp.db") as db:
            async with aiofiles.open(self.config.sc_path, encoding="utf-8") as file:
                await db.executescript(await file.read())
            await db.commit()

        # getting the last session id
        self.db_connection = await aiosqlite.connect(self.config.db_path / "tcp.db")
        last_session_id = await get_last_session_id(self.db_connection)

        # event to cancel threads
        self.cancel_event = threading.Event()

        # queue for communication between tasks
        queue_cfg_decoder = asyncio.Queue[ConfigItem](maxsize=100)
        queue_msg_decoder = queue.Queue[Message](maxsize=100)
        queue_com_decoder = asyncio.Queue[TCP_Message](maxsize=100)

        self.command_processor = CommandProcessor(
            self.add_result,
            self.clear,
            self.request_restart,
            self._used_args,
            queue_cfg_decoder,
            self.runtime_parser.format_usage()
        )

        # sniffer thread
        packet_handler = generate_packet_handler(queue_msg_decoder, printer)

        def custom_prn(pkt: Packet) -> None:
            return packet_handler(pkt, self.ip_servs)

        def custom_stop_filter(_: Any) -> bool:
            return self.cancel_event.is_set()

        sn_task = asyncio.create_task(
            asyncio.to_thread(
                lambda: sniff(
                    filter="tcp", 
                    prn=custom_prn, 
                    store=0, 
                    stop_filter=custom_stop_filter
                )
            )
        )

        # decoder task
        de_worker = TCPDecoder.get_decoder(
            queue_cfg_decoder,
            queue_msg_decoder, 
            queue_com_decoder,
            self.config,
            printer,
            printer_display
        )
        de_task = asyncio.create_task(de_worker())

        self.add_message_and_log("Decoder worker started")

        # database task
        db_worker = get_database_worker(queue_com_decoder, last_session_id + 1, printer)
        db_task = asyncio.create_task(db_worker(self.db_connection))

        self.add_message_and_log("Database worker started")

        self.tasks = [
            sn_task,
            de_task,
            db_task,
        ]

        return True


    def compose(self) -> ComposeResult:
        with Vertical():
            self.log_area = Horizontal()
            with self.log_area:
                self.packet_log = RichLog()
                self.packet_display = RichLog()
                yield self.packet_log
                yield self.packet_display

            self.command_area = Vertical()
            with self.command_area:
                self.result = Static("")
                self.command_input = Input(placeholder="type help for more information ...")
                yield self.result
                yield self.command_input


    def on_mount(self) -> None:
        self.result.styles.padding = 1
        self.command_area.styles.height = "1fr"
        self.log_area.styles.height = "4fr"


    def on_input_submitted(self, event: Input.Submitted) -> None:

        command = event.value 

        try:
            args, remainder = self.runtime_parser.parse_known_args(command.split())
            asyncio.create_task(
                self.command_processor.process(
                    self.config, 
                    args,
                    remainder
                )
            )
            self.history.append(command)
            self.history_index = len(self.history)

        except Exception as e:
            self.add_result(f"Invalid command: {e}")
            self.logger.error(e)
        except SystemExit as e:
            if e.code != 0:
                raise ValueError("Invalid arguments") from e

        self.command_input.clear()


    def action_history(self, amout: int) -> None:

        self.history_index += amout

        if self.history:
            self.history_index %= len(self.history)

        if self.history:
            self.command_input.clear()
            self.command_input.insert(self.history[self.history_index], 0)
            self.command_input.action_end()


    def add_message_and_log(self, message: str) -> None:
        self.packet_log.write(message)
        self.logger.info(message)


    def add_message(self, message: str) -> None:
        self.packet_log.write(message)


    def add_display(self, message: str) -> None:
        self.packet_display.write(message)


    def add_result(self, result: str) -> None:
        self.result.update(result)


    def on_exception(self, exception: Exception) -> None:
        self.add_message(f"App error: {exception}")


    async def request_restart(self, new_args: Sequence[str]) -> None:
        self._restart_requested = True
        self._new_args = new_args
        self.logger.info(f"Restarting with {' '.join(self._new_args) if self._new_args else 'no args'}")
        self.exit()


    def on_key(self, event: Key) -> None:
        if event.key == "ctrl+c":
            self.exit()


    async def on_exit(self) -> None:
        self.logger.info("Cleaning up...")

        if hasattr(self, "cancel_event"):
            self.cancel_event.set()

        if hasattr(self, "tasks"):
            for task in self.tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.logger.info("All tasks cleaned up.")

        if hasattr(self, "db_connection") and self.db_connection:
            await self.db_connection.close()
            self.logger.info("Connection closed.")


    def clear(self) -> None:
        self.packet_log.clear()
        self.packet_display.clear()


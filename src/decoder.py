# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

from __future__ import annotations

import asyncio
import logging
import hashlib
from importlib import import_module
from pathlib import Path
import queue
import re
import subprocess
from types import ModuleType
from typing import Callable, Coroutine, List, Optional, Tuple, Self

from attrs import define, field

from scapy.layers.inet import TCP
from scapy.all import Packet
from google.protobuf.any_pb2 import Any
from google.protobuf.json_format import MessageToJson

from src.utils import (
    ByteArrayRepr,
    GameProtocolConfig,
    Message,
    TCP_Message,
    ConfigItem,
)
from src.utils_display import get_tcp_display, print_proto_name, print_varint
from src.serialization import serialize_protobuf_message
from src.profiling import AsyncProfiler

MAX_TRIES_IMPORT = 100
BUF_SIZE = 65536  # reading the buffer in chunks of BUF_SIZE to avoid reading all the file in once


def compile_proto(proto_path: Path, proto_name: str) -> None:
    try:
        result = subprocess.run(
            [
                "protoc",
                f"--proto_path={proto_path}",
                "--python_out=.",
                f"proto\\{proto_name}.proto",
            ],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Protoc failed: {result.stderr!r}")
    except:
        raise


def hash_proto(proto_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(proto_path, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def import_proto(
    proto_path: Path,
    proto_name: str,
    printer: Callable[[str], None],
) -> Tuple[ModuleType, str]:
    for _ in range(MAX_TRIES_IMPORT):
        try:
            printer(f"Trying loading {proto_name}_pb2...")
            proto_module = import_module(f"{proto_name}_pb2")
            # Managed to import => return
            return proto_module, hash_proto(proto_path / f"{proto_name}.proto")

        except ImportError as e:
            match = re.search(r"No module named '(\w+)_pb2'", e.msg)
            if match:
                proto_file = match.group(1)

                printer(
                    f"No compiled proto file for {proto_file}, trying to compile it..."
                )
                compile_proto(proto_path, proto_file)
                printer(f"Compilation for {proto_file} done...")

                continue

            raise ValueError(
                f"Cant parse error message to automatically compile protobuf files. Error was: {e}"
            )

        except Exception:
            raise

    raise TimeoutError(
        f"Maximum retry limit reached ({MAX_TRIES_IMPORT} attempts). Import of {proto_name} be completed."
    )


def parse_varints_from_hex(bytes_msg: bytes) -> Tuple[int, int, ByteArrayRepr]:
    """
    Parse a varint from a hexadecimal string.
    Returns a (varint_value, bytes_consumed, varint_bytes) tuple.
    """

    position = 0

    result = 0
    shift = 0
    start_pos = position

    while position < len(bytes_msg):
        byte = bytes_msg[position]
        position += 1

        # Extract the 7 lower bits and shift them
        result |= (byte & 0x7F) << shift
        shift += 7

        # If MSB is 0, this is the last byte of the varint
        if (byte & 0x80) == 0:
            break

    bytes_consumed = position - start_pos

    return (
        result,
        bytes_consumed,
        ByteArrayRepr.from_bytes(bytes_msg[start_pos:position]),
    )


@define
class TCPDecoder:
    queue_cfg: asyncio.Queue[ConfigItem]
    queue_msg: queue.Queue[Message]
    queue_com: asyncio.Queue[TCP_Message]
    printer_widget: Callable[[str, str], None]
    logger: logging.Logger

    _magic_bytes: bytes = field(init=False)
    _display: bool = field(init=False)
    _game_version: str = field(init=False)
    _proto_path: Path = field(init=False)
    _protos: List[str] = field(init=False)
    _blacklist: List[str] = field(init=False)
    _verbose: bool = field(init=False)
    display_tcp: Callable[[str, str, Packet, Optional[str]], None] = field(init=False)

    @classmethod
    def as_decoder(
        cls,
        queue_cfg: asyncio.Queue[ConfigItem],
        queue_msg: queue.Queue[Message],
        queue_com: asyncio.Queue[TCP_Message],
        config: GameProtocolConfig,
        printer_widget: Callable[[str, str], None],
        logger: logging.Logger,
    ) -> Self:
        decoder = cls(
            queue_cfg,
            queue_msg,
            queue_com,
            printer_widget,
            logger,
        )
        decoder._magic_bytes = config.magic_bytes
        decoder._display = config.display
        decoder._game_version = config.game_version
        decoder._proto_path = config.proto_path
        decoder._protos = config.protos
        decoder._blacklist = config.blacklist
        decoder._verbose = config.verbose
        decoder.display_tcp = get_tcp_display(
            lambda msg: decoder.printer_widget(msg, "log"), decoder._display
        )

        return decoder

    @classmethod
    def get_decoder(
        cls,
        queue_cfg: asyncio.Queue[ConfigItem],
        queue_msg: queue.Queue[Message],
        queue_com: asyncio.Queue[TCP_Message],
        config: GameProtocolConfig,
        printer_widget: Callable[[str, str], None],
        logger: logging.Logger,
    ) -> Callable[[], Coroutine[None, None, None]]:
        decoderContainer = cls.as_decoder(
            queue_cfg,
            queue_msg,
            queue_com,
            config,
            printer_widget,
            logger,
        )
        profiler = AsyncProfiler(logger)

        async def decoder() -> None:
            await asyncio.gather(
                decoderContainer.handle_messages(profiler),
                decoderContainer.handle_updates(),
                return_exceptions=True,
            )

        return decoder

    async def handle_messages(self, profiler: AsyncProfiler) -> None:
        while True:
            try:
                msg = await asyncio.to_thread(self.queue_msg.get, timeout=1)
                tcp_msg = await profiler.profile(
                    "decoder", self.process_tcp_message, msg
                )
                if tcp_msg is not None:
                    await self.queue_com.put(tcp_msg)

                self.queue_msg.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.exception(f"Message handler error: {e}")

    async def handle_updates(self) -> None:
        while True:
            try:
                key, value = await self.queue_cfg.get()
                setattr(self, f"_{key}", value)

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.exception(f"Update handler error: {e}")

    def process_tcp_message(
        self,
        msg: Message,
    ) -> Optional[TCP_Message]:
        payload = bytes(msg.pkt[TCP].payload)

        # decode the varint
        value_varint, bytes_consumed, varint_bytes = parse_varints_from_hex(payload)

        # detect messages that spawn on multiple packets
        # not handled yet
        if value_varint + bytes_consumed > len(payload):
            raise ValueError(
                f"Packet size is {len(payload)} but {value_varint + bytes_consumed} was expected"
            )

        # if some magic_bytes were given, use them to find the Any protobuf
        if self._magic_bytes:
            magic_number_index = -1
            if self._magic_bytes in payload:
                magic_number_index = payload.index(self._magic_bytes)
            any_msg = Any()
            any_msg.ParseFromString(payload[magic_number_index - 2 :])
        # else print the payload as ascii for exploration purpose
        # and stop here
        else:
            self.printer_widget(payload.decode("ascii", "replace"), "log")
            self.printer_widget("---", "log")
            return None

        # if verbose, print the name of each proto found unless they are blacklist
        # it's an exploration feature
        if (
            self._verbose
            and not any(b in any_msg.type_url for b in self._blacklist)
            and any_msg.type_url != ""
        ):
            print_proto_name(lambda msg: self.printer_widget(msg, "log"), any_msg)

        # if the message needs to handle, decode and display it
        if self._protos != [""] and any(
            (proto_filter := p) in any_msg.type_url for p in self._protos
        ):
            self.display_tcp(*msg.unpack(), None)
            print_varint(
                lambda msg: self.printer_widget(msg, "log"),
                value_varint,
                bytes_consumed,
                varint_bytes,
            )
            self.printer_widget("---\nDecoding...", "log")

            # import desired proto file, compile it if needed
            proto_module, proto_hash = import_proto(
                self._proto_path,
                proto_filter,
                lambda msg: self.printer_widget(msg, "log"),
            )
            proto_class = getattr(proto_module, proto_filter)
            proto_msg = proto_class()
            # parse it
            proto_msg.ParseFromString(any_msg.value)
            self.printer_widget("---", "log")
            print_proto_name(lambda msg: self.printer_widget(msg, "display"), any_msg)
            self.printer_widget(MessageToJson(proto_msg), "display")

            # create an abstraction for communication with other tasks
            tcp_msg = TCP_Message(
                client_ip=f"{msg.dst_ip}:{msg.pkt[TCP].sport}",
                server_ip=f"{msg.src_ip}:{msg.pkt[TCP].dport}",
                proto=proto_filter,
                size=value_varint + bytes_consumed,
                nb_packet=1,
                data=serialize_protobuf_message(proto_msg),
                version=self._game_version,
                hash=proto_hash,
            )
            self.printer_widget("-------", "display")

            return tcp_msg

        return None

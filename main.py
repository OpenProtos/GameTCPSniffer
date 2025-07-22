# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

import asyncio
from pathlib import Path
import queue
import threading
from typing import Any, List
import aiofiles
import aiosqlite
from scapy.all import sniff, Packet
import argparse

from src.database import get_database_worker
from src.decoder import get_decoder
from src.servers import generate_packet_handler, get_game_servers
from src.state_machine import get_packet_sequence_worker
from src.utils import Communication, GameProtocolConfig, Message, TCP_Message


async def main(ip_servs: List[str], cfg: GameProtocolConfig) -> None:

    async with aiosqlite.connect(cfg.database_path / "tcp.db") as db:
        async with aiofiles.open(cfg.schema_path, encoding="utf-8") as file:
            await db.executescript(await file.read())
        await db.commit()

    cancel_event = threading.Event()
    # queue for communication between tasks
    queue_msg_statemachine = queue.Queue[Message](maxsize=100)
    queue_com_statemachine = asyncio.Queue[Communication](maxsize=100)

    queue_msg_decoder = queue.Queue[Message](maxsize=100)
    queue_com_decoder = asyncio.Queue[TCP_Message](maxsize=100)

    # sniffer thread
    packet_handler = generate_packet_handler(queue_msg_statemachine, queue_msg_decoder)

    def custom_prn(pkt: Packet) -> None:
        return packet_handler(pkt, ip_servs, cfg.ack_packet_size)
    
    def custom_stop_filter(_: Any) -> bool:
        return cancel_event.is_set()
    
    sn_task = asyncio.to_thread(
        lambda: sniff(
            filter="tcp", 
            prn=custom_prn, 
            store=0, 
            stop_filter=custom_stop_filter
        )
    )

    # state machine task
    ps_worker = get_packet_sequence_worker(
        queue_msg_statemachine, 
        queue_com_statemachine, 
        max_client_messages_stored=5, 
        timeout=10, 
        display=cfg.display
    )
    ps_task = asyncio.create_task(ps_worker())

    print("PacketSequenceHandler worker started")

    # decoder task
    de_worker = get_decoder(queue_msg_decoder, queue_com_decoder, cfg.magic_bytes, cfg.display)
    de_task = asyncio.create_task(de_worker(cfg.proto_path, cfg.proto, cfg.blacklist, cfg.verbose))

    print("Decoder worker started")

    # database task
    db_connection = await aiosqlite.connect(cfg.database_path / "tcp.db")
    db_worker = get_database_worker(queue_com_decoder)
    db_task = asyncio.create_task(db_worker(db_connection))

    print("Database worker started")

    tasks = [
        ps_task,
        de_task,
        db_task,
    ]
    try:
        print("Start packet capture now...\n")
        await asyncio.gather(sn_task, *tasks, return_exceptions=True)
    except asyncio.CancelledError:
        print("Shutting down...")
    except Exception as e:
        print(f"Exception in gather: {e}")
    finally:
        print("Cleaning up...")
        cancel_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(sn_task, *tasks, return_exceptions=True)
        print("All tasks cleaned up.")


def create_config_from_args() -> GameProtocolConfig:
    parser = argparse.ArgumentParser(
        description="TCP Game Protocol Analyzer - Monitor client-server communication patterns"
    )
    parser.add_argument(
        '-p', '--ports', 
        nargs='+', 
        type=int,
        default=[5555, 1119, 8080],
        help="Target server ports to monitor (default: 5555, 1119, 8080)"
    )
    parser.add_argument(
        '-f', '--filter', 
        type=int,
        default=-1,
        help="ACK packet size to filter (-1 for no filtering, default: -1)"
    )
    parser.add_argument(
        '-pr', '--protos',
        nargs="+",
        help="List of proto packets to filter (`""` will discard all packets)"
    )
    parser.add_argument(
        '-bl', '--blacklist',
        nargs="*",
        default=[],
        help="List of proto packets to blacklist"
    )
    parser.add_argument(
        '-mb', '--magic-bytes', 
        type=str,
        default="",
        help="TODO"
    )
    parser.add_argument(
        '--db-path',
        default="database",
        help="Database path (default: database)"
    )
    parser.add_argument(
        '--sc-path',
        default="database/schema.sql",
        help="Sql schema file path (default: database/schema.sql)"
    )
    parser.add_argument(
        '--proto-path',
        default="proto",
        help="Protobuf folder path (default: proto)"
    )
    parser.add_argument(
        '-d', '--display', 
        action='store_true', 
        default=False,
        help="Display packet on the terminal (default: False)"
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true', 
        default=False,
        help="Display all protobuf messages found (default: False)"
    )
    args = parser.parse_args()

    # check proto files
    if not Path(args.proto_path).exists():
        raise ValueError(f"Cannot find the proto folder {args.proto_path}, did you correctly export all proto files ?")
    
    for proto in args.protos:
        if not (Path(args.proto_path) / f"{proto}.proto").exists():
            raise ValueError(f"Cannot find the proto file {args.proto}.proto in folder {args.proto_path}.")

    # compute magic_bytes
    magic_bytes_str = args.magic_bytes
    if magic_bytes_str.startswith('\\x'): # escaped hex case, with \x prefix
        magic_bytes = magic_bytes_str.encode().decode('unicode_escape').encode('latin1')
    else:  # raw hex case, no prefix
        magic_bytes = bytes.fromhex(magic_bytes_str)

    return GameProtocolConfig(
        target_ports=args.ports,
        ack_packet_size=args.filter,
        proto=args.protos,
        blacklist=args.blacklist,
        magic_bytes=magic_bytes,
        database_path=Path(args.db_path),
        schema_path=Path(args.sc_path),
        proto_path=Path(args.proto_path),
        display=args.display,
        verbose=args.verbose,
    )


if __name__ == "__main__":

    config = create_config_from_args()

    print(f"{'Monitoring ports':<35}: {config.target_ports}")
    print(f"{'ACK filter size':<35}: {config.ack_packet_size}")
    print(f"{'Capturing protos':<35}: {config.proto}")
    print(f"{'Ignoring protos':<35}: {config.blacklist}")
    print(f"{'Magic bytes used to decode protos':<35}: {config.magic_bytes!r}")
    print("Getting servers...")
    servs = get_game_servers(config.target_ports)
    if not servs:
        print(f"Script is closing, no servers on port {config.target_ports} were found.")
        exit()
    print(f"Starting packet capture for {servs} servers...")
    ip_servs = [ip for (ip, _) in servs]
    
    asyncio.run(main(ip_servs, config))

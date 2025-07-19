# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of MyDeputeFr project from https://github.com/remyCases/MyDeputeFr.

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
from src.servers import generate_packet_handler, get_game_servers
from src.state_machine import get_packet_sequence_worker
from src.utils import Communication, GameProtocolConfig, Message


async def main(ip_servs: List[str], cfg: GameProtocolConfig) -> None:

    async with aiosqlite.connect(cfg.database_path) as db:
        async with aiofiles.open(cfg.schema_path, encoding="utf-8") as file:
            await db.executescript(await file.read())
        await db.commit()

    cancel_event = threading.Event()
    # queue for communication between tasks
    queue_msg = queue.Queue[Message](maxsize=100)
    queue_com = asyncio.Queue[Communication](maxsize=100)

    # sniffer thread
    packet_handler = generate_packet_handler(queue_msg, cfg.display)

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
        queue_msg, 
        queue_com, 
        max_client_messages_stored=5, 
        timeout=10, 
        display=cfg.display
    )
    ps_task = asyncio.create_task(ps_worker())

    print("PacketSequenceHandler worker started. Start packet capture now...")

    # database task
    db_connection = await aiosqlite.connect(cfg.database_path)
    db_worker = get_database_worker(queue_com)
    db_task = asyncio.create_task(db_worker(db_connection))

    print("Database worker started. Start packet capture now...")

    tasks = [
        ps_task,
        db_task,
    ]
    try:
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
        default=6,
        help="ACK packet size to filter (-1 for no filtering, default: 6)"
    )
    parser.add_argument(
        '--db-path',
        default="database/tcp.db",
        help="Database file path (default: database/tcp.db)"
    )
    parser.add_argument(
        '--sc-path',
        default="database/schema.sql",
        help="Sql schema file path (default: database/schema.sql)"
    )
    parser.add_argument(
        '-d', '--display', 
        action='store_true', 
        default=False,
        help="Display packet on the terminal (default: False)"
    )
    args = parser.parse_args()

    return GameProtocolConfig(
        target_ports=args.ports,
        ack_packet_size=args.filter,
        database_path=Path(args.db_path),
        schema_path=Path(args.sc_path),
        display=args.display
    )


if __name__ == "__main__":

    config = create_config_from_args()

    print(f"Monitoring ports: {config.target_ports}")
    print(f"ACK filter size: {config.ack_packet_size}")
    print("Getting servers...")
    servs = get_game_servers(config.target_ports)
    if not servs:
        print(f"Script is closing, no servers on port {config.target_ports} were found.")
        exit()
    print(f"Starting packet capture for {servs} servers...")
    ip_servs = [ip for (ip, _) in servs]
    
    asyncio.run(main(ip_servs, config))

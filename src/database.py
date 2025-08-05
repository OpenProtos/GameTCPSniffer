# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

import asyncio
from typing import Coroutine, Callable, TypeVar, Union, overload
import aiosqlite

from src.utils import Communication, TCP_Message

T = TypeVar('T', Communication, TCP_Message)

@overload
def get_database_worker(
    queue: asyncio.Queue[Communication],
) -> Callable[[aiosqlite.Connection], Coroutine[None, None, None]]:
    ...


@overload
def get_database_worker(
    queue: asyncio.Queue[TCP_Message],
) -> Callable[[aiosqlite.Connection], Coroutine[None, None, None]]:
    ...


def get_database_worker(
    queue: Union[asyncio.Queue[Communication], asyncio.Queue[TCP_Message]]
) -> Callable[[aiosqlite.Connection], Coroutine[None, None, None]]:
    
    async def database_worker(db_connection: aiosqlite.Connection) -> None:
        while True:
            item = await queue.get()
            
            try:
                if isinstance(item, Communication):
                    await db_connection.execute(
                        "INSERT INTO tcp_client_server_messages(client_ip, server_ip, request_data, acknowledgment, response_data) VALUES (?, ?, ?, ?, ?)",
                        (item.unpack())
                    )
                elif isinstance(item, TCP_Message):
                    await db_connection.execute(
                        "INSERT INTO tcp_proto_messages(client_ip, server_ip, proto, size, nb_packet, data, version, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (item.unpack())
                    )
                else:
                    raise ValueError(f"Unexpected item type: {type(item)}")
                
                await db_connection.commit()
                print(f"Stored: {item.client_ip} -> {item.server_ip}")
                
            except Exception as e:
                print(f"Database error: {e}")
            
            queue.task_done()
    
    return database_worker
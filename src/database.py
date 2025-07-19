# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of MyDeputeFr project from https://github.com/remyCases/MyDeputeFr.

import asyncio
from typing import Coroutine, Callable
import aiosqlite

from src.utils import Communication

def get_database_worker(queue: asyncio.Queue[Communication]) -> Callable[[aiosqlite.Connection], Coroutine[None, None, None]]:
    async def database_worker(db_connection: aiosqlite.Connection) -> None:
        """Simple worker that processes database insertions"""
        nonlocal queue
        while True:
            # Wait for communication data
            comm = await queue.get()
            
            try:
                await db_connection.execute(
                    "INSERT INTO tcp(client_ip, server_ip, request_data, acknowledgment, response_data) VALUES (?, ?, ?, ?, ?)",
                    (
                        comm.client_ip,
                        comm.server_ip,
                        comm.request,
                        comm.ack,
                        comm.response
                    ),
                )
                await db_connection.commit()
                print(f"Stored: {comm.client_ip} -> {comm.server_ip}")
                
            except Exception as e:
                print(f"Database error: {e}")
            
            # Mark task done
            queue.task_done()
    
    return database_worker
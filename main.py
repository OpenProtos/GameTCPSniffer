# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

import logging.config
import sys
import asyncio
from typing import List, Sequence
from pathlib import Path

import yaml

from src.tui import TCPSnifferApp
from src.parser import tcp_parser


async def main(args: Sequence[str]) -> None:
    history: List[str] = []
    while True:  # to handle restart
        app = TCPSnifferApp(args, history)

        try:
            # async initialization
            if not await app.initialize():
                app.logger.info("Failed to initialize app")

            app.logger.info("Start packet capture now...\n")
            await app.run_async()

        except asyncio.CancelledError:
            app.logger.info("Shutting down...")
        except Exception as e:
            app.logger.error(f"{e}")
        finally:
            await app.on_exit()
            if not app._restart_requested:
                break
            args = app._new_args
            history = app.history


if __name__ == "__main__":
    with open(Path("logging_configs/config.yaml"), "r") as f:
        config = yaml.safe_load(f)

    logging.config.dictConfig(config)
    # for handling help command
    _ = tcp_parser().parse_args(sys.argv[1:])

    asyncio.run(main(sys.argv[1:]))

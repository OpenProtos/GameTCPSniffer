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


async def main(args: Sequence[str]) -> None:
    
    history: List[str] = []
    while True: # to handle restart
        app = TCPSnifferApp(history)
        app_task = asyncio.create_task(app.run_async())
        await asyncio.sleep(0.1)  # create widgets

        # async initialization
        if not await app.initialize(args):
            app.logger.info("Failed to initialize app")
            app_task.cancel()
            return

        try:
            app.logger.info("Start packet capture now...\n")
            await app_task

        except asyncio.CancelledError:
            app.logger.info("Shutting down...")
        except Exception as e:
            app.logger.info(f"Exception in gather: {e}")
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

    asyncio.run(main(sys.argv[1:]))
    # since the app does not return a restored terminal, and I tried, and I tried and I tried to fix it
    # I call it a feature and grant the user with some magic
    print("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Whoosh!")


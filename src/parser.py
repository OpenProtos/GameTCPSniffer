from pathlib import Path
from typing import Callable, Coroutine, List, Sequence 

from argparse import REMAINDER, ArgumentParser, Namespace 

from src.utils import GameProtocolConfig


def tcp_parser() -> ArgumentParser:
    parser = ArgumentParser(
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
        nargs="*",
        default=[],
        help="List of proto packets to filter"
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
        help="Magic bytes used to find the Any message in each packets (default: ``)"
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
        '-gv', '--game-version',
        type=str,
        default="UNKNOWN",
        help="Version of the game you're sniffing (default: `UNKNOWN`)"
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
    return parser


def create_start_config_from_args(arguments: Sequence[str]) -> GameProtocolConfig:
    parser = tcp_parser()
    args = parser.parse_args(arguments)

    # check proto files
    if not Path(args.proto_path).exists():
        raise ValueError(f"Cannot find the proto folder {args.proto_path}, did you correctly export all proto files ?")
    
    for proto in args.protos:
        if not (Path(args.proto_path) / f"{proto}.proto").exists():
            raise ValueError(f"Cannot find the proto file {proto}.proto in folder {args.proto_path}.")

    # compute magic_bytes
    magic_bytes_str = args.magic_bytes
    if magic_bytes_str.startswith('\\x'): # escaped hex case, with \x prefix
        magic_bytes = magic_bytes_str.encode().decode('unicode_escape').encode('latin1')
    else:  
        try:
            # raw hex case, no prefix
            magic_bytes = bytes.fromhex(magic_bytes_str)
        except ValueError:
            # is that string ?
            magic_bytes = magic_bytes_str.encode()

    return GameProtocolConfig(
        ports=args.ports,
        protos=args.protos,
        blacklist=args.blacklist,
        magic_bytes=magic_bytes,
        db_path=Path(args.db_path),
        sc_path=Path(args.sc_path),
        proto_path=Path(args.proto_path),
        game_version=args.game_version,
        display=args.display,
        verbose=args.verbose,
    )


def create_runtime_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="",
        add_help=False,
        exit_on_error=False,
    )

    subparsers = parser.add_subparsers(dest="command")

    add_proto_parser = subparsers.add_parser("add_proto")
    remove_proto_parser = subparsers.add_parser("remove_proto")
    add_blacklist_parser = subparsers.add_parser("add_blacklist")
    remove_blacklist_parser = subparsers.add_parser("remove_blacklist")
    restart_parser = subparsers.add_parser("restart")

    subparsers.add_parser("verbose")
    subparsers.add_parser("show")
    subparsers.add_parser("help")
    subparsers.add_parser("clear")

    add_proto_parser.add_argument(
        'names', 
        nargs="*",
        default=[],
        help="Adds proto packets to filter"
    )

    remove_proto_parser.add_argument(
        'names', 
        nargs="*",
        default=[],
        help="Removes proto packets to filter"

    )

    add_blacklist_parser.add_argument(
        'names', 
        nargs="*",
        default=[],
        help="Adds proto packets to blacklist"

    )

    remove_blacklist_parser.add_argument(
        'names', 
        nargs="*",
        default=[],
        help="Removes proto packets to blacklist"
    )

    restart_parser.add_argument(
        '--previous',
        action="store_true",
    )
    restart_parser.add_argument(
        '--current',
        action="store_true",
    )

    return parser


class CommandProcessor:
    def __init__(
        self,
        printer: Callable[[str], None],
        clear_handler: Callable[[], None],
        restart_handler: Callable[[Sequence[str]], Coroutine[None, None, None]],
        previous_args: Sequence[str],
        usage: str,
    ):
        self.printer = printer
        self.clear_handler = clear_handler
        self.restart_handler = restart_handler
        self.previous_args = previous_args
        self.usage = usage


    async def process(
        self,
        config: GameProtocolConfig,
        command: Namespace,
        remainder_args: Sequence[str]
    ) -> None:

        if command.command == "add_proto":
            await config.add_proto(command.names)
            self.printer(f"{'Capturing protos':<35}: {config.protos}")

        elif command.command  == "remove_proto":
            await config.remove_proto(command.names)
            self.printer(f"{'Capturing protos':<35}: {config.protos}")

        elif command.command  == "add_blacklist":
            await config.add_blacklist(command.names)
            self.printer(f"{'Ignoring protos':<35}: {config.blacklist}")

        elif command.command  == "remove_blacklist":
            await config.remove_blacklist(command.names)
            self.printer(f"{'Ignoring protos':<35}: {config.blacklist}")

        elif command.command  == "verbose":
            await config.toggle_verbose()
            self.printer(f"{'Verbose':<35}: {config.verbose}")

        elif command.command  == "show":
            self.printer(f"{'Capturing protos':<35}: {config.protos}\n{'Ignoring protos':<35}: {config.blacklist}")

        elif command.command  == "help":
            self.printer(self.usage)

        elif command.command  == "restart":
            parser = tcp_parser()
            if command.previous:
                new_args = self.previous_args
            elif command.current:
                new_args = config.to_args()
            else:
                try:
                    parser.parse_args(remainder_args)
                except SystemExit as e:
                    self.printer(f"Invalid arguments {remainder_args} for restart")
                    if e.code != 0:
                        raise ValueError("Invalid arguments for restart") from e
                new_args = remainder_args

            await self.restart_handler(new_args)

        elif command.command == "clear":
            self.clear_handler()


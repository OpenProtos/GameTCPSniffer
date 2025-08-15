# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

import asyncio
import hashlib
from importlib import import_module
from pathlib import Path
import queue
import re
import subprocess
from types import ModuleType
from typing import Callable, Coroutine, List, Tuple

from scapy.layers.inet import TCP
from google.protobuf.any_pb2 import Any
from google.protobuf.json_format import MessageToJson

from src.utils import ByteArrayRepr, Message, TCP_Message
from src.utils_display import get_tcp_display, print_proto_name, print_varint 
from src.serialization import serialize_protobuf_message

MAX_TRIES_IMPORT = 100
BUF_SIZE = 65536 # reading the buffer in chunks of BUF_SIZE to avoid reading all the file in once


def compile_proto(proto_path: Path, proto_name: str) -> None:
    try:
        result = subprocess.run([
            'protoc', 
            f'--proto_path={proto_path}', 
            '--python_out=.',
            f'proto\\{proto_name}.proto'
        ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            raise RuntimeError(f"Protoc failed: {result.stderr!r}")
    except:
        raise


def hash_proto(proto_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(proto_path, 'rb') as f:
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

                printer(f"No compiled proto file for {proto_file}, trying to compile it...")
                compile_proto(proto_path, proto_file)
                printer(f"Compilation for {proto_file} done...")

                continue

            raise ValueError(f"Cant parse error message to automatically compile protobuf files. Error was: {e}")

        except Exception:
            raise

    raise TimeoutError(f"Maximum retry limit reached ({MAX_TRIES_IMPORT} attempts). Import of {proto_name} be completed.")


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

    return result, bytes_consumed, ByteArrayRepr.from_bytes(bytes_msg[start_pos:position])


def get_decoder(
    queue_msg: queue.Queue[Message],
    queue_com: asyncio.Queue[TCP_Message],
    magic_bytes: bytes,
    display: bool,
    game_version: str,
    printer_log: Callable[[str], None],
    printer_display: Callable[[str], None],
) -> Callable[[Path, List[str], List[str], bool], Coroutine[None, None, None]]:

    display_tcp = get_tcp_display(printer_log, display)

    async def decoder(proto_path: Path, protos_filter: List[str], blacklist: List[str], verbose: bool) -> None:
        while True:
            try:
                # Convert blocking get to async
                # Wait for communication data
                msg = await asyncio.to_thread(queue_msg.get, timeout=1)
                payload = bytes(msg.pkt[TCP].payload)
                value_varint, bytes_consumed, varint_bytes = parse_varints_from_hex(payload)

                if value_varint + bytes_consumed > len(payload):
                    raise ValueError(f"Packet size is {len(payload)} but {value_varint + bytes_consumed} was expected")

                magic_number_index = -1
                if magic_bytes in payload:
                    magic_number_index = payload.index(magic_bytes)

                any_msg = Any()
                any_msg.ParseFromString(payload[magic_number_index-2:])

                if verbose and not any(b in any_msg.type_url for b in blacklist) and any_msg.type_url != "":
                    print_proto_name(printer_log, any_msg)

                if protos_filter != [""] and any((proto_filter:=p) in any_msg.type_url for p in protos_filter):

                    display_tcp(*msg.unpack(), None)
                    print_varint(printer_log, value_varint, bytes_consumed, varint_bytes)
                    printer_log("---")
                    printer_log("Decoding...")
                    proto_module, proto_hash = import_proto(proto_path, proto_filter, printer_log)
                    proto_class = getattr(proto_module, proto_filter)
                    proto_msg = proto_class()
                    proto_msg.ParseFromString(any_msg.value)
                    printer_log("---")
                    print_proto_name(printer_display, any_msg)
                    printer_display(MessageToJson(proto_msg))

                    tcp_msg = TCP_Message(
                        client_ip=f"{msg.dst_ip}:{msg.pkt[TCP].sport}",
                        server_ip=f"{msg.src_ip}:{msg.pkt[TCP].dport}",
                        proto=proto_filter,
                        size=value_varint + bytes_consumed,
                        nb_packet=1,
                        data=serialize_protobuf_message(proto_msg),
                        version=game_version,
                        hash=proto_hash,
                    )
                    printer_display("-------")

                    await queue_com.put(tcp_msg)

                queue_msg.task_done()

            except queue.Empty:
                continue  # Timeout, try again
            except Exception as e:
                printer_log(f"Decoder error: {e}")

    return decoder


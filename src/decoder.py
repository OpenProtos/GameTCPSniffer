# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

import asyncio
from importlib import import_module
from pathlib import Path
import queue
import re
import subprocess
from types import ModuleType
from typing import Callable, Coroutine

from scapy.layers.inet import TCP
from google.protobuf.any_pb2 import Any

from src.utils import CLIENT_COLOR, COLOR_END, DEFAULT_COLOR, ByteArrayRepr, Message, get_tcp_display

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


def import_proto(proto_path: Path, proto_name: str) -> ModuleType:

    while True:
        try:
            print(f"Trying loading {proto_name}_pb2...")
            proto_module = import_module(f"{proto_name}_pb2")
            # Managed to import => return
            return proto_module

        except ImportError as e:
            match = re.search(r"No module named '(\w{3})_pb2'", e.msg)
            if match:
                proto_file = match.group(1)

                print(f"No compiled proto file for {proto_file}, trying to compile it...")
                compile_proto(proto_path, proto_file)
                print(f"Compilation for {proto_file} done...")

                continue

            raise ValueError(f"Cant parse error message to automatically compile protobuf files. Error was: {e}")
        
        except Exception:
            raise


def parse_varints_from_hex(bytes_msg: bytes):
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

def get_decoder(queue_msg: queue.Queue[Message], magic_bytes: bytes, display: bool) -> Callable[[Path, str, bool], Coroutine[None, None, None]]:

    display_tcp = get_tcp_display(display)

    async def decoder(proto_path: Path, proto_filter: str, verbose: bool):
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

                if verbose:
                    print(f"{CLIENT_COLOR}Proto\t\t: {any_msg.type_url}{COLOR_END}")

                if proto_filter != "" and proto_filter in any_msg.type_url:
                    
                    display_tcp(*msg.unpack(), DEFAULT_COLOR)
                    print(f"{CLIENT_COLOR}Varint\t\t: {varint_bytes.to_hex()}{COLOR_END}")
                    print(f"{CLIENT_COLOR}Value\t\t: {value_varint}{COLOR_END}")
                    print(f"{CLIENT_COLOR}VarLen\t\t: {bytes_consumed}{COLOR_END}")
                    
                    print("---")
                    print("Decoding...")
                    proto_module = import_proto(proto_path, proto_filter)
                    proto_class = getattr(proto_module, proto_filter)
                    msg = proto_class()
                    msg.ParseFromString(any_msg.value)
                    print("---")
                    print(msg)
                    print("-------")
                
                queue_msg.task_done()

            except queue.Empty:
                continue  # Timeout, try again
            except Exception as e:
                print(f"Decoder error: {e}")

    return decoder

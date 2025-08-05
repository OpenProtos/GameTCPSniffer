# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

from __future__ import annotations

import binascii
from datetime import timedelta
from enum import Enum
from pathlib import Path
import time
from typing import Callable, List, Tuple, TypeAlias

from attr import define
from scapy.all import Packet
from scapy.layers.inet import TCP

COLOR_END = '\033[0m'
CLIENT_COLOR = '\033[94m'
SERV_COLOR = '\033[92m'
ACK_COLOR = '\033[31m'
DEFAULT_COLOR = '\033[37m'

start = time.time()

class CommunicationFlag(Enum):
    ACK = "ack"
    OTHER = "other"

@define
class ByteArrayRepr:
    values: bytes

    @classmethod
    def from_bytes(cls, arr: bytes) -> ByteArrayRepr:
        return cls(arr)
    
    def to_hex(self) -> str:
        return f"0x{self.values.hex()}"

@define
class Message:
    src_ip: str
    dst_ip: str
    pkt: Packet
    flag: CommunicationFlag

    def unpack(self) -> Tuple[str, str, Packet]:
        return self.src_ip, self.dst_ip, self.pkt
    

    @classmethod
    def empty(cls) -> Message:
        return Message(
            src_ip="",
            dst_ip="",
            pkt=Packet(),
            flag=CommunicationFlag.OTHER,
        )


JSON: TypeAlias = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None
@define
class TCP_Message:
    client_ip: str
    server_ip: str
    proto: str
    size: int
    nb_packet: int
    data: JSON
    version: str
    hash: str

    def unpack(self) -> Tuple[str, str, str, int, int, JSON, str, str]:
        return self.client_ip, self.server_ip, self.proto, self.size, self.nb_packet, self.data, self.version, self.hash


@define
class Communication:
    client_ip: str
    server_ip: str
    request: str
    ack: str
    response: str

    def unpack(self) -> Tuple[str, str, str, str, str]:
        return self.client_ip, self.server_ip, self.request, self.ack, self.response

@define
class GameProtocolConfig:
    target_ports: List[int]
    ack_packet_size: int
    proto: List[str]
    blacklist: List[str]
    magic_bytes: bytes
    database_path: Path
    schema_path: Path
    proto_path: Path
    game_version: str
    display: bool
    verbose: bool

def decode_tcp_paylod(pkt: Packet) -> str:
    return binascii.hexlify(bytes(pkt[TCP].payload)).decode()

def get_tcp_display(display: bool) -> Callable[[str, str, Packet, str], None]:
    def not_print_tcp_request(_src_ip: str, _dst_ip: str, _pkt: Packet, _color: str) -> None:
        pass

    def print_tcp_request(src_ip: str, dst_ip: str, pkt: Packet, color: str) -> None:
        """Print a tcp request with color coding."""
        payload = bytes(pkt[TCP].payload)
        elapsed = (time.time() - start)
        print(f"{color}From\t\t: {src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport}{COLOR_END}")
        print(f"{color}TS\t\t: {str(timedelta(seconds=elapsed))}{COLOR_END}")
        print(f"{color}Size\t\t: {len(payload)} bytes{COLOR_END}")
        print(f"{color}Hex\t\t: {binascii.hexlify(payload)[:100]!r}...{COLOR_END}")  # First 50 bytes
        print("---")

    if display:
        return print_tcp_request
    else:
        return not_print_tcp_request

def is_client(ip: str) -> bool:
    """Return True if localhost."""
    return ip.startswith("127.") or ip.startswith("192.168.")

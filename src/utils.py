# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of GameTCPSniffer project from https://github.com/remyCases/GameTCPSniffer.

from __future__ import annotations

import asyncio
import binascii
from enum import Enum
from pathlib import Path
from typing import List, Tuple

from attr import define, field
from attrs import fields
from scapy.all import Packet
from scapy.layers.inet import TCP


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


@define
class TCP_Message:
    client_ip: str
    server_ip: str
    proto: str
    size: int
    nb_packet: int
    data: bytes
    version: str
    hash: str

    def unpack(self) -> Tuple[str, str, str, int, int, bytes, str, str]:
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
    ports: List[int]
    protos: List[str]
    blacklist: List[str]
    magic_bytes: bytes
    db_path: Path
    sc_path: Path
    proto_path: Path
    game_version: str
    display: bool
    verbose: bool
    _lock: asyncio.Lock = field(factory=asyncio.Lock, init=False)


    async def add_proto(self, names: List[str]) -> None:
        async with self._lock:
            for p in names:
                if p not in self.protos and (Path(self.proto_path) / f"{p}.proto").exists():
                    self.protos.append(p)


    async def remove_proto(self, names: List[str]) -> None:
        async with self._lock:
            for p in names:
                if p in self.protos:
                    self.protos.remove(p)


    async def add_blacklist(self, names: List[str]) -> None:
        async with self._lock:
            for p in names:
                if p not in self.blacklist:
                    self.blacklist.append(p)


    async def remove_blacklist(self, names: List[str]) -> None:
        async with self._lock:
            for p in names:
                if p in self.blacklist:
                    self.blacklist.remove(p)


    async def toggle_verbose(self) -> None:
        async with self._lock:
            self.verbose = not self.verbose


    def to_args(self) -> List[str]:
        args: List[str] = []
 
        for f in fields(self.__class__):
            value = getattr(self, f.name)
            name = f.name.replace("_", "-")

            if isinstance(value, bool) and value:
                args.append(f"--{name}")

            elif isinstance(value, list) and value:
                args.append(f"--{name}")
                args.extend(map(str, value))

            elif isinstance(value, bytes) and value:
                args.append(f"--{name}")
                args.append(value.decode('latin1'))

            elif isinstance(value, (Path, str)) and value:
                args.append(f"--{name}")
                args.append(str(value))

        return args


def decode_tcp_paylod(pkt: Packet) -> str:
    return binascii.hexlify(bytes(pkt[TCP].payload)).decode()


def is_client(ip: str) -> bool:
    """Return True if localhost."""
    return ip.startswith("127.") or ip.startswith("192.168.")


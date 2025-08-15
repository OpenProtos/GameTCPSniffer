import binascii
from typing import Callable, Optional
from datetime import timedelta
import time

from scapy.layers.inet import TCP
from scapy.all import Packet
import google.protobuf.any_pb2

from src.utils import ByteArrayRepr


COLOR_END = '\033[0m'
CLIENT_COLOR = '\033[94m'
SERV_COLOR = '\033[92m'
ACK_COLOR = '\033[31m'
DEFAULT_COLOR = '\033[37m'


start = time.time()


def get_tcp_display(printer: Callable[[str], None], display: bool) -> Callable[[str, str, Packet, Optional[str]], None]:
    def not_print_tcp_request(_src_ip: str, _dst_ip: str, _pkt: Packet, _color: Optional[str]) -> None:
        pass

    def print_tcp_request(src_ip: str, dst_ip: str, pkt: Packet, color: Optional[str]) -> None:
        """Print a tcp request with color coding."""

        if color is None:
            color = DEFAULT_COLOR
        payload = bytes(pkt[TCP].payload)
        elapsed = (time.time() - start)
        printer(f"{color}From\t\t: {src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport}{COLOR_END}")
        printer(f"{color}TS\t\t: {str(timedelta(seconds=elapsed))}{COLOR_END}")
        printer(f"{color}Size\t\t: {len(payload)} bytes{COLOR_END}")
        printer(f"{color}Hex\t\t: {binascii.hexlify(payload)[:100]!r}...{COLOR_END}")  # First 50 bytes
        printer("---")

    if display:
        return print_tcp_request
    else:
        return not_print_tcp_request


def print_proto_name(printer: Callable[[str], None], any_msg: google.protobuf.any_pb2.Any) -> None:
    printer(f"{CLIENT_COLOR}Proto\t\t: {any_msg.type_url}{COLOR_END}")


def print_varint(printer: Callable[[str], None], value_varint: int, bytes_consumed: int, varint_bytes: ByteArrayRepr, color: str = DEFAULT_COLOR) -> None:

    printer(f"{color}Varint\t\t: {varint_bytes.to_hex()}{COLOR_END}")
    printer(f"{color}Value\t\t: {value_varint}{COLOR_END}")
    printer(f"{color}VarLen\t\t: {bytes_consumed}{COLOR_END}")


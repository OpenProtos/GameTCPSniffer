# Copyright (C) 2025 Rémy Cases
# See LICENSE file for extended copyright information.
# This file is part of MyDeputeFr project from https://github.com/remyCases/MyDeputeFr.

from __future__ import annotations

import asyncio
import collections
import queue
import time
from enum import Enum
from typing import Callable, Coroutine, Optional

from attrs import define
from scapy.all import Packet

from src.utils import ACK_COLOR, CLIENT_COLOR, SERV_COLOR, Communication, CommunicationFlag, Message, decode_tcp_paylod, get_tcp_display, is_client


class State(Enum):
    IDLE = "idle"
    WAITING_RESPONSE = "waiting_response"


@define
class RARSequence:
    request: Message
    ack: Message
    response: Message

    @classmethod
    def empty(cls) -> RARSequence:
        return RARSequence(
            request=Message.empty(),
            ack=Message.empty(),
            response=Message.empty(),
        )

    def add_request(self: RARSequence, request: Message) -> RARSequence:
        return RARSequence(
            request=request,
            ack=self.ack,
            response=self.response,
        )

    def add_ack(self: RARSequence, ack: Message) -> RARSequence:
        return RARSequence(
            request=self.request,
            ack=ack,
            response=self.response,
        )

    def add_response(self: RARSequence, response: Message) -> RARSequence:
        return RARSequence(
            request=self.request,
            ack=self.ack,
            response=response,
        )

    def to_communication(self) -> Communication:
        return Communication(
            client_ip=self.request.src_ip,
            server_ip=self.request.dst_ip,
            request=decode_tcp_paylod(self.request.pkt),
            ack=decode_tcp_paylod(self.ack.pkt),
            response=decode_tcp_paylod(self.response.pkt),
        )


@define
class PacketSequenceState:
    state: State
    output_queue: asyncio.Queue[Communication]
    client_messages: collections.deque[Message]
    pending_sequence: RARSequence
    last_message_time: float
    timeout_handler: float

class PacketSequenceHandler:
    
    @classmethod
    async def process_message(
        cls, 
        cs: PacketSequenceState, 
        msg: Message, 
        display_request: Callable[[str, str, Packet, str], None]
    ) -> PacketSequenceState:
        """
        Analyze TCP packets for request-response patterns commonly found in game protocols.
        
        Monitors for the pattern:
        1. Client request (variable size)
        2. Server acknowledgment (fixed size, configurable)
        3. Server response (large data packet)
        
        Args:
            TODO
        """

        if cls.should_timeout(cs, time.time()):
            return cls.reset_state(cs)
        
        pending_sequence = cs.pending_sequence
        client_messages = cs.client_messages

        if cs.state == State.IDLE and is_client(msg.src_ip):
            # A client request is sent, store it, it may be a request needed for a RAR trio
            client_messages.append(msg)
            return cls.new_state(cs, State.IDLE, client_messages=client_messages)
            
        elif cs.state == State.IDLE and msg.flag == CommunicationFlag.ACK:
            # find an ACK, check if there is an existing client message
            for client_msg in reversed(client_messages):
                if client_msg.dst_ip == msg.src_ip:
                    # find the most recent corresponding client request to the ACK
                    return cls.new_state(
                        cs, 
                        State.WAITING_RESPONSE, 
                        pending_sequence=pending_sequence.add_request(client_msg).add_ack(msg)
                    )
            
            # Cant find a correct request, reset
            return cls.reset_state(cs)

        elif cs.state == State.WAITING_RESPONSE and not is_client(msg.src_ip):
            # Complete communication - send to output

            if pending_sequence.request.dst_ip ==  msg.src_ip:
                pending_sequence = pending_sequence.add_response(msg)
                display_request(*pending_sequence.request.unpack(), CLIENT_COLOR)
                display_request(*pending_sequence.ack.unpack(), ACK_COLOR)
                display_request(*pending_sequence.response.unpack(), SERV_COLOR)

                await cs.output_queue.put(pending_sequence.to_communication())

            # the response is not correct AND should, reset
            return cls.reset_state(cs)

        else:
            # Invalid transition
            return cls.reset_state(cs)


    @classmethod
    def new_state(
        cls, 
        cs: PacketSequenceState, 
        new_state: State, 
        client_messages: Optional[collections.deque[Message]] = None,
        pending_sequence: Optional[RARSequence] = None,
    ) -> PacketSequenceState:

        return PacketSequenceState(
            new_state,
            cs.output_queue,
            client_messages if client_messages is not None else cs.client_messages,
            pending_sequence if pending_sequence is not None else cs.pending_sequence,
            time.time(),
            cs.timeout_handler,
        )


    @classmethod
    def reset_state(cls, cs: PacketSequenceState) -> PacketSequenceState:

        cs.client_messages.clear()
        return PacketSequenceState(
            State.IDLE,
            cs.output_queue,
            cs.client_messages,
            RARSequence.empty(),
            time.time(),
            cs.timeout_handler,
        )


    @classmethod
    def should_timeout(cls, cs: PacketSequenceState, current_time: float) -> bool:
        return current_time - cs.last_message_time > cs.timeout_handler

def get_packet_sequence_worker(
        queue_msg: queue.Queue[Message], 
        queue_com: asyncio.Queue[Communication], 
        max_client_messages_stored: int, 
        timeout: float,
        display: bool
) -> Callable[[], Coroutine[None, None, None]]:

    cs = PacketSequenceState(
        state=State.IDLE,
        output_queue=queue_com,
        client_messages=collections.deque[Message](maxlen=max_client_messages_stored),
        pending_sequence=RARSequence.empty(),
        last_message_time=time.time(),
        timeout_handler=timeout
    )

    display_request = get_tcp_display(display)

    async def packet_sequence_worker() -> None:
        nonlocal queue_msg
        nonlocal cs

        while True:
            try:
                # Convert blocking get to async
                # Wait for communication data
                msg = await asyncio.to_thread(queue_msg.get, timeout=1)

                cs = await PacketSequenceHandler.process_message(cs, msg, display_request)

                queue_msg.task_done()

            except queue.Empty:
                continue  # Timeout, try again
            except Exception as e:
                print(f"PacketSequenceHandler error: {e}")
    
    
    return packet_sequence_worker

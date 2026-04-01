from __future__ import annotations

import os
from random import randint

from . import IntermediateTransport
from ..packets import BasePacket, QuickAckPacket, MessagePacket, ErrorPacket
from ...enums import TransportEvent, TransportType


class PaddedIntermediateTransport(IntermediateTransport):
    SUPPORTS_OBFUSCATION = True
    TYPE = TransportType.PADDED_INTERMEDIATE

    __slots__ = ()

    def _read(self) -> BasePacket | TransportEvent | None:
        if len(self.rx_buffer) < 4:
            return None

        is_quick_ack = (self.rx_buffer.peekexactly(1)[0] & 0x80) == 0x80
        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        if length > self.max_packet_size:
            return TransportEvent.DISCONNECT
        if len(self.rx_buffer) < (length + 4):
            return None

        self.rx_buffer.readexactly(4)
        data = self.rx_buffer.readexactly(length)
        if length > 16:
            return MessagePacket.parse(
                data[:(length - length % 4)],
                is_quick_ack,
            )

        if data[:4] == b"\xff\xff\xff\xff":  # TODO: is check for self.role == ConnectionRole.CLIENT needed?
            return QuickAckPacket(data[4:8])

        return ErrorPacket(int.from_bytes(data[:4], "little", signed=True))

    def write(self, packet: BasePacket) -> None:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            data = b"\xff\xff\xff\xff" + data

        data += os.urandom(randint(0, 3))
        self.tx_buffer.write(len(data).to_bytes(4, byteorder="little"))
        self.tx_buffer.write(data)

    def _has_packet(self) -> bool:
        if len(self.rx_buffer) < 4:
            return False

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        return len(self.rx_buffer) >= (length + 4) or length > self.max_packet_size

    def ready_read(self) -> bool:
        return True

    def ready_write(self) -> bool:
        return True

from __future__ import annotations

import os

from . import IntermediateTransport
from .. import Buffer
from ..packets import BasePacket, QuickAckPacket, MessagePacket, ErrorPacket


class PaddedIntermediateTransport(IntermediateTransport):
    def read(self, buf: Buffer) -> BasePacket | None:
        if buf.size() < 4:
            return

        is_quick_ack = (buf.peekexactly(1)[0] & 0x80) == 0x80
        length = int.from_bytes(buf.peekexactly(4), "little") & 0x7FFFFFFF
        if buf.size() < length:
            return

        buf.readexactly(4)
        data = buf.readexactly(length)
        if len(data) > 16:
            return MessagePacket.parse(data, is_quick_ack)

        if data[:4] == b"\xff\xff\xff\xff":  # TODO: is check for self.role == ConnectionRole.CLIENT needed?
            return QuickAckPacket(data[4:8])

        return ErrorPacket(int.from_bytes(data[:4], "little", signed=True))

    def write(self, packet: BasePacket) -> bytes:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            data = b"\xff\xff\xff\xff" + data

        buf = Buffer()
        data += os.urandom(-len(data) % 16)
        buf.write(len(data).to_bytes(4, byteorder="little"))
        buf.write(data)

        return buf.data()

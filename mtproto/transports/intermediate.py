from __future__ import annotations
from .base_transport import BaseTransport
from .. import Buffer, ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class IntermediateTransport(BaseTransport):
    def read(self, buf: Buffer) -> BasePacket | None:
        if buf.size() < 4:
            return

        is_quick_ack = (buf.peekexactly(1)[0] & 0x80) == 0x80
        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            return QuickAckPacket(buf.readexactly(4))

        length = int.from_bytes(buf.peekexactly(4), "little") & 0x7FFFFFFF
        if buf.size() < length:
            return

        buf.readexactly(4)
        data = buf.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> bytes:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            return data

        buf = Buffer()
        buf.write(len(data).to_bytes(4, byteorder="little"))
        buf.write(data)

        return buf.data()

    def has_packet(self, buf: Buffer) -> bool:
        if buf.size() < 4:
            return False
        if buf.peekexactly(1)[0] & 0x80 == 0x80:
            return True

        length = int.from_bytes(buf.peekexactly(4), "little") & 0x7FFFFFFF
        return buf.size() >= (length + 4)

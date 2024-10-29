from __future__ import annotations
from .base_transport import BaseTransport
from .. import Buffer, ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class AbridgedTransport(BaseTransport):
    def read(self, buf: Buffer) -> BasePacket | None:
        if buf.size() < 4:
            return

        length = buf.peekexactly(1)[0]
        is_quick_ack = length & 0x80 == 0x80
        length &= 0x7F

        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            return QuickAckPacket(buf.readexactly(4)[::-1])

        big_length = length & 0x7F == 0x7F
        if big_length:
            length = int.from_bytes(buf.peekexactly(3, 1), "little")

        length *= 4
        if buf.size() < length:
            return

        buf.readexactly(4 if big_length else 1)
        data = buf.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> bytes:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            return data[::-1]

        buf = Buffer()
        length = (len(data) + 3) // 4

        if length >= 0x7F:
            buf.write(b"\x7f")
            buf.write(length.to_bytes(3, byteorder="little"))
        else:
            buf.write(length.to_bytes(1, byteorder="little"))

        buf.write(data)
        return buf.data()

    def has_packet(self, buf: Buffer) -> bool:
        if buf.size() < 4:
            return False
        length = buf.peekexactly(1)[0]
        if length & 0x80 == 0x80:
            return True
        length &= 0x7F

        length_size = 1
        if length & 0x7F == 0x7F:
            length_size = 4
            length = int.from_bytes(buf.peekexactly(3, 1), "little")

        length *= 4
        return buf.size() >= (length + length_size)

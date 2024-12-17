from __future__ import annotations

from .base_transport import BaseTransport
from .. import ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class AbridgedTransport(BaseTransport):
    def read(self) -> BasePacket | None:
        if self.buffer.size() < 4:
            return

        length = self.buffer.peekexactly(1)[0]
        is_quick_ack = length & 0x80 == 0x80
        length &= 0x7F

        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            return QuickAckPacket(self.buffer.readexactly(4)[::-1])

        big_length = length & 0x7F == 0x7F
        if big_length:
            length = int.from_bytes(self.buffer.peekexactly(3, 1), "little")

        length *= 4
        if self.buffer.size() < (length + 4 if big_length else 1):
            return

        self.buffer.readexactly(4 if big_length else 1)
        data = self.buffer.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> None:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            self.buffer.write(data[::-1])
            return

        length = (len(data) + 3) // 4

        if length >= 0x7F:
            self.buffer.write(b"\x7f")
            self.buffer.write(length.to_bytes(3, byteorder="little"))
        else:
            self.buffer.write(length.to_bytes(1, byteorder="little"))

        self.buffer.write(data)

    def has_packet(self) -> bool:
        if self.buffer.size() < 4:
            return False
        length = self.buffer.peekexactly(1)[0]
        if length & 0x80 == 0x80:
            return True
        length &= 0x7F

        length_size = 1
        if length & 0x7F == 0x7F:
            length_size = 4
            length = int.from_bytes(self.buffer.peekexactly(3, 1), "little")

        length *= 4
        return self.buffer.size() >= (length + length_size)

from __future__ import annotations

from .base_transport import BaseTransport
from .. import ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class IntermediateTransport(BaseTransport):
    def read(self) -> BasePacket | None:
        if self.buffer.size() < 4:
            return

        is_quick_ack = (self.buffer.peekexactly(1)[0] & 0x80) == 0x80
        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            return QuickAckPacket(self.buffer.readexactly(4))

        length = int.from_bytes(self.buffer.peekexactly(4), "little") & 0x7FFFFFFF
        if self.buffer.size() < length:
            return

        self.buffer.readexactly(4)
        data = self.buffer.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> None:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            self.buffer.write(data)
            return

        self.buffer.write(len(data).to_bytes(4, byteorder="little"))
        self.buffer.write(data)

    def has_packet(self) -> bool:
        if self.buffer.size() < 4:
            return False
        if self.buffer.peekexactly(1)[0] & 0x80 == 0x80:
            return True

        length = int.from_bytes(self.buffer.peekexactly(4), "little") & 0x7FFFFFFF
        return self.buffer.size() >= (length + 4)

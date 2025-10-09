from __future__ import annotations

from .base_transport import BaseTransport
from ..enums import ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class IntermediateTransport(BaseTransport):
    def read(self, *, _peek: bool = False) -> BasePacket | None:
        if self.rx_buffer.size() < 4:
            return None

        is_quick_ack = (self.rx_buffer.peekexactly(1)[0] & 0x80) == 0x80
        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            data = self.rx_buffer.peekexactly(4) if _peek else self.rx_buffer.readexactly(4)
            return QuickAckPacket(data)

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        if self.rx_buffer.size() < length:
            return None

        if not _peek:
            self.rx_buffer.readexactly(4)
        data = self.rx_buffer.peekexactly(length, 4) if _peek else self.rx_buffer.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> None:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            self.tx_buffer.write(data)
            return

        self.tx_buffer.write(len(data).to_bytes(4, byteorder="little"))
        self.tx_buffer.write(data)

    def has_packet(self) -> bool:
        if self.rx_buffer.size() < 4:
            return False
        if self.rx_buffer.peekexactly(1)[0] & 0x80 == 0x80:  # TODO: ?
            return True

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        return self.rx_buffer.size() >= (length + 4)

    def peek(self) -> BasePacket | None:
        if not self.has_packet():
            return None

        return self.read(_peek=True)

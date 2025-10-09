from __future__ import annotations

from .base_transport import BaseTransport
from ..enums import ConnectionRole
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class AbridgedTransport(BaseTransport):
    def read(self, *, _peek: bool = False) -> BasePacket | None:
        if self.rx_buffer.size() < 4:
            return None

        length = self.rx_buffer.peekexactly(1)[0]
        is_quick_ack = length & 0x80 == 0x80
        length &= 0x7F

        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            data = self.rx_buffer.peekexactly(4) if _peek else self.rx_buffer.readexactly(4)
            return QuickAckPacket(data[::-1])

        big_length = length & 0x7F == 0x7F
        if big_length:
            length = int.from_bytes(self.rx_buffer.peekexactly(3, 1), "little")

        length *= 4
        length_bytes = 4 if big_length else 1
        if self.rx_buffer.size() < (length + length_bytes):
            return None

        if not _peek:
            self.rx_buffer.readexactly(length_bytes)
        data = self.rx_buffer.peekexactly(length, length_bytes) if _peek else self.rx_buffer.readexactly(length)
        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, is_quick_ack)

    def write(self, packet: BasePacket) -> None:
        data = packet.write()
        if isinstance(packet, QuickAckPacket):
            self.tx_buffer.write(data[::-1])
            return

        length = (len(data) + 3) // 4

        if length >= 0x7F:
            self.tx_buffer.write(b"\x7f")
            self.tx_buffer.write(length.to_bytes(3, byteorder="little"))
        else:
            self.tx_buffer.write(length.to_bytes(1, byteorder="little"))

        self.tx_buffer.write(data)

    def _peek_length(self) -> tuple[int, int] | None:
        if self.rx_buffer.size() < 4:
            return None
        length = self.rx_buffer.peekexactly(1)[0]
        if length & 0x80 == 0x80:
            return None
        length &= 0x7F

        length_size = 1
        if length & 0x7F == 0x7F:
            length_size = 4
            length = int.from_bytes(self.rx_buffer.peekexactly(3, 1), "little")

        return length * 4, length_size

    def has_packet(self) -> bool:
        length_maybe = self._peek_length()
        if length_maybe is None:
            return False

        length, length_size = length_maybe
        return self.rx_buffer.size() >= (length + length_size)

    def peek(self) -> BasePacket | None:
        if not self.has_packet():
            return None

        return self.read(_peek=True)


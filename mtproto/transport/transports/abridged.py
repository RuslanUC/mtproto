from __future__ import annotations

from mtproto.enums import ConnectionRole, TransportEvent, TransportType
from .base_transport import TcpTransport
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class AbridgedTransport(TcpTransport):
    SUPPORTS_OBFUSCATION = True
    TYPE = TransportType.ABRIDGED

    __slots__ = ()

    def _read(self) -> BasePacket | TransportEvent | None:
        if len(self.rx_buffer) < 4:
            return None

        length = self.rx_buffer.peekexactly(1)[0]
        is_quick_ack = length & 0x80 == 0x80
        length &= 0x7F

        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            data = self.rx_buffer.readexactly(4)
            return QuickAckPacket(data[::-1])

        big_length = length & 0x7F == 0x7F
        if big_length:
            length = int.from_bytes(self.rx_buffer.peekexactly(3, 1), "little")

        length *= 4
        if length > self.max_packet_size:
            return TransportEvent.DISCONNECT

        length_bytes = 4 if big_length else 1
        if len(self.rx_buffer) < (length + length_bytes):
            return None

        self.rx_buffer.readexactly(length_bytes)
        data = self.rx_buffer.readexactly(length)
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

    def _has_packet(self) -> bool:
        if len(self.rx_buffer) < 4:
            return False

        length = self.rx_buffer.peekexactly(1)[0]

        if (length & 0x80 == 0x80) and self.our_role == ConnectionRole.CLIENT:
            return True

        length &= 0x7F
        big_length = length == 0x7F
        if big_length:
            length = int.from_bytes(self.rx_buffer.peekexactly(3, 1), "little")

        length *= 4
        length += 4 if big_length else 1
        return len(self.rx_buffer) >= length or length > self.max_packet_size

    def ready_read(self) -> bool:
        return True

    def ready_write(self) -> bool:
        return True


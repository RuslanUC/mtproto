from __future__ import annotations

from mtproto.enums import ConnectionRole, TransportEvent, TransportType
from .base_transport import TcpTransport
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class IntermediateTransport(TcpTransport):
    SUPPORTS_OBFUSCATION = True
    TYPE = TransportType.INTERMEDIATE

    __slots__ = ()

    def _read(self) -> BasePacket | TransportEvent | None:
        if len(self.rx_buffer) < 4:
            return None

        is_quick_ack = (self.rx_buffer.peekexactly(1)[0] & 0x80) == 0x80
        if is_quick_ack and self.our_role == ConnectionRole.CLIENT:
            data = self.rx_buffer.readexactly(4)
            return QuickAckPacket(data)

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        if length > self.max_packet_size:
            return TransportEvent.DISCONNECT
        if len(self.rx_buffer) < length:
            return None

        self.rx_buffer.readexactly(4)
        data = self.rx_buffer.readexactly(length)
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

    def _has_packet(self) -> bool:
        if len(self.rx_buffer) < 4:
            return False
        if self.rx_buffer.peekexactly(1)[0] & 0x80 == 0x80:  # TODO: ?
            return True

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little") & 0x7FFFFFFF
        return len(self.rx_buffer) >= (length + 4) or length > self.max_packet_size

    def ready_read(self) -> bool:
        return True

    def ready_write(self) -> bool:
        return True

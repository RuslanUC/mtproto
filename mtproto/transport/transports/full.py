from __future__ import annotations

from zlib import crc32

from .base_transport import TcpTransport
from ..buffer import TxBuffer, RxBuffer
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket
from ...enums import TransportEvent, ConnectionRole, TransportType


class FullTransport(TcpTransport):
    SUPPORTS_OBFUSCATION = False
    TYPE = TransportType.FULL

    __slots__ = ("_seq_no_r", "_seq_no_w",)

    def __init__(
            self,
            role: ConnectionRole,
            rx_buffer: RxBuffer,
            tx_buffer: TxBuffer,
            max_packet_size: int = 1024 * 1024,
    ) -> None:
        super().__init__(role, rx_buffer, tx_buffer, max_packet_size)
        self._seq_no_r = self._seq_no_w = 0

    def _read(self) -> BasePacket | TransportEvent | None:
        if len(self.rx_buffer) < 4:
            return None

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little")
        if length > self.max_packet_size:
            return TransportEvent.DISCONNECT
        if len(self.rx_buffer) < length:
            return None

        length_bytes = self.rx_buffer.readexactly(4)
        seq_no_bytes =  self.rx_buffer.readexactly(4)
        data = self.rx_buffer.readexactly(length - 12)
        crc_bytes = self.rx_buffer.readexactly(4)

        crc = int.from_bytes(crc_bytes, "little")
        if crc != crc32(length_bytes + seq_no_bytes + data):
            return None

        seq_no = int.from_bytes(seq_no_bytes, "little")
        if seq_no != self._seq_no_r:
            return None

        self._seq_no_r += 1

        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, False)

    def write(self, packet: BasePacket) -> None:
        if isinstance(packet, QuickAckPacket):
            raise ValueError("\"Full\" transport does not support quick-acks.")

        data = packet.write()

        tmp = TxBuffer()
        tmp.write((len(data) + 12).to_bytes(4, "little"))
        tmp.write(self._seq_no_w.to_bytes(4, "little"))
        tmp.write(data)
        tmp.write(crc32(tmp.data()).to_bytes(4, "little"))

        self._seq_no_w += 1

        self.tx_buffer.write(tmp)

    def _has_packet(self) -> bool:
        if len(self.rx_buffer) < 4:
            return False

        length = int.from_bytes(self.rx_buffer.peekexactly(4), "little")
        return len(self.rx_buffer) >= length or length > self.max_packet_size

    def ready_read(self) -> bool:
        return True

    def ready_write(self) -> bool:
        return True

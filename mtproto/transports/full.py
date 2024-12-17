from __future__ import annotations

from zlib import crc32

from .base_transport import BaseTransport
from .. import Buffer
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket


class FullTransport(BaseTransport):
    __slots__ = ("_seq_no_r", "_seq_no_w",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._seq_no_r = self._seq_no_w = 0

    def read(self) -> BasePacket | None:
        if self.buffer.size() < 4:
            return

        length = int.from_bytes(self.buffer.peekexactly(4), "little")
        if self.buffer.size() < length:
            return

        length_bytes = self.buffer.readexactly(4)
        seq_no_bytes = self.buffer.readexactly(4)
        seq_no = int.from_bytes(seq_no_bytes, "little")
        data = self.buffer.readexactly(length - 12)
        crc = int.from_bytes(self.buffer.readexactly(4), "little")

        if crc != crc32(length_bytes + seq_no_bytes + data):
            return
        if seq_no != self._seq_no_r:
            return
        self._seq_no_r += 1

        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, False)

    def write(self, packet: BasePacket) -> None:
        if isinstance(packet, QuickAckPacket):
            raise ValueError("\"Full\" transport does not support quick-acks.")

        data = packet.write()

        tmp = Buffer()
        tmp.write((len(data) + 12).to_bytes(4, byteorder="little"))
        tmp.write(self._seq_no_w.to_bytes(4, "little"))
        tmp.write(data)
        tmp.write(crc32(tmp.data()).to_bytes(4, byteorder="little"))

        self._seq_no_w += 1

        self.buffer.write(tmp.data())

    def has_packet(self) -> bool:
        if self.buffer.size() < 4:
            return False

        length = int.from_bytes(self.buffer.peekexactly(4), "little")
        return self.buffer.size() >= length

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

    def read(self, buf: Buffer) -> BasePacket | None:
        if buf.size() < 4:
            return

        length = int.from_bytes(buf.peekexactly(4), "little")
        if buf.size() < length:
            return

        length_bytes = buf.readexactly(4)
        seq_no_bytes = buf.readexactly(4)
        seq_no = int.from_bytes(seq_no_bytes, "little")
        data = buf.readexactly(length - 12)
        crc = int.from_bytes(buf.readexactly(4), "little")

        if crc != crc32(length_bytes + seq_no_bytes + data):
            return
        if seq_no != self._seq_no_r:
            return
        self._seq_no_r += 1

        if len(data) == 4:
            return ErrorPacket(int.from_bytes(data, "little", signed=True))

        return MessagePacket.parse(data, False)

    def write(self, packet: BasePacket) -> bytes:
        if isinstance(packet, QuickAckPacket):
            raise ValueError("\"Full\" transport does not support quick-acks.")

        data = packet.write()

        buf = Buffer()
        buf.write((len(data) + 12).to_bytes(4, byteorder="little"))
        buf.write(self._seq_no_w.to_bytes(4, "little"))
        buf.write(data)
        buf.write(crc32(buf.data()).to_bytes(4, byteorder="little"))

        self._seq_no_w += 1

        return buf.data()

    def has_packet(self, buf: Buffer) -> bool:
        if buf.size() < 4:
            return False

        length = int.from_bytes(buf.peekexactly(4), "little")
        return buf.size() >= length

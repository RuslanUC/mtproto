from __future__ import annotations

from .base_transport import BaseTransport
from .. import Buffer, ObfuscatedBuffer
from ..crypto.aes import CtrTuple
from ..packets import BasePacket


class ObfuscatedTransport(BaseTransport):
    __slots__ = ("_transport", "_encrypt", "_decrypt",)

    def __init__(self, transport: BaseTransport, encrypt: CtrTuple, decrypt: CtrTuple) -> None:
        super().__init__(transport.our_role)

        self._transport = transport
        self._encrypt = encrypt
        self._decrypt = decrypt

    def set_buffer(self, buffer: Buffer) -> Buffer:
        back_buffer = Buffer()
        obf_buffer = ObfuscatedBuffer(back_buffer, self._encrypt, self._decrypt)
        obf_buffer.raw_write(buffer.readall())

        self._transport.set_buffer(back_buffer)

        return obf_buffer

    def read(self) -> BasePacket | None:
        return self._transport.read()

    def write(self, packet: BasePacket) -> None:
        return self._transport.write(packet)

    def has_packet(self) -> bool:
        return self._transport.has_packet()

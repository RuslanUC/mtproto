from __future__ import annotations

from .base_transport import BaseTransport
from .. import Buffer, ObfuscatedBuffer
from ..crypto.aes import ctr256_encrypt, CtrTuple
from ..packets import BasePacket


class ObfuscatedTransport(BaseTransport):
    __slots__ = ("_transport", "_encrypt", "_decrypt",)

    def __init__(self, transport: BaseTransport, encrypt: CtrTuple, decrypt: CtrTuple) -> None:
        super().__init__(transport.our_role)

        self._transport = transport
        self._encrypt = encrypt
        self._decrypt = decrypt

    def read(self, buf: Buffer) -> BasePacket | None:
        buf = ObfuscatedBuffer(buf, self._encrypt, self._decrypt)
        return self._transport.read(buf)

    def write(self, packet: BasePacket) -> bytes:
        data = self._transport.write(packet)
        return ctr256_encrypt(data, *self._encrypt)

    def has_packet(self, buf: Buffer) -> bool:
        buf = ObfuscatedBuffer(buf, self._encrypt, self._decrypt)
        return self._transport.has_packet(buf)

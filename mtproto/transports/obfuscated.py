from __future__ import annotations

from .base_transport import BaseTransport
from .. import Buffer, ObfuscatedBuffer
from ..crypto.aes import ctr256_encrypt, CtrTuple


class ObfuscatedTransport(BaseTransport):
    __slots__ = ("_transport", "_encrypt", "_decrypt")

    def __init__(self, transport: BaseTransport, encrypt: CtrTuple, decrypt: CtrTuple) -> None:
        super().__init__(transport.role)

        self._transport = transport
        self._encrypt = encrypt
        self._decrypt = decrypt

    def is_quick_ack(self, buf: Buffer) -> bool:
        buf = ObfuscatedBuffer(buf, self._encrypt, self._decrypt)
        return self._transport.is_quick_ack(buf)

    def read_length(self, buf: Buffer) -> int | None:
        buf = ObfuscatedBuffer(buf, self._encrypt, self._decrypt)
        return self._transport.read_length(buf)

    def read(self, buf: Buffer, length: int) -> bytes | None:
        buf = ObfuscatedBuffer(buf, self._encrypt, self._decrypt)
        return self._transport.read(buf, length)

    def write(self, data: bytes) -> bytes:
        data = self._transport.write(data)
        return ctr256_encrypt(data, *self._encrypt)

from __future__ import annotations

from mtproto.crypto.aes import ctr256_decrypt, ctr256_encrypt, CtrTuple


class Buffer:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes = b""):
        self._data = data

    def size(self) -> int:
        return len(self._data)

    def data(self) -> bytes:
        return self._data

    def readexactly(self, n: int) -> bytes | None:
        if len(self._data) < n:
            return

        data = self._data[:n]
        self._data = self._data[n:]

        return data

    def readall(self) -> bytes:
        data, self._data = self._data, b""
        return data

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        if len(self._data) < (n + offset):
            return

        return self._data[offset:offset+n]

    def write(self, data: bytes) -> None:
        self._data += data


class ObfuscatedBuffer(Buffer):
    __slots__ = ("_buffer", "_encrypt", "_decrypt")

    def __init__(self, data: bytes | Buffer, encrypt: CtrTuple, decrypt: CtrTuple):
        super().__init__()

        if isinstance(data, bytes):
            data = Buffer(data)
        self._buffer = data
        self._encrypt = encrypt
        self._decrypt = decrypt

    def readexactly(self, n: int) -> bytes | None:
        if (data := self._buffer.readexactly(n)) is None:
            return

        return ctr256_decrypt(data, *self._decrypt)

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        if (data := self._buffer.peekexactly(n)) is None:
            return

        return ctr256_decrypt(data, *self._decrypt)

    def write(self, data: bytes) -> None:
        self._buffer.write(ctr256_encrypt(data, *self._encrypt))

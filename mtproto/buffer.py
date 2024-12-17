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
        if self.size() < n:
            return

        data, self._data = self._data[:n], self._data[n:]

        return data

    def readall(self) -> bytes:
        data, self._data = self._data, b""
        return data

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        if self.size() < (n + offset):
            return

        return self._data[offset:offset+n]

    def write(self, data: bytes) -> None:
        self._data += data

    def raw_write(self, data: bytes) -> None:
        return self.write(data)

    def raw_readall(self) -> bytes:
        return self.readall()


class ObfuscatedBuffer(Buffer):
    __slots__ = ("_buffer", "_encrypt", "_decrypt")

    def __init__(self, buffer: Buffer, encrypt: CtrTuple, decrypt: CtrTuple):
        super().__init__()

        self._buffer = buffer
        self._encrypt = encrypt
        self._decrypt = decrypt

    def size(self) -> int:
        return self._buffer.size()

    def readexactly(self, n: int) -> bytes | None:
        return self._buffer.readexactly(n)

    def readall(self) -> bytes:
        return self._buffer.readall()

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        return self._buffer.peekexactly(n, offset)

    def write(self, data: bytes) -> None:
        return self._buffer.write(data)

    def raw_write(self, data: bytes) -> None:
        if data:
            self._buffer.write(ctr256_decrypt(data, *self._decrypt))

    def raw_readall(self) -> bytes:
        return ctr256_encrypt(self._buffer.readall(), *self._encrypt)

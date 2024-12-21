from __future__ import annotations

from mtproto.crypto.aes import ctr256_decrypt, ctr256_encrypt, CtrTuple


class RxBuffer:
    __slots__ = ("_data",)

    def __init__(self, data: bytes = b""):
        self._data = data

    def size(self) -> int:
        return len(self._data)

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

    def data_received(self, data: bytes) -> None:
        self._data += data


class TxBuffer:
    __slots__ = ("_data",)

    def __init__(self, data: bytes = b""):
        self._data = data

    def data(self) -> bytes:
        return self._data

    def write(self, data: bytes | TxBuffer) -> None:
        if isinstance(data, TxBuffer):
            data = data.get_data()
        self._data += data

    def get_data(self) -> bytes:
        data, self._data = self._data, b""
        return data


class ObfuscatedRxBuffer(RxBuffer):
    __slots__ = ("_buffer", "_decrypt")

    def __init__(self, buffer: RxBuffer, decrypt: CtrTuple):
        super().__init__()

        self._buffer = buffer
        self._decrypt = decrypt

    def size(self) -> int:
        return self._buffer.size()

    def readexactly(self, n: int) -> bytes | None:
        return self._buffer.readexactly(n)

    def readall(self) -> bytes:
        return self._buffer.readall()

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        return self._buffer.peekexactly(n, offset)

    def data_received(self, data: bytes) -> None:
        if data:
            self._buffer.data_received(ctr256_decrypt(data, *self._decrypt))


class ObfuscatedTxBuffer(TxBuffer):
    __slots__ = ("_buffer", "_encrypt",)

    def __init__(self, buffer: TxBuffer, encrypt: CtrTuple):
        super().__init__()

        self._buffer = buffer
        self._encrypt = encrypt

    def data(self) -> bytes:
        return self._buffer.data()

    def write(self, data: bytes | TxBuffer) -> None:
        return self._buffer.write(data)

    def get_data(self) -> bytes:
        return ctr256_encrypt(self._buffer.get_data(), *self._encrypt)

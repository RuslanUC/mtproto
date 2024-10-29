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


class ObfuscatedBuffer(Buffer):
    __slots__ = ("_buffer", "_encrypt", "_decrypt", "_decrypted")

    def __init__(self, data: bytes | Buffer, encrypt: CtrTuple, decrypt: CtrTuple):
        super().__init__()

        if isinstance(data, bytes):
            data = Buffer(data)
        self._buffer = data
        self._encrypt = encrypt
        self._decrypt = decrypt

    def size(self) -> int:
        return self._buffer.size()

    def readexactly(self, n: int) -> bytes | None:
        if self.size() < n:
            return

        return ctr256_decrypt(self._buffer.readexactly(n), *self._decrypt)

    def readall(self) -> bytes:
        return ctr256_decrypt(self._buffer.readall(), *self._decrypt)

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        if self.size() < (n + offset):
            return

        # Backup state
        *dec, state = self._decrypt
        #old_iv = bytes(dec[1])
        new_state = bytearray(state)
        encrypted = self._buffer.peekexactly(n + offset)
        d = ctr256_decrypt(encrypted, *dec, new_state)
        #print(f"decrypted: {encrypted} -> {d}, state: {state} -> {new_state}")
        return d[offset:offset+n]

    def write(self, data: bytes) -> None:
        self._buffer.write(ctr256_encrypt(data, *self._encrypt))

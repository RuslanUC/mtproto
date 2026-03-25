from __future__ import annotations

from mtproto.crypto.aes import ctr256_decrypt, ctr256_encrypt, CtrTuple


class RxBuffer:
    __slots__ = ("_data", "_decrypt",)

    def __init__(self, data: bytes = b""):
        self._data = bytearray(data)
        self._decrypt = None

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return bool(len(self))

    def readexactly(self, n: int) -> bytes | None:
        if len(self) < n:
            return None

        data = self._data[:n]
        del self._data[:n]

        return data

    def readall(self) -> bytes:
        data, self._data = self._data, bytearray()
        return bytes(data)

    def peekexactly(self, n: int, offset: int = 0) -> bytes | None:
        if len(self) < (n + offset):
            return None

        return self._data[offset:offset+n]

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        if self._decrypt:
            data = ctr256_decrypt(data, *self._decrypt)
        self._data += data

    def deobfuscate(self, decrypt: CtrTuple, decrypt_existing: bool = True) -> None:
        self._decrypt = decrypt
        if decrypt_existing and self._data:
            self._data = bytearray(ctr256_decrypt(self._data, *self._decrypt))


class TxBuffer:
    __slots__ = ("_data", "_encrypt",)

    def __init__(self, data: bytes = b""):
        self._data = bytearray(data)
        self._encrypt = None

    def __len__(self) -> int:
        return len(self._data)

    def data(self) -> bytearray:
        return self._data

    def write(self, data: bytes | TxBuffer) -> None:
        if isinstance(data, TxBuffer):
            assert data._encrypt is None
            data = data.get_data()
        if self._encrypt:
            data = ctr256_encrypt(data, *self._encrypt)
        self._data += data

    def get_data(self) -> bytes:
        data, self._data = self._data, bytearray()
        return data

    def obfuscate(self, encrypt: CtrTuple) -> None:
        self._encrypt = encrypt

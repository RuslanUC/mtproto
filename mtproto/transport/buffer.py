from __future__ import annotations

from mtproto.crypto.aes import ctr256_decrypt, ctr256_encrypt, CtrTuple


class _BaseBuffer:
    __slots__ = ("_data", "_ctr",)

    def __init__(self, data: bytes = b""):
        self._data = bytearray(data)
        self._ctr: CtrTuple | None = None

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return bool(len(self))

    @property
    def is_obfuscated(self) -> bool:
        return self._ctr is not None


class RxBuffer(_BaseBuffer):
    __slots__ = ()

    def readexactly(self, n: int) -> bytearray:
        if len(self) < n:
            raise ValueError(f"Buffer size ({len(self)}) is less than {n}")

        data = self._data[:n]
        del self._data[:n]

        return data

    def readall(self) -> bytearray:
        data, self._data = self._data, bytearray()
        return data

    def peekexactly(self, n: int, offset: int = 0) -> bytearray:
        if len(self) < (n + offset):
            raise ValueError(f"Buffer size ({len(self)}) is less than {n}")

        return self._data[offset:offset+n]

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        if self._ctr:
            # TODO: inplace decrypt?
            data = ctr256_decrypt(data, *self._ctr)
        self._data += data

    def deobfuscate(self, decrypt: CtrTuple, decrypt_existing: bool = True) -> None:
        self._ctr = decrypt
        if decrypt_existing and self._data and self._ctr:
            # TODO: inplace decrypt
            self._data = bytearray(ctr256_decrypt(self._data, *self._ctr))


class TxBuffer(_BaseBuffer):
    __slots__ = ()

    def data(self) -> bytearray:
        return self._data

    def write(self, data: bytes | TxBuffer) -> None:
        if isinstance(data, TxBuffer):
            assert data._ctr is None
            data = data.get_data()
        if self._ctr:
            # TODO: inplace encrypt
            data = ctr256_encrypt(data, *self._ctr)
        self._data += data

    def get_data(self) -> bytearray:
        data, self._data = self._data, bytearray()
        return data

    def obfuscate(self, encrypt: CtrTuple) -> None:
        self._ctr = encrypt

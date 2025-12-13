from __future__ import annotations

from io import BytesIO
from typing import Self

from mtproto.utils import Long, Int


class FutureSalt:
    __slots__ = ("valid_since", "valid_until", "salt",)

    def __init__(self, valid_since: int, valid_until: int, salt: int):
        self.valid_since = valid_since
        self.valid_until = valid_until
        self.salt = salt

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        valid_since = Int.read(stream)
        valid_until = Int.read(stream)
        salt = Long.read(stream)

        return FutureSalt(valid_since, valid_until, salt)

    def serialize(self) -> bytes:
        return (
                Int.write(self.valid_since)
                + Int.write(self.valid_until)
                + Long.write(self.salt)
        )

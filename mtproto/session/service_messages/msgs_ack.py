from __future__ import annotations

from array import array
from io import BytesIO
from typing import MutableSequence, Self

from mtproto.utils import Int

VECTOR = b"\x15\xc4\xb5\x1c"


class MsgsAck:
    __tl_id__ = 0x62d6b459
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("msg_ids", )

    def __init__(self, msg_ids: MutableSequence[int]):
        self.msg_ids = msg_ids

    def serialize(self) -> bytes:
        result = b"\x15\xc4\xb5\x1c"
        result += Int.write(len(self.msg_ids))
        result += array("q", self.msg_ids).tobytes()
        return result

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != VECTOR:
            raise ValueError(f"Expected constructor {VECTOR.hex()}, got {constructor.hex()}")
        count = Int.read(stream)
        msg_ids = array("q", stream.read(count * 8))
        return cls(msg_ids)

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()

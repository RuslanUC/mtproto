from __future__ import annotations

from array import array
from typing import cast, MutableSequence

from mtproto.utils import Int

VECTOR = b"\x15\xc4\xb5\x1c"


class MsgsAck:
    __tl_id__ = 0x62d6b459

    __slots__ = ("msg_ids", )

    def __init__(self, msg_ids: MutableSequence[int]):
        self.msg_ids = msg_ids

    def serialize(self) -> bytes:
        result = b"\x15\xc4\xb5\x1c"
        result += Int.write(len(self.msg_ids))
        result += array("q", self.msg_ids).tobytes()
        return result

    @classmethod
    def deserialize(cls, stream) -> MsgsAck:
        constructor = stream.read(4)
        if constructor != VECTOR:
            raise ValueError(f"Expected constructor {VECTOR.hex()}, got {constructor.hex()}")
        count = Int.read(stream)
        msg_ids = array("q", stream.read(count * 8))
        return cls(msg_ids)

    def write(self) -> bytes:
        return Int.write(self.__tl_id__, False) + self.serialize()

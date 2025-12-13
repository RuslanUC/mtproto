from io import BytesIO
from typing import Self

from ...utils import Int


class GetFutureSalts:
    __tl_id__ = 0xb921bd04
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("num",)

    def __init__(self, num: int):
        self.num = num

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        return GetFutureSalts(Int.read(stream))

    def serialize(self) -> bytes:
        return Int.write(self.num)

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()

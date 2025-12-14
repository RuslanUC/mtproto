from io import BytesIO
from typing import Self

from ...utils import Int


class HttpWait:
    __tl_id__ = 0x9299359f
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("max_delay", "wait_after", "max_wait",)

    def __init__(self, max_delay: int, wait_after: int, max_wait: int):
        self.max_delay = max_delay
        self.wait_after = wait_after
        self.max_wait = max_wait

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        max_delay = Int.read(stream)
        wait_after = Int.read(stream)
        max_wait = Int.read(stream)
        return cls(max_delay, wait_after, max_wait)

    def serialize(self) -> bytes:
        return Int.write(self.max_delay) + Int.write(self.wait_after) + Int.write(self.max_wait)

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()

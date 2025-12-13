from io import BytesIO
from typing import Self

from .future_salt import FutureSalt
from ...utils import Int, Long


class FutureSalts:
    __tl_id__ = 0xae500895
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("req_msg_id", "now", "salts",)

    def __init__(self, req_msg_id: int, now: int, salts: list[FutureSalt]):
        self.req_msg_id = req_msg_id
        self.now = now
        self.salts = salts

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        req_msg_id = Long.read(stream)
        now = Int.read(stream)

        count = Int.read(stream)
        salts = []

        for _ in range(count):
            salts.append(FutureSalt.deserialize(stream))

        return FutureSalts(req_msg_id, now, salts)

    def serialize(self) -> bytes:
        result = Long.write(self.req_msg_id)
        result += Int.write(self.now)

        result += Int.write(len(self.salts))
        for salt in self.salts:
            result += salt.serialize()

        return result

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()

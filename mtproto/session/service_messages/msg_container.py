from io import BytesIO
from typing import Self, Sequence

from .message import Message
from ...utils import Int


class MsgContainer:
    __tl_id__ = 0x73f1f8dc
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("messages",)

    def __init__(self, messages: Sequence[Message]):
        self.messages = messages

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        count = Int.read(stream)
        result = []

        for _ in range(count):
            result.append(Message.deserialize(stream))

        return MsgContainer(messages=result)

    def serialize(self) -> bytes:
        result = Int.write(len(self.messages))
        for message in self.messages:
            result += message.serialize()
        return result

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()

from io import BytesIO
from typing import Self

from .message import Message
from ...utils import Int


class MsgContainer:
    __tl_id__ = 0x73f1f8dc

    __slots__ = ("messages",)

    def __init__(self, messages: list[Message]):
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
        constructor = Int.read(stream, False)
        if constructor != cls.__tl_id__:
            raise ValueError(f"Expected constructor {hex(cls.__tl_id__)}, got {hex(constructor)}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return Int.write(self.__tl_id__, False) + self.serialize()
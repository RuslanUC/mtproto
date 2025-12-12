from io import BytesIO
from typing import Self

from .message import Message
from ...utils import Int

MSG_CONTAINER_ID_BYTES = Int.write(0x73f1f8dc, False)


class MsgContainer:
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
        constructor = stream.read(4)
        if constructor != MSG_CONTAINER_ID_BYTES:
            raise ValueError(f"Expected constructor {MSG_CONTAINER_ID_BYTES.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return MSG_CONTAINER_ID_BYTES + self.serialize()

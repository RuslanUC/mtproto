from __future__ import annotations

from io import BytesIO
from typing import Self

from mtproto.utils import Long, Int


class Message:
    __slots__ = ("message_id", "seq_no", "body",)

    def __init__(self, message_id: int, seq_no: int, body: bytes):
        self.message_id = message_id
        self.seq_no = seq_no
        self.body = body

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Self:
        msg_id = Long.read(stream)
        seq_no = Int.read(stream)
        length = Int.read(stream)
        body = stream.read(length)

        return Message(message_id=msg_id, seq_no=seq_no, body=body)

    def serialize(self) -> bytes:
        return (
                Long.write(self.message_id)
                + Int.write(self.seq_no)
                + Int.write(len(self.body))
                + self.body
        )

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        return Message.deserialize(stream)

    def write(self) -> bytes:
        return self.serialize()

from io import BytesIO
from typing import Self

from mtproto.utils import Long, Int


class NewSessionCreated:
    __tl_id__ = 0x9ec20908
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("first_msg_id", "unique_id", "server_salt", )

    def __init__(self, *, first_msg_id: int, unique_id: int, server_salt: int):
        self.first_msg_id = first_msg_id
        self.unique_id = unique_id
        self.server_salt = server_salt

    def serialize(self) -> bytes:
        result = b""
        result += Long.write(self.first_msg_id)
        result += Long.write(self.unique_id)
        result += Long.write(self.server_salt)
        return result

    @classmethod
    def deserialize(cls, stream) -> Self:
        first_msg_id = Long.read(stream)
        unique_id = Long.read(stream)
        server_salt = Long.read(stream)
        return cls(first_msg_id=first_msg_id, unique_id=unique_id, server_salt=server_salt)

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()
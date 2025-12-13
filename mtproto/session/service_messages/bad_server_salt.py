from io import BytesIO
from typing import Self

from mtproto.utils import Long, Int


class BadServerSalt:
    __tl_id__ = 0xedab447b
    __tl_id_bytes__ = Int.write(__tl_id__, False)

    __slots__ = ("bad_msg_id", "bad_msg_seqno", "error_code", "new_server_salt",)

    def __init__(self, *, bad_msg_id: int, bad_msg_seqno: int, error_code: int, new_server_salt: int):
        self.bad_msg_id = bad_msg_id
        self.bad_msg_seqno = bad_msg_seqno
        self.error_code = error_code
        self.new_server_salt = new_server_salt

    def serialize(self) -> bytes:
        result = b""
        result += Long.write(self.bad_msg_id)
        result += Int.write(self.bad_msg_seqno)
        result += Int.write(self.error_code)
        result += Long.write(self.new_server_salt)
        return result

    @classmethod
    def deserialize(cls, stream) -> Self:
        bad_msg_id = Long.read(stream)
        bad_msg_seqno = Int.read(stream)
        error_code = Int.read(stream)
        new_server_salt = Long.read(stream)
        return cls(
            bad_msg_id=bad_msg_id, bad_msg_seqno=bad_msg_seqno, error_code=error_code, new_server_salt=new_server_salt,
        )

    @classmethod
    def read(cls, stream: BytesIO) -> Self:
        constructor = stream.read(4)
        if constructor != cls.__tl_id_bytes__:
            raise ValueError(f"Expected constructor {cls.__tl_id_bytes__.hex()}, got {constructor.hex()}")

        return cls.deserialize(stream)

    def write(self) -> bytes:
        return self.__tl_id_bytes__ + self.serialize()
from __future__ import annotations

from abc import ABC
from io import BytesIO

from mtproto.packets import BasePacket


class MessagePacket(BasePacket, ABC):
    @classmethod
    def parse(cls, payload: bytes, needs_quick_ack: bool = False) -> MessagePacket | None:
        buf = BytesIO(payload)
        auth_key_id = int.from_bytes(buf.read(8), "little")
        if auth_key_id == 0:
            message_id = int.from_bytes(buf.read(8), "little")
            message_length = int.from_bytes(buf.read(4), "little")
            return UnencryptedMessagePacket(message_id, buf.read(message_length))

        message_key = buf.read(16)
        encrypted_data = buf.read()
        return EncryptedMessagePacket(auth_key_id, message_key, encrypted_data)


class UnencryptedMessagePacket(MessagePacket):
    __slots__ = ("message_id", "message_data",)

    def __init__(self, message_id: int, message_data: bytes):
        self.message_id = message_id
        self.message_data = message_data

    def write(self) -> bytes:
        return (
                (0).to_bytes(8, "little") +
                self.message_id.to_bytes(8, "little") +
                len(self.message_data).to_bytes(4, "little") +
                self.message_data
        )


class EncryptedMessagePacket(MessagePacket):
    __slots__ = ("auth_key_id", "message_key", "encrypted_data",)

    def __init__(self, auth_key_id: int, message_key: bytes, encrypted_data: bytes):
        self.auth_key_id = auth_key_id
        self.message_key = message_key
        self.encrypted_data = encrypted_data

    def write(self) -> bytes:
        return (
                self.auth_key_id.to_bytes(8, "little") +
                self.message_key +
                self.encrypted_data
        )

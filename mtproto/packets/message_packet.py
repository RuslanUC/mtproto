from __future__ import annotations

from abc import ABC
from hashlib import sha256, sha1
from io import BytesIO
from os import urandom

from mtproto.crypto import kdf, ige256_encrypt, ige256_decrypt
from mtproto.crypto.aes import kdf_v1
from mtproto.enums import ConnectionRole
from mtproto.utils import AutoRepr, Long, Int
from .base_packet import BasePacket
from .quick_ack_packet import QuickAckPacket


class MessagePacket(BasePacket, ABC):
    @classmethod
    def parse(cls, payload: bytes, needs_quick_ack: bool = False) -> MessagePacket | None:
        buf = BytesIO(payload)
        auth_key_id = Long.read(buf)
        if auth_key_id == 0:
            message_id = Long.read(buf)
            message_length = Int.read(buf)
            return UnencryptedMessagePacket(message_id, buf.read(message_length))

        message_key = buf.read(16)
        encrypted_data = buf.read()
        return EncryptedMessagePacket(auth_key_id, message_key, encrypted_data, needs_quick_ack)


class UnencryptedMessagePacket(MessagePacket, AutoRepr):
    __slots__ = ("message_id", "message_data",)

    def __init__(self, message_id: int, message_data: bytes):
        self.message_id = message_id
        self.message_data = message_data

    def write(self) -> bytes:
        return (
                Long.write(0) +
                Long.write(self.message_id) +
                Int.write(len(self.message_data)) +
                self.message_data
        )


class EncryptedMessagePacket(MessagePacket, AutoRepr):
    __slots__ = ("auth_key_id", "message_key", "encrypted_data", "needs_quick_ack",)

    def __init__(self, auth_key_id: int, message_key: bytes, encrypted_data: bytes, needs_quick_ack: bool = False):
        self.auth_key_id = auth_key_id
        self.message_key = message_key
        self.encrypted_data = encrypted_data
        self.needs_quick_ack = needs_quick_ack

    def write(self) -> bytes:
        return (
                Long.write(self.auth_key_id) +
                self.message_key +
                self.encrypted_data
        )

    def decrypt(self, auth_key: bytes, sender_role: ConnectionRole, v1: bool = False) -> DecryptedMessagePacket:
        if (got_key_id := Long.read_bytes(sha1(auth_key).digest()[-8:])) != self.auth_key_id:
            raise ValueError(f"Invalid auth_key: expected key with id {self.auth_key_id}, got {got_key_id}")

        kdf_func = kdf_v1 if v1 else kdf
        aes_key, aes_iv = kdf_func(auth_key, self.message_key, sender_role == ConnectionRole.CLIENT)

        decrypted = ige256_decrypt(self.encrypted_data, aes_key, aes_iv)
        return DecryptedMessagePacket.parse(decrypted)


class DecryptedMessagePacket(MessagePacket, AutoRepr):
    __slots__ = ("salt", "session_id", "message_id", "seq_no", "data", "padding",)

    def __init__(
            self, salt: bytes, session_id: int, message_id: int, seq_no: int, data: bytes, padding: bytes | None = None
    ):
        self.salt = salt
        self.session_id = session_id
        self.message_id = message_id
        self.seq_no = seq_no
        self.data = data
        self.padding = padding

    def write(self) -> bytes:
        raise NotImplementedError(
            f"{self.__class__.__name__}.write is not implemented. "
            f"You should call {self.__class__.__name__}.encrypt and call .write on returned encrypted message."
        )

    @classmethod
    def parse(cls, data: bytes, *args, **kwargs) -> DecryptedMessagePacket:
        buf = BytesIO(data)
        salt = buf.read(8)
        session_id = Long.read(buf)
        message_id = Long.read(buf)
        seq_no = Int.read(buf)
        length = Int.read(buf)

        return cls(
            salt,
            session_id,
            message_id,
            seq_no,
            buf.read(length),
            buf.read(),
        )

    def encrypt(self, auth_key: bytes, sender_role: ConnectionRole) -> EncryptedMessagePacket:
        data = (
                self.salt +
                Long.write(self.session_id) +
                Long.write(self.message_id) +
                Int.write(self.seq_no) +
                Int.write(len(self.data)) +
                self.data
        )

        padding = urandom(-(len(data) + 12) % 16 + 12)

        # 96 = 88 + 8 (8 = incoming message (server message); 0 = outgoing (client message))
        key_offset = 88 + (0 if sender_role == ConnectionRole.CLIENT else 8)
        msg_key_large = sha256(auth_key[key_offset:key_offset + 32] + data + padding).digest()
        msg_key = msg_key_large[8:24]
        aes_key, aes_iv = kdf(auth_key, msg_key, sender_role == ConnectionRole.CLIENT)

        return EncryptedMessagePacket(
            Long.read_bytes(sha1(auth_key).digest()[-8:]),
            msg_key,
            ige256_encrypt(data + padding, aes_key, aes_iv),
        )

    def quick_ack_response(self, auth_key: bytes, sender_role: ConnectionRole) -> QuickAckPacket:
        key_offset = 88 + (0 if sender_role == ConnectionRole.CLIENT else 8)
        msg_key_large = sha256(auth_key[key_offset:key_offset + 32] + self.data + self.padding).digest()

        return QuickAckPacket(
            Int.write(-abs(Int.read_bytes(msg_key_large[:4])))
        )

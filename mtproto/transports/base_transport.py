from __future__ import annotations
from abc import ABC, abstractmethod

from mtproto import Buffer, transports, ConnectionRole
from mtproto.crypto.aes import ctr256_decrypt
from mtproto.packets import BasePacket


class BaseTransport(ABC):
    def __init__(self, role: ConnectionRole):
        self.role = role

    @abstractmethod
    def read(self, buf: Buffer) -> BasePacket | None: ...

    @abstractmethod
    def write(self, packet: BasePacket) -> bytes: ...

    @classmethod
    def new(cls, buf: Buffer, role: ConnectionRole, _four_ef: bool = False) -> BaseTransport | None:
        ef_count = 4 if _four_ef else 1
        if (header := buf.peekexactly(ef_count)) is None:
            return

        if header == b"\xef" * ef_count:
            buf.readexactly(ef_count)
            return transports.AbridgedTransport(role)

        if (header := buf.peekexactly(4)) is None:
            return

        if header == b"\xee" * 4:
            buf.readexactly(4)
            return transports.IntermediateTransport(role)
        elif header == b"\xdd" * 4:
            buf.readexactly(4)
            return transports.PaddedIntermediateTransport(role)
        elif header in {b"POST", b"GET ", b"HEAD"}:
            ...  # TODO: http transport
        elif buf.peekexactly(4, 4) == b"\x00" * 4:
            return transports.FullTransport(role)
        elif buf.size() < 64:
            return

        nonce = buf.readexactly(64)
        temp = nonce[8:56][::-1]
        encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
        decrypt = (temp[0:32], temp[32:48], bytearray(1))
        decrypted = ctr256_decrypt(nonce, *encrypt)
        header = decrypted[56:56 + 4]

        if (transport := BaseTransport.new(Buffer(header), role)) is None:
            raise ValueError(f"Unknown transport!")

        return transports.ObfuscatedTransport(transport, encrypt, decrypt)

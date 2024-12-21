from __future__ import annotations

from abc import ABC, abstractmethod
from os import urandom

from mtproto import transports
from mtproto.buffer import RxBuffer, TxBuffer
from mtproto.crypto.aes import ctr256_decrypt, ctr256_encrypt
from mtproto.enums import ConnectionRole
from mtproto.packets import BasePacket

HTTP_HEADER = {b"POST", b"GET ", b"HEAD", b"OPTI"}


class BaseTransport(ABC):
    __slots__ = ("our_role", "rx_buffer", "tx_buffer",)

    def __init__(self, role: ConnectionRole):
        self.our_role = role
        self.rx_buffer: RxBuffer | None = None
        self.tx_buffer: TxBuffer | None = None

    @abstractmethod
    def read(self) -> BasePacket | None: ...

    @abstractmethod
    def write(self, packet: BasePacket) -> None: ...

    @abstractmethod
    def has_packet(self) -> bool: ...

    def set_buffers(self, rx_buffer: RxBuffer, tx_buffer: TxBuffer) -> tuple[RxBuffer, TxBuffer]:
        self.rx_buffer = rx_buffer
        self.tx_buffer = tx_buffer

        return rx_buffer, tx_buffer

    @classmethod
    def from_buffer(cls, buf: RxBuffer, _four_ef: bool = False) -> BaseTransport | None:
        ef_count = 4 if _four_ef else 1
        if (header := buf.peekexactly(ef_count)) is None:
            return

        if header == b"\xef" * ef_count:
            buf.readexactly(ef_count)
            return transports.AbridgedTransport(ConnectionRole.SERVER)

        if (header := buf.peekexactly(4)) is None:
            return

        if header == b"\xee" * 4:
            buf.readexactly(4)
            return transports.IntermediateTransport(ConnectionRole.SERVER)
        elif header == b"\xdd" * 4:
            buf.readexactly(4)
            return transports.PaddedIntermediateTransport(ConnectionRole.SERVER)
        elif header in HTTP_HEADER:
            ...  # TODO: http transport
        elif buf.peekexactly(4, 4) == b"\x00" * 4:
            return transports.FullTransport(ConnectionRole.SERVER)
        elif buf.size() < 64:
            return

        nonce = buf.readexactly(64)
        temp = nonce[8:56][::-1]
        encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
        decrypt = (temp[0:32], temp[32:48], bytearray(1))
        decrypted = ctr256_decrypt(nonce, *encrypt)
        header = decrypted[56:56 + 4]

        if (transport := cls.from_buffer(RxBuffer(header), True)) is None:
            raise ValueError(f"Unknown transport!")

        return transports.ObfuscatedTransport(transport, decrypt, encrypt)

    @classmethod
    def new(cls, buf: TxBuffer, transport_cls: type[BaseTransport], obf: bool) -> BaseTransport:
        if obf:
            if issubclass(transport_cls, transports.FullTransport):
                raise ValueError("Obfuscation of \"Full\" transport is nut supported")
            tmp_buf = TxBuffer()
            nonobf_transport = cls.new(tmp_buf, transport_cls, False)

            while True:
                nonce = bytearray(urandom(64))
                if (nonce[0] not in (0xef, 0xee, 0xdd)
                        and bytes(nonce[:4]) not in HTTP_HEADER
                        and nonce[4:8] != b"\x00" * 4):
                    nonce[56:60] = tmp_buf.data()[0:1] * 4
                    break

            temp = bytearray(nonce[55:7:-1])
            encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
            decrypt = (temp[0:32], temp[32:48], bytearray(1))
            nonce[56:64] = ctr256_encrypt(nonce, *encrypt)[56:64]

            buf.write(bytes(nonce))
            return transports.ObfuscatedTransport(nonobf_transport, encrypt, decrypt)

        if issubclass(transport_cls, transports.AbridgedTransport):
            buf.write(b"\xef")
            return transports.AbridgedTransport(ConnectionRole.CLIENT)
        elif issubclass(transport_cls, transports.PaddedIntermediateTransport):
            buf.write(b"\xdd" * 4)
            return transports.PaddedIntermediateTransport(ConnectionRole.CLIENT)
        elif issubclass(transport_cls, transports.IntermediateTransport):
            buf.write(b"\xee" * 4)
            return transports.IntermediateTransport(ConnectionRole.CLIENT)
        elif issubclass(transport_cls, transports.FullTransport):
            return transports.FullTransport(ConnectionRole.CLIENT)

        raise ValueError(f"Unknown transport class: {transport_cls}")

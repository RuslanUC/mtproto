from __future__ import annotations

from abc import ABC, abstractmethod
from os import urandom
from typing import overload, Literal

from mtproto.crypto.aes import ctr256_encrypt
from mtproto.enums import ConnectionRole
from mtproto.transport import transports
from mtproto.transport.buffer import RxBuffer, TxBuffer
from mtproto.transport.packets import BasePacket

HTTP_HEADER = {b"POST", b"GET ", b"HEAD", b"OPTI"}


class BaseTransport(ABC):
    SUPPORTS_OBFUSCATION: bool
    NAME: str

    __slots__ = ("our_role", "rx_buffer", "tx_buffer",)

    def __init__(self, role: ConnectionRole, rx_buffer: RxBuffer, tx_buffer: TxBuffer) -> None:
        self.our_role = role
        self.rx_buffer = rx_buffer
        self.tx_buffer = tx_buffer

    @property
    def is_obfuscated(self) -> bool:
        return self.rx_buffer.is_obfuscated and self.tx_buffer.is_obfuscated

    @abstractmethod
    def read(self) -> BasePacket | None: ...

    @abstractmethod
    def write(self, packet: BasePacket) -> None: ...

    @abstractmethod
    def has_packet(self) -> bool: ...

    @abstractmethod
    def peek(self) -> BasePacket | None: ...

    @abstractmethod
    def peek_length(self) -> int | None: ...

    @abstractmethod
    def ready_read(self) -> bool:
        ...

    @abstractmethod
    def ready_write(self) -> bool:
        ...

    @classmethod
    @overload
    def from_buffer(
            cls, rx_buf: RxBuffer, tx_buf: TxBuffer, _for_obfuscated: Literal[False] = False,
    ) -> BaseTransport | None:
        ...

    @classmethod
    @overload
    def from_buffer(
            cls, rx_buf: RxBuffer, tx_buf: TxBuffer, _for_obfuscated: Literal[True] = False,
    ) -> TcpTransport | None:
        ...

    @classmethod
    def from_buffer(cls, rx_buf: RxBuffer, tx_buf: TxBuffer, _for_obfuscated: bool = False) -> BaseTransport | None:
        ef_count = 4 if _for_obfuscated else 1
        if (header := rx_buf.peekexactly(ef_count)) is None:
            return None

        if header == b"\xef" * ef_count:
            rx_buf.readexactly(ef_count)
            return transports.AbridgedTransport(ConnectionRole.SERVER, rx_buf, tx_buf)

        if (header := rx_buf.peekexactly(4)) is None:
            return None

        if header == b"\xee" * 4:
            rx_buf.readexactly(4)
            return transports.IntermediateTransport(ConnectionRole.SERVER, rx_buf, tx_buf)
        elif header == b"\xdd" * 4:
            rx_buf.readexactly(4)
            return transports.PaddedIntermediateTransport(ConnectionRole.SERVER, rx_buf, tx_buf)
        elif header == b"POST":
            return transports.HttpTransport(ConnectionRole.SERVER, rx_buf, tx_buf)
        elif header == b"GET ":
            # GET requests cannot have body, so assuming that transport is ws
            return transports.WsTransport(ConnectionRole.SERVER, rx_buf, tx_buf)
        elif rx_buf.peekexactly(4, 4) == b"\x00" * 4:
            return transports.FullTransport(ConnectionRole.SERVER, rx_buf, tx_buf)
        elif len(rx_buf) < 64:
            return None

        nonce = rx_buf.peekexactly(64)
        temp = nonce[8:56][::-1]
        encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
        decrypt = (temp[0:32], temp[32:48], bytearray(1))

        rx_buf.deobfuscate(encrypt)
        tx_buf.obfuscate(decrypt)

        rx_buf.readexactly(56)

        if (transport := cls.from_buffer(rx_buf, tx_buf, True)) is None:
            raise ValueError(f"Unknown transport!")

        rx_buf.readexactly(4)

        return transport

    @classmethod
    def new(cls, tx_buf: TxBuffer, rx_buf: RxBuffer, transport_cls: type[BaseTransport], obf: bool) -> BaseTransport:
        if obf and not transport_cls.SUPPORTS_OBFUSCATION:
            raise ValueError(f"\"{transport_cls.__name__}\" transport does not support obfuscation")

        if issubclass(transport_cls, transports.AbridgedTransport):
            ef_count = 4 if obf else 1
            tx_buf.write(b"\xef" * ef_count)
            transport = transports.AbridgedTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        elif issubclass(transport_cls, transports.PaddedIntermediateTransport):
            tx_buf.write(b"\xdd" * 4)
            transport = transports.PaddedIntermediateTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        elif issubclass(transport_cls, transports.IntermediateTransport):
            tx_buf.write(b"\xee" * 4)
            transport = transports.IntermediateTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        elif issubclass(transport_cls, transports.FullTransport):
            transport = transports.FullTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        elif issubclass(transport_cls, transports.HttpTransport):
            transport = transports.HttpTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        elif issubclass(transport_cls, transports.WsTransport):
            transport = transports.WsTransport(ConnectionRole.CLIENT, rx_buf, tx_buf)
        else:
            raise ValueError(f"Unknown transport class: {transport_cls}")

        if obf:
            header = tx_buf.get_data()
            if len(header) != 4:
                raise ValueError(f"Expected obfuscated transport header to be 4 bytes, got {len(header)}")

            while True:
                nonce = bytearray(urandom(64))

                if nonce[0] in (0xef, 0xee, 0xdd) \
                        or bytes(nonce[:4]) in HTTP_HEADER \
                        or nonce[4:8] == b"\x00" * 4:
                    continue

                nonce[56:60] = header[0:1] * 4
                break

            temp = bytearray(nonce[55:7:-1])
            encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
            decrypt = (temp[0:32], temp[32:48], bytearray(1))
            nonce[56:64] = ctr256_encrypt(nonce, *encrypt)[56:64]

            tx_buf.write(nonce)

            rx_buf.deobfuscate(decrypt)
            tx_buf.obfuscate(encrypt)

        return transport


class TcpTransport(BaseTransport, ABC):
    ...

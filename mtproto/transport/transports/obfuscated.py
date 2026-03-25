from __future__ import annotations

from mtproto.crypto.aes import CtrTuple
from .base_transport import BaseTransport, TcpTransport
from ..buffer import TxBuffer, RxBuffer
from ..packets import BasePacket


class ObfuscatedTransport(BaseTransport):
    SUPPORTS_OBFUSCATION = False

    __slots__ = ("_transport", "_encrypt", "_decrypt",)

    def __init__(self, transport: TcpTransport, encrypt: CtrTuple, decrypt: CtrTuple) -> None:
        super().__init__(transport.our_role)

        self._transport = transport
        self._encrypt = encrypt
        self._decrypt = decrypt

    def set_buffers(self, rx_buffer: RxBuffer, tx_buffer: TxBuffer) -> tuple[RxBuffer, TxBuffer]:
        rx_buffer.deobfuscate(self._decrypt)
        tx_buffer.obfuscate(self._encrypt)

        return self._transport.set_buffers(rx_buffer, tx_buffer)

    def read(self) -> BasePacket | None:
        return self._transport.read()

    def write(self, packet: BasePacket) -> None:
        return self._transport.write(packet)

    def has_packet(self) -> bool:
        return self._transport.has_packet()

    def peek(self) -> BasePacket | None:
        return self._transport.peek()

    def peek_length(self) -> int | None:
        return self._transport.peek_length()

    def ready_read(self) -> bool:
        return True

    def ready_write(self) -> bool:
        return True

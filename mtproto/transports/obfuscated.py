from __future__ import annotations

from .base_transport import BaseTransport
from ..buffer import TxBuffer, RxBuffer, ObfuscatedRxBuffer, ObfuscatedTxBuffer
from ..crypto.aes import CtrTuple
from ..packets import BasePacket


class ObfuscatedTransport(BaseTransport):
    __slots__ = ("_transport", "_encrypt", "_decrypt",)

    def __init__(self, transport: BaseTransport, encrypt: CtrTuple, decrypt: CtrTuple) -> None:
        super().__init__(transport.our_role)

        self._transport = transport
        self._encrypt = encrypt
        self._decrypt = decrypt

    def set_buffers(self, rx_buffer: RxBuffer, tx_buffer: TxBuffer) -> tuple[RxBuffer, TxBuffer]:
        back_rx, back_tx = RxBuffer(), TxBuffer()
        obf_rx = ObfuscatedRxBuffer(back_rx, self._decrypt)
        obf_tx = ObfuscatedTxBuffer(back_tx, self._encrypt)
        obf_rx.data_received(rx_buffer.readall())

        self._transport.set_buffers(back_rx, back_tx)

        return obf_rx, obf_tx

    def read(self) -> BasePacket | None:
        return self._transport.read()

    def write(self, packet: BasePacket) -> None:
        return self._transport.write(packet)

    def has_packet(self) -> bool:
        return self._transport.has_packet()

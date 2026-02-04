from __future__ import annotations

import logging

from wsproto import ConnectionState
from wsproto.events import Request, BytesMessage, AcceptConnection

try:
    import h11
except ImportError:
    h11 = None

try:
    import wsproto
except ImportError:
    wsproto = None

from .base_transport import BaseTransport, BaseTransportParam, TcpTransport
from ..packets import BasePacket
from mtproto.transport import transports
from .. import RxBuffer, TxBuffer

_CORS_HEADERS = [
    (b"Access-Control-Allow-Origin", b"*"),
    (b"Access-Control-Allow-Methods", b"POST, OPTIONS"),
    (b"Access-Control-Allow-Headers", b"origin, content-type"),
    (b"Access-Control-Max-Age", b"1728000"),
]

log = logging.getLogger(__name__)


class WsClientTransport(BaseTransport):
    SUPPORTS_OBFUSCATION = False

    __slots__ = (
        "_conn", "_raw", "_raw_rx", "_raw_tx", "_init_tx", "_peeked_packet",
    )

    def __init__(self, *args, **kwargs) -> None:
        if h11 is None or wsproto is None:
            raise RuntimeError("h11 and wsproto are required for ws transport")

        super().__init__(*args, **kwargs)

        self._conn: wsproto.WSConnection | None = None
        self._raw: TcpTransport | None = None
        self._raw_rx = RxBuffer()
        self._raw_tx = TxBuffer()
        self._init_tx = TxBuffer()

        self._peeked_packet: BasePacket | None = None

    def _write_maybe(self) -> None:
        log.debug(f"Wsproto state is {self._conn.state}")
        if self._conn.state is not ConnectionState.OPEN:
            return

        if self._init_tx is not None and self._init_tx.size():
            self.tx_buffer.write(self._conn.send(BytesMessage(data=self._init_tx.get_data())))
            self._init_tx = None
            log.debug("Wrote transport init data")

        if self._raw_tx.size():
            data = self._raw_tx.get_data()
            self.tx_buffer.write(self._conn.send(BytesMessage(data=data)))
            log.debug(f"Wrote {len(data)} bytes")

    def read(self) -> BasePacket | None:
        if self._conn is None or self._raw is None:
            raise RuntimeError("Unreachable, probably")

        if self.rx_buffer.size():
            self._conn.receive_data(self.rx_buffer.readall())

        self._write_maybe()

        if self._peeked_packet is not None:
            to_return, self._peeked_packet = self._peeked_packet, None
            return to_return

        for event in self._conn.events():
            log.debug(f"Got wsproto event {event}")
            log.debug(f"Wsproto state is {self._conn.state}")
            if isinstance(event, BytesMessage):
                self._raw_rx.data_received(event.data)
                return self._raw.read()
            elif isinstance(event, AcceptConnection):
                self._write_maybe()

    def write(self, packet: BasePacket) -> None:
        if self._conn is None:
            self._conn = wsproto.WSConnection(wsproto.ConnectionType.CLIENT)
            to_write = self._conn.send(Request(host="127.0.0.1", target="/apis", subprotocols=["binary"]))
            self.tx_buffer.write(to_write)
            self._raw = BaseTransport.new(self._init_tx, transports.AbridgedTransport, True)
            self._raw_rx, self._raw_tx = self._raw.set_buffers(self._raw_rx, self._raw_tx)

        self._raw.write(packet)
        self._write_maybe()

    def has_packet(self) -> bool:
        if self._peeked_packet is not None:
            return True
        return self.peek() is not None

    def peek(self) -> BasePacket | None:
        if self._peeked_packet is not None:
            return self._peeked_packet
        self._peeked_packet = self.read()
        return self._peeked_packet

    def peek_length(self) -> int | None:
        return self._raw.peek_length()

    def set_param(self, param: BaseTransportParam) -> None:
        ...

    def ready_read(self) -> bool:
        return self._conn is not None

    def ready_write(self) -> bool:
        return True

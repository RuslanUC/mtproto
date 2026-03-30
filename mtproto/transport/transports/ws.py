from __future__ import annotations

import logging

try:
    import h11
except ImportError:
    h11 = None

try:
    import wsproto
    from wsproto.events import Request, BytesMessage, AcceptConnection, CloseConnection
except ImportError:
    wsproto = None
    Request = BytesMessage = AcceptConnection = CloseConnection = None

from .base_transport import BaseTransport, TcpTransport
from ..packets import BasePacket
from mtproto.transport import transports
from .. import RxBuffer, TxBuffer
from ... import ConnectionRole
from ...enums import TransportEvent

_CORS_HEADERS = [
    (b"Access-Control-Allow-Origin", b"*"),
    (b"Access-Control-Allow-Methods", b"POST, OPTIONS"),
    (b"Access-Control-Allow-Headers", b"origin, content-type"),
    (b"Access-Control-Max-Age", b"1728000"),
]

log = logging.getLogger(__name__)


class WsTransport(BaseTransport):
    SUPPORTS_OBFUSCATION = False
    NAME = "websocket"

    __slots__ = ("_conn", "_raw", "_raw_rx", "_raw_tx",)

    def __init__(
            self,
            role: ConnectionRole,
            rx_buffer: RxBuffer,
            tx_buffer: TxBuffer,
            max_packet_size: int = 1024 * 1024,
    ) -> None:
        if h11 is None or wsproto is None:
            raise RuntimeError("h11 and wsproto are required for ws transport")

        super().__init__(role, rx_buffer, tx_buffer, max_packet_size)

        self._conn: wsproto.WSConnection | None = None
        self._raw: TcpTransport | None = None
        self._raw_rx = RxBuffer()
        self._raw_tx = TxBuffer()

    def _write_maybe(self) -> None:
        log.debug(f"Wsproto state is {self._conn.state}")
        if self._conn.state is not wsproto.ConnectionState.OPEN:
            return

        if self._raw_tx:
            data = self._raw_tx.get_data()
            self.tx_buffer.write(self._conn.send(BytesMessage(data=data)))
            log.debug(f"Wrote {len(data)} bytes")

    def read(self) -> BasePacket | TransportEvent | None:
        if self._conn is None and self.our_role is ConnectionRole.CLIENT:
            raise RuntimeError("Unreachable, probably")
        elif self._conn is None and self.our_role is ConnectionRole.SERVER:
            self._conn = wsproto.WSConnection(wsproto.ConnectionType.SERVER)

        if self.rx_buffer:
            self._conn.receive_data(self.rx_buffer.readall())

        return super().read()

    def _read(self) -> BasePacket | TransportEvent | None:
        self._write_maybe()

        for event in self._conn.events():
            log.debug(f"Got wsproto event {event}")
            log.debug(f"Wsproto state is {self._conn.state}")
            if isinstance(event, BytesMessage):
                self._raw_rx.data_received(event.data)
            elif self.our_role is ConnectionRole.CLIENT and isinstance(event, AcceptConnection):
                self._write_maybe()
            elif self.our_role is ConnectionRole.SERVER and isinstance(event, Request):
                if "binary" not in event.subprotocols:
                    self._raw_tx.write(self._conn.send(CloseConnection(code=1000)))
                    return TransportEvent.DISCONNECT
                target = event.target.rpartition("/")[2]
                if target.endswith("_test"):
                    target = target[:-5]
                if not target.startswith("api"):
                    self._raw_tx.write(self._conn.send(CloseConnection(code=1000)))
                    return TransportEvent.DISCONNECT
                if "w" not in target[-2:]:
                    self._raw_tx.write(self._conn.send(CloseConnection(code=1000)))
                    return TransportEvent.DISCONNECT
                self._raw_tx.write(self._conn.send(AcceptConnection(subprotocol="binary")))
            else:
                log.warning(f"Got unknown event: {event!r}")

        if self.our_role is ConnectionRole.SERVER and self._raw is None:
            self._raw = BaseTransport.from_buffer(self._raw_rx, self._raw_tx)
            if self._raw is not None and not self._raw.is_obfuscated:
                self._raw_tx.write(self._conn.send(CloseConnection(code=1000)))
                return TransportEvent.DISCONNECT
        if self._raw is not None:
            return self._raw.read()

    def write(self, packet: BasePacket) -> None:
        if self._conn is None and self.our_role is ConnectionRole.CLIENT:
            self._conn = wsproto.WSConnection(wsproto.ConnectionType.CLIENT)
            to_write = self._conn.send(Request(host="127.0.0.1", target="/apiws", subprotocols=["binary"]))
            self.tx_buffer.write(to_write)
            self._raw = BaseTransport.new(self._raw_tx, self._raw_rx, transports.AbridgedTransport, True)
        elif self._conn is None and self.our_role is ConnectionRole.SERVER:
            raise RuntimeError

        self._raw.write(packet)
        self._write_maybe()

    def _has_packet(self) -> bool:
        return self.peek() is not None

    def ready_read(self) -> bool:
        return self._conn is not None

    def ready_write(self) -> bool:
        return True

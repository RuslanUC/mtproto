from __future__ import annotations

import logging

from .. import RxBuffer, TxBuffer

try:
    import h11
except ImportError:
    h11 = None

from mtproto.enums import ConnectionRole, TransportEvent, TransportType
from .base_transport import BaseTransport
from ..packets import BasePacket, ErrorPacket, MessagePacket

_CORS_HEADERS = [
    (b"Access-Control-Allow-Origin", b"*"),
    (b"Access-Control-Allow-Methods", b"POST, OPTIONS"),
    (b"Access-Control-Allow-Headers", b"origin, content-type"),
    (b"Access-Control-Max-Age", b"1728000"),
]

log = logging.getLogger(__name__)


class HttpTransport(BaseTransport):
    SUPPORTS_OBFUSCATION = False
    TYPE = TransportType.HTTP

    __slots__ = (
        "_conn", "_need_cors_headers", "_length", "_host", "_keep_alive", "_cors_headers",
        "_skip_data",
    )

    def __init__(
            self,
            role: ConnectionRole,
            rx_buffer: RxBuffer,
            tx_buffer: TxBuffer,
            max_packet_size: int = 1024 * 1024,
    ) -> None:
        if h11 is None:
            raise RuntimeError("h11 is required for http transport")

        super().__init__(role, rx_buffer, tx_buffer, max_packet_size)

        self._conn: h11.Connection | None = None
        self._need_cors_headers = False
        self._length: int | None = None
        self._skip_data = False

        self._host = "127.0.0.1"
        self._keep_alive = True
        self._cors_headers = False

    def _read(self) -> BasePacket | TransportEvent | None:
        if self._conn is None:
            self._conn = h11.Connection(our_role=h11.SERVER if self.our_role is ConnectionRole.SERVER else h11.CLIENT)

        if len(self.rx_buffer):
            self._conn.receive_data(self.rx_buffer.readall())

        while True:
            event = self._conn.next_event()
            log.debug(f"Got h11 event {event if event in (h11.NEED_DATA, h11.PAUSED) else type(event)}")
            log.debug(f"Our h11 state is {self._conn.our_state}, theirs is {self._conn.their_state}")
            if isinstance(event, h11.Data):
                next_event = self._conn.next_event()
                if not isinstance(next_event, h11.EndOfMessage):
                    raise RuntimeError(f"Expected EndOfMessage, got {next_event!r}")
                if self.our_role is ConnectionRole.CLIENT:
                    log.debug("New h11 cycle")
                    self._conn.start_next_cycle()
                self._length = None
                if self._skip_data:
                    return None
                return MessagePacket.parse(event.data)
            elif isinstance(event, h11.Request):
                self._need_cors_headers = b"w" in event.target.rpartition(b"/")[-1]
                for header in event.headers:
                    if header[0] == b"content-length":
                        try:
                            self._length = int(header[1])
                        except ValueError:
                            log.debug("Invalid \"Content-Length\" header")
                            return TransportEvent.DISCONNECT
                        else:
                            if self._length > self.max_packet_size:
                                log.debug("Invalid packet length")
                                return TransportEvent.DISCONNECT
                        break
                else:
                    log.debug("\"Content-Length\" header is missing")
                    return TransportEvent.DISCONNECT
                continue
            elif isinstance(event, h11.Response):
                if event.status_code >= 400:
                    self._skip_data = True
                    return ErrorPacket(event.status_code)
                continue
            break

    def write(self, packet: BasePacket) -> None:
        if self._conn is None:
            self._conn = h11.Connection(our_role=h11.SERVER if self.our_role is ConnectionRole.SERVER else h11.CLIENT)

        data = packet.write()

        if self.our_role is ConnectionRole.SERVER:
            is_err = isinstance(packet, ErrorPacket)
            status_code = packet.error_code if isinstance(packet, ErrorPacket) else 200
            headers = [
                (b"connection", b"keep-alive" if self._keep_alive else b"close"),
                (b"content-type", b"application/octet-stream"),
                (b"pragma", b"no-cache"),
                (b"cache-control", b"no-store"),
                (b"Content-Length", str(len(data)).encode("latin1") if not is_err else b"0"),
            ]

            if self._need_cors_headers:
                headers.extend(_CORS_HEADERS)

            if to_write := self._conn.send(h11.Response(status_code=status_code, headers=headers)):
                self.tx_buffer.write(to_write)
            if to_write := self._conn.send(h11.Data(data=data if not is_err else b"")):
                self.tx_buffer.write(to_write)
            if to_write := self._conn.send(h11.EndOfMessage()):
                self.tx_buffer.write(to_write)

            log.debug("New h11 cycle")
            self._conn.start_next_cycle()
        else:
            headers = [
                (b"host", self._host),
                (b"connection", b"keep-alive" if self._keep_alive else b"close"),
                (b"content-type", b"application/octet-stream"),
                (b"Content-Length", str(len(data)).encode("latin1")),
            ]

            target = b"/api"
            if self._cors_headers:
                target += b"w"

            if to_write := self._conn.send(h11.Request(method=b"POST", headers=headers, target=target)):
                self.tx_buffer.write(to_write)
            if to_write := self._conn.send(h11.Data(data=data)):
                self.tx_buffer.write(to_write)
            if to_write := self._conn.send(h11.EndOfMessage()):
                self.tx_buffer.write(to_write)

    def _has_packet(self) -> bool:
        return self.peek() is not None

    def set_host(self, value: str) -> None:
        self._host = value

    def set_keepalive(self, value: bool) -> None:
        self._keep_alive = value

    def set_require_cors(self, value: bool) -> None:
        self._cors_headers = value

    def ready_read(self) -> bool:
        if self._conn is None:
            return self.our_role is ConnectionRole.SERVER
        if self.our_role is ConnectionRole.SERVER:
            return self._conn.our_state is h11.IDLE \
                or (self._conn.our_state is h11.SEND_RESPONSE and self._conn.their_state is h11.SEND_BODY)
        else:
            return self._conn.our_state is h11.DONE and self._conn.their_state is h11.SEND_RESPONSE

    def ready_write(self) -> bool:
        if self._conn is None:
            return self.our_role is ConnectionRole.CLIENT
        log.debug(f"Our h11 state as of ready_write call is {self._conn.our_state}, theirs is {self._conn.their_state}")
        if self.our_role is ConnectionRole.CLIENT:
            return self._conn.our_state is h11.IDLE \
                or (self._conn.our_state is h11.SEND_BODY and self._conn.their_state is h11.SEND_RESPONSE)
        else:
            return self._conn.our_state is h11.SEND_RESPONSE and self._conn.their_state is h11.DONE

from __future__ import annotations

try:
    import h11
except ImportError:
    h11 = None

from mtproto.enums import ConnectionRole
from .base_transport import BaseTransport, BaseTransportParam
from ..packets import BasePacket, QuickAckPacket, ErrorPacket, MessagePacket

_CORS_HEADERS = [
    (b"Access-Control-Allow-Origin", b"*"),
    (b"Access-Control-Allow-Methods", b"POST, OPTIONS"),
    (b"Access-Control-Allow-Headers", b"origin, content-type"),
    (b"Access-Control-Max-Age", b"1728000"),
]


class HttpTransportParam(BaseTransportParam):
    __slots__ = ()


class HttpTransportParamHost(HttpTransportParam):
    __slots__ = ("host",)

    def __init__(self, host: str) -> None:
        self.host = host


class HttpTransportParamKeepalive(HttpTransportParam):
    __slots__ = ("enable",)

    def __init__(self, enable: str) -> None:
        self.enable = enable


class HttpTransportParamCorsHeaders(HttpTransportParam):
    __slots__ = ("enable",)

    def __init__(self, enable: str) -> None:
        self.enable = enable


class HttpTransport(BaseTransport):
    SUPPORTS_OBFUSCATION = False

    __slots__ = (
        "_conn", "_need_cors_headers", "_length", "_peeked_packet", "_host", "_keep_alive", "_cors_headers",
        "_skip_data",
    )

    def __init__(self, *args, **kwargs) -> None:
        if h11 is None:
            raise RuntimeError("h11 is required for http transport")

        super().__init__(*args, **kwargs)

        self._conn: h11.Connection | None = None
        self._need_cors_headers = False
        self._length: int | None = None
        self._peeked_packet: BasePacket | None = None
        self._skip_data = False

        self._host = "127.0.0.1"
        self._keep_alive = True
        self._cors_headers = False

    def read(self) -> BasePacket | None:
        if self._conn is None:
            self._conn = h11.Connection(our_role=h11.SERVER if self.our_role is ConnectionRole.SERVER else h11.CLIENT)

        self._conn.receive_data(self.rx_buffer.readall())

        if self._peeked_packet is not None:
            to_return, self._peeked_packet = self._peeked_packet, None
            return to_return

        while True:
            event = self._conn.next_event()
            if isinstance(event, h11.Data):
                next_event = self._conn.next_event()
                if not isinstance(next_event, h11.EndOfMessage):
                    raise RuntimeError(f"Expected EndOfMessage, got {next_event!r}")
                self._length = None
                if self._skip_data:
                    return None
                return MessagePacket.parse(event.data)
            elif isinstance(event, h11.Request):
                self._need_cors_headers = b"w" in event.target.rpartition(b"/")[-1]
                for header in event.headers:
                    if header[0] == "content-length":
                        try:
                            self._length = int(header[1])
                        except ValueError:
                            # TODO: throw custom exception
                            raise RuntimeError(f"Invalid \"Content-Length\" header: {header[1]!r}\"")
                        break
                else:
                    # TODO: throw custom exception
                    raise RuntimeError(f"No \"Content-Length\" in request\"")
                continue
            elif isinstance(event, h11.Response):
                if event.status_code >= 400:
                    self._skip_data = True
                    return ErrorPacket(event.status_code)
                continue
            break

    def write(self, packet: BasePacket) -> None:
        if isinstance(packet, QuickAckPacket):
            raise ValueError("\"Http\" transport does not support quick-acks.")
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
        return self._length

    def set_param(self, param: BaseTransportParam) -> None:
        if not isinstance(param, HttpTransportParam):
            return

        if isinstance(param, HttpTransportParamHost):
            self._host = param.host
        elif isinstance(param, HttpTransportParamKeepalive):
            self._keep_alive = param.enable
        elif isinstance(param, HttpTransportParamCorsHeaders):
            self._cors_headers = param.enable

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
        if self.our_role is ConnectionRole.CLIENT:
            return self._conn.our_state is h11.IDLE \
                or (self._conn.our_state is h11.SEND_BODY and self._conn.their_state is h11.SEND_RESPONSE)
        else:
            return self._conn.our_state is h11.SEND_RESPONSE and self._conn.their_state is h11.DONE

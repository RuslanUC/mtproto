from __future__ import annotations

from typing import Generic, TypeVar

from .buffer import RxBuffer, TxBuffer
from .packets import BasePacket
from .transports import AbridgedTransport, HttpTransport
from .transports.base_transport import BaseTransport
from ..enums import ConnectionRole


TransportT = TypeVar("TransportT", bound=BaseTransport)


class Connection(Generic[TransportT]):
    __slots__ = (
        "_role", "_rx_buffer", "_tx_buffer", "_transport", "_transport_cls", "_obfuscated",
        "_transport_param_http_keepalive",
    )

    def __init__(
            self,
            role: ConnectionRole = ConnectionRole.CLIENT,
            transport: type[TransportT] = AbridgedTransport,
            obfuscated: bool = False,
    ):
        self._role = role
        self._rx_buffer = RxBuffer()
        self._tx_buffer = TxBuffer()
        self._transport: TransportT | None = None
        self._transport_cls = transport
        self._obfuscated = obfuscated
        self._transport_param_http_keepalive: bool | None = None

    def data_received(self, data: bytes | None) -> None:
        if data:
            self._rx_buffer.data_received(data)

    def _create_transport_if_does_not_exist(self, fail_on_client: bool) -> None:
        if self._transport is not None:
            return
        if self._role is not ConnectionRole.SERVER:
            if not fail_on_client:
                return
            raise ValueError(
                "Transport should exist when next_event() method is called and role is ConnectionRole.CLIENT"
            )

        self._transport = BaseTransport.from_buffer(self._rx_buffer, self._tx_buffer)
        if self._transport is None:
            return None
        if isinstance(self._transport, HttpTransport) and self._transport_param_http_keepalive is not None:
            self._transport.set_keepalive(self._transport_param_http_keepalive)

    def next_event(self) -> BasePacket | None:
        self._create_transport_if_does_not_exist(True)
        if self._transport is None:
            return None
        return self._transport.read()

    def _client_make_transport_maybe(self) -> None:
        if self._transport is None and self._role is ConnectionRole.CLIENT:
            self._transport = BaseTransport.new(self._tx_buffer, self._rx_buffer, self._transport_cls, self._obfuscated)

    def send(self, packet: BasePacket | None) -> bytes:
        if self._transport is None and self._role is ConnectionRole.CLIENT:
            self._client_make_transport_maybe()
        elif self._transport is None:
            raise ValueError("Transport should exist when send() method is called and role is ConnectionRole.SERVER")

        if packet is not None:
            self._transport.write(packet)

        return self._tx_buffer.get_data() if self._tx_buffer else b""

    def has_packet(self) -> bool:
        self._create_transport_if_does_not_exist(False)
        return self._transport is not None and self._transport.has_packet()

    def peek_packet(self) -> BasePacket | None:
        self._create_transport_if_does_not_exist(True)
        return self._transport.peek() if self._transport is not None else None

    def opposite(self, require_transport: bool = True) -> Connection | None:
        if self._transport_cls is None:
            if require_transport:
                raise ValueError("transport_cls is required!")
            return None

        return Connection(
            role=ConnectionRole.CLIENT if self._role is ConnectionRole.SERVER else ConnectionRole.SERVER,
            transport=self._transport_cls,
            obfuscated=self._obfuscated,
        )

    def transport_recv_ready(self) -> bool:
        if self._transport is None:
            return self._role is ConnectionRole.SERVER
        return self._transport.ready_read()

    def transport_send_ready(self) -> bool:
        if self._transport is None:
            return self._role is ConnectionRole.CLIENT
        return self._transport.ready_write()

    def _check_role_and_transport_for_param(
            self, required_role: ConnectionRole | None, required_transport: type[BaseTransport], param_name: str
    ) -> None:
        if required_role is not None and self._role is not required_role:
            raise ValueError(
                f"Cannot set {required_transport.NAME} transport \"{param_name}\" "
                f"parameter on SERVER connection.")
        if not issubclass(self._transport_cls, required_transport):
            raise ValueError(
                f"Cannot set {required_transport.NAME} \"{param_name}\" "
                f"parameter on {self._transport_cls.NAME} transport."
            )

    def client_http_set_host(self: Connection[HttpTransport], value: str) -> None:
        self._check_role_and_transport_for_param(ConnectionRole.CLIENT, HttpTransport, "host")
        self._client_make_transport_maybe()
        self._transport.set_host(value)

    def client_http_set_keepalive(self: Connection[HttpTransport], value: bool) -> None:
        self._check_role_and_transport_for_param(None, HttpTransport, "keepalive")
        self._client_make_transport_maybe()
        if self._transport is None:
            self._transport_param_http_keepalive = value
        else:
            self._transport.set_keepalive(value)

    def client_http_set_require_cors(self: Connection[HttpTransport], value: bool) -> None:
        self._check_role_and_transport_for_param(ConnectionRole.CLIENT, HttpTransport, "require_cors")
        self._client_make_transport_maybe()
        self._transport.set_require_cors(value)


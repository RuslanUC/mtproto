from __future__ import annotations

from .buffer import RxBuffer, TxBuffer
from .packets import BasePacket
from .transports import AbridgedTransport
from .transports.base_transport import BaseTransport, BaseTransportParam
from ..enums import ConnectionRole


class Connection:
    __slots__ = (
        "_role", "_rx_buffer", "_tx_buffer", "_transport", "_transport_cls", "_transport_obf", "_transport_params"
    )

    def __init__(
            self,
            role: ConnectionRole = ConnectionRole.CLIENT,
            transport: type[BaseTransport] = AbridgedTransport,
            obfuscated: bool = False,
    ):
        self._role = role
        self._rx_buffer = RxBuffer()
        self._tx_buffer = TxBuffer()
        self._transport: BaseTransport | None = None
        self._transport_cls = transport
        self._transport_obf = obfuscated
        self._transport_params = None

    def data_received(self, data: bytes | None) -> None:
        if data:
            self._rx_buffer.data_received(data)

    def receive(self, data: bytes = b"") -> BasePacket | None:
        self.data_received(data)

        was_none = self._transport is None
        if self._transport is None and self._role is ConnectionRole.SERVER:
            self._transport = BaseTransport.from_buffer(self._rx_buffer)
            if self._transport is None:
                return None
            self._rx_buffer, self._tx_buffer = self._transport.set_buffers(self._rx_buffer, self._tx_buffer)
        elif self._transport is None:
            raise ValueError("Transport should exist when receive() method is called and role is ConnectionRole.CLIENT")

        if was_none and self._transport_params:
            for param in self._transport_params:
                self._transport.set_param(param)
            self._transport_params = None

        return self._transport.read()

    def send(self, packet: BasePacket | None) -> bytes:
        initial_data = b""

        was_none = self._transport is None
        if self._transport is None and self._role is ConnectionRole.CLIENT:
            init_buf = TxBuffer()
            self._transport = BaseTransport.new(init_buf, self._transport_cls, self._transport_obf)
            initial_data = init_buf.get_data()
            self._rx_buffer, self._tx_buffer = self._transport.set_buffers(self._rx_buffer, self._tx_buffer)
        elif self._transport is None:
            raise ValueError("Transport should exist when send() method is called and role is ConnectionRole.SERVER")

        if was_none and self._transport_params:
            for param in self._transport_params:
                self._transport.set_param(param)
            self._transport_params = None

        if packet is not None:
            self._transport.write(packet)
        return initial_data + self._tx_buffer.get_data()

    def has_packet(self) -> bool:
        return self._transport is not None and self._transport.has_packet()

    def peek_packet(self) -> BasePacket | None:
        return self._transport.peek() if self._transport is not None else None

    def peek_length(self) -> int | None:
        return self._transport.peek_length() if self._transport is not None else None

    def opposite(self, require_transport: bool = True) -> Connection | None:
        if self._transport_cls is None:
            if require_transport:
                raise ValueError("transport_cls is required!")
            return None

        return Connection(
            role=ConnectionRole.CLIENT if self._role is ConnectionRole.SERVER else ConnectionRole.SERVER,
            transport=self._transport_cls,
            obfuscated=self._transport_obf,
        )

    def set_transport_param(self, param: BaseTransportParam) -> None:
        if self._transport is not None:
            self._transport.set_param(param)
            return
        if self._transport_params is None:
            self._transport_params = []
        self._transport_params.append(param)

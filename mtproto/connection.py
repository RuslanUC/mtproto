from __future__ import annotations

from . import ConnectionRole, Buffer
from .packets import BasePacket
from .transports import AbridgedTransport
from .transports.base_transport import BaseTransport


class Connection:
    __slots__ = ("_role", "_buffer", "_transport", "_transport_cls", "_transport_obf")

    def __init__(
            self,
            role: ConnectionRole = ConnectionRole.CLIENT,
            transport_cls: type[BaseTransport] = AbridgedTransport,
            transport_obf: bool = False,
    ):
        self._role = role
        self._buffer = Buffer()
        self._transport: BaseTransport | None = None
        self._transport_cls = transport_cls
        self._transport_obf = transport_obf

    def receive(self, data: bytes = b"") -> BasePacket | None:
        self._buffer.raw_write(data)
        if self._transport is None and self._role == ConnectionRole.SERVER:
            self._transport = BaseTransport.from_buffer(self._buffer)
            if self._transport is None:
                return
            self._buffer = self._transport.set_buffer(self._buffer)
        elif self._transport is None:
            raise ValueError("Transport should exist when receive() method is called and role is ConnectionRole.CLIENT")

        return self._transport.read()

    def send(self, packet: BasePacket) -> bytes:
        initial_data = b""
        if self._transport is None and self._role == ConnectionRole.CLIENT:
            init_buf = Buffer()
            self._transport = BaseTransport.new(init_buf, self._transport_cls, self._transport_obf)
            initial_data = init_buf.readall()
            self._buffer = self._transport.set_buffer(self._buffer)
        elif self._transport is None:
            raise ValueError("Transport should exist when send() method is called and role is ConnectionRole.SERVER")

        self._transport.write(packet)
        return initial_data + self._buffer.raw_readall()

    def has_packet(self) -> bool:
        return self._transport is not None and self._transport.has_packet()



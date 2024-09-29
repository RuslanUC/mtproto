from __future__ import annotations

from . import ConnectionRole, Buffer
from .packets import BasePacket
from .transports import AbridgedTransport
from .transports.base_transport import BaseTransport


class Connection:
    __slots__ = ("_role", "_buffer", "_transport", "_transport_cls", "_read_values")

    def __init__(
            self, role: ConnectionRole = ConnectionRole.CLIENT, transport_cls: type[BaseTransport] = AbridgedTransport
    ):
        self._role = role
        self._buffer = Buffer()
        self._transport: BaseTransport | None = None
        self._transport_cls: transport_cls
        self._read_values: tuple[bool, int] | None = None

    def receive(self, data: bytes) -> BasePacket | None:
        self._buffer.write(data)
        if self._transport is None:
            self._transport = BaseTransport.new(self._buffer, self._role)
            if self._transport is None:
                return

        return self._transport.read(self._buffer)

    def send(self, packet: BasePacket) -> bytes:
        ...  # TODO: create transport for sending data



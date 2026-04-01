from __future__ import annotations

from enum import Enum, auto, StrEnum


class ConnectionRole(Enum):
    SERVER = auto()
    CLIENT = auto()

    @classmethod
    def opposite(cls, role: ConnectionRole) -> ConnectionRole:
        return cls.SERVER if role is cls.CLIENT else cls.CLIENT


class TransportEvent(Enum):
    DISCONNECT = auto()


class TransportType(StrEnum):
    ABRIDGED = "abridged"
    INTERMEDIATE = "intermediate"
    PADDED_INTERMEDIATE = "padded-intermediate"
    FULL = "full"
    HTTP = "http"
    WEBSOCKET = "websocket"

from __future__ import annotations

from enum import Enum, auto


class ConnectionRole(Enum):
    SERVER = auto()
    CLIENT = auto()

    @classmethod
    def opposite(cls, role: ConnectionRole) -> ConnectionRole:
        return cls.SERVER if role is cls.CLIENT else cls.CLIENT

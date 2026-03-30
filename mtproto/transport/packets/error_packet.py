from typing import Any

from mtproto.utils import AutoRepr
from .base_packet import BasePacket


class ErrorPacket(BasePacket, AutoRepr):
    __slots__ = ("error_code",)

    def __init__(self, error_code: int):
        self.error_code = abs(error_code)

    def write(self) -> bytes:
        return (-self.error_code).to_bytes(4, "little", signed=True)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return self.error_code == other.error_code

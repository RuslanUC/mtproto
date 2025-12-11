from mtproto.utils import AutoRepr
from .base_packet import BasePacket


class QuickAckPacket(BasePacket, AutoRepr):
    __slots__ = ("token",)

    def __init__(self, token: bytes):
        self.token = token

    def write(self) -> bytes:
        return self.token

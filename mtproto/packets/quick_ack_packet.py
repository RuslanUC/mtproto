from mtproto.packets import BasePacket
from mtproto.utils import AutoRepr


class QuickAckPacket(BasePacket, AutoRepr):
    __slots__ = ("token",)

    def __init__(self, token: bytes):
        self.token = token

    def write(self) -> bytes:
        return self.token

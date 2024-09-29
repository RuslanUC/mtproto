from mtproto.packets import BasePacket


class QuickAckPacket(BasePacket):
    __slots__ = ("token",)

    def __init__(self, token: bytes):
        self.token = token

    def write(self) -> bytes:
        return self.token

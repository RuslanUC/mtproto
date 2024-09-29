from mtproto.packets import BasePacket


class ErrorPacket(BasePacket):
    __slots__ = ("error_code",)

    def __init__(self, error_code: int):
        self.error_code = abs(error_code)

    def write(self) -> bytes:
        return (-self.error_code).to_bytes(4, "little", signed=True)

from io import BytesIO


class Int(int):
    BIT_SIZE = 32
    SIZE = BIT_SIZE // 8

    @classmethod
    def read_bytes(cls, data: bytes, signed: bool = True) -> int:
        return int.from_bytes(data, "little", signed=signed)

    @classmethod
    def read(cls, stream: BytesIO, signed: bool = True) -> int:
        return cls.read_bytes(stream.read(cls.SIZE), signed)

    @classmethod
    def write(cls, value: int, signed: bool = True) -> bytes:
        return value.to_bytes(cls.SIZE, "little", signed=signed)


class Long(Int):
    BIT_SIZE = 64
    SIZE = BIT_SIZE // 8
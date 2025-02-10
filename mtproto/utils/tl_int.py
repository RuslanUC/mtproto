from io import BytesIO


class Int(int):
    BIT_SIZE = 32
    SIZE = BIT_SIZE // 8

    @classmethod
    def read_bytes(cls, data: bytes) -> int:
        return int.from_bytes(data, "little", signed=True)

    @classmethod
    def read(cls, stream: BytesIO) -> int:
        return cls.read_bytes(stream.read(cls.SIZE))

    @classmethod
    def write(cls, value: int) -> bytes:
        return value.to_bytes(cls.SIZE, "little", signed=True)


class Long(Int):
    BIT_SIZE = 64
    SIZE = BIT_SIZE // 8
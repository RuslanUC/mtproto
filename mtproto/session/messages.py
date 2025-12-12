class BaseMessage:
    __slots__ = ()


class ErrorMessage(BaseMessage):
    __slots__ = ("code",)

    def __init__(self, code: int) -> None:
        self.code = code


class UnencryptedMessage(BaseMessage):
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data


class DataMessage(BaseMessage):
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data


class DataMessages(BaseMessage):
    __slots__ = ("messages",)

    def __init__(self, messages: list[DataMessage]) -> None:
        self.messages = messages


class FailMessage(BaseMessage):
    __slots__ = ()


class NeedAuthkey(BaseMessage):
    __slots__ = ("auth_key_id",)

    def __init__(self, auth_key_id: int) -> None:
        self.auth_key_id = auth_key_id

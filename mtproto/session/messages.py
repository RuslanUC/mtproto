from typing import MutableSequence


class BaseEvent:
    __slots__ = ()


class TransportError(BaseEvent):
    __slots__ = ("code",)

    def __init__(self, code: int) -> None:
        self.code = code


class UnencryptedData(BaseEvent):
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data


class Data(BaseEvent):
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data


class NeedAuthkey(BaseEvent):
    __slots__ = ("auth_key_id",)

    def __init__(self, auth_key_id: int) -> None:
        self.auth_key_id = auth_key_id


class NewSession(BaseEvent):
    __slots__ = ("new_session_id", "old_session_id",)

    def __init__(self, new_session_id: int, old_session_id: int | None) -> None:
        self.new_session_id = new_session_id
        self.old_session_id = old_session_id


class MessagesAck(BaseEvent):
    __slots__ = ("message_ids",)

    def __init__(self, message_ids: MutableSequence[int]) -> None:
        self.message_ids = message_ids

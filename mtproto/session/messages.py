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
    __slots__ = ("message_id", "session_id", "data",)

    def __init__(self, message_id: int, session_id: int, data: bytes) -> None:
        self.message_id = message_id
        self.session_id = session_id
        self.data = data


class NeedAuthkey(BaseEvent):
    __slots__ = ("auth_key_id",)

    def __init__(self, auth_key_id: int) -> None:
        self.auth_key_id = auth_key_id


class NewSession(BaseEvent):
    __slots__ = ("new_session_id", "old_session_id", "first_message_id",)

    def __init__(self, new_session_id: int, old_session_id: int | None, first_message_id: int | None) -> None:
        self.new_session_id = new_session_id
        self.old_session_id = old_session_id
        self.first_message_id = first_message_id


class MessagesAck(BaseEvent):
    __slots__ = ("message_ids",)

    def __init__(self, message_ids: MutableSequence[int]) -> None:
        self.message_ids = message_ids


class UpdateMessageId(BaseEvent):
    __slots__ = ("old_message_id", "new_message_id",)

    def __init__(self, old_message_id: int, new_message_id: int) -> None:
        self.old_message_id = old_message_id
        self.new_message_id = new_message_id


class BadMessageId(BaseEvent):
    __slots__ = ()


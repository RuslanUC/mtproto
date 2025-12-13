from time import time

from mtproto import ConnectionRole


class MsgId:
    __slots__ = ("_role", "_time", "_offset",)

    def __init__(self, role: ConnectionRole) -> None:
        self._role = role
        self._time = 0
        self._offset = 0

    def make(self, in_reply: bool = False) -> int:
        now = int(time())
        if now != self._time:
            self._time = now
            self._offset = 0
        else:
            self._offset += 1

        msg_id = now * 2 ** 32 + self._offset * 4

        if self._role is ConnectionRole.SERVER:
            msg_id += 1 if in_reply else 3

        return msg_id
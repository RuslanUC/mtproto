class SeqNo:
    __slots__ = ("_seq",)

    def __init__(self) -> None:
        self._seq = 0

    def make(self, content_related: bool) -> int:
        result = self._seq * 2
        if content_related:
            self._seq += 1
            result += 1

        return result
from abc import ABC, abstractmethod


class BasePacket(ABC):
    @abstractmethod
    def write(self) -> bytes: ...

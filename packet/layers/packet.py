from abc import ABC, abstractmethod

class Packet(ABC):
    name = -1

    @abstractmethod
    def summary(self, offset=0) -> str:
        ...


from abc import ABC, abstractmethod
from packet.layers.layer_type import LayerID

class Packet(ABC):
    name: LayerID = LayerID.UNDEFINED

    @abstractmethod
    def summary(self, offset: int) -> str:
        ...

    @abstractmethod
    def get_field(self, fieldname: str) -> int | str | None:
        ...

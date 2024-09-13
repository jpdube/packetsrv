from abc import ABC, abstractmethod

from packet.layers.layer_type import LayerID


class Packet(ABC):
    name: LayerID = LayerID.UNDEFINED

    @abstractmethod
    def summary(self, offset: int) -> str:
        pass

    @abstractmethod
    def get_field(self, fieldname: str) -> None | int:
        return None

    @abstractmethod
    def export(self) -> dict[str, str | int]:
        return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.packet) and (offset + length) < len(self.packet): 
            return self.packet[offset: offset + length]
        else:
            return None

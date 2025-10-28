
from enum import Enum
from struct import unpack

from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet


class Smb(Packet):
    name = LayerID.SMB

    __slots__ = ["packet"]

    def __init__(self, packet) -> None:
        self.packet = packet

    @property
    def payload(self) -> bytes:
        return self.packet[5:]

    def summary(self, offset: int) -> str:
        result = f"{' ' * offset}SMB -> \n"

        return result

    def export(self) -> dict[str, int | str]:
        return {
        }

    def get_field(self, fieldname: str) -> None | int | str:
        field = fieldname.split('.')[1]
        # match field:
        #     case 'content_type':
        #         return self.content_type
        #     case 'tls_version':
        #         return self.tls_version
        #     case 'tls_version_str':
        #         return self.tls_version_str
        #     case 'length':
        #         return self.length
        #     case 'payload':
        #         return str(self.payload)
        #     case _:
        #         return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

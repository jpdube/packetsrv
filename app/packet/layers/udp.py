from struct import unpack
from packet.layers.packet import Packet
from packet.layers.layer_type import LayerID
from typing import Dict


class UDP(Packet):
    name = LayerID.UDP
    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def src_port(self) -> int:
        return unpack("!H", self.packet[0:2])[0]

    @property
    def dst_port(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def length(self) -> int:
        return unpack("!H", self.packet[4:6])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[6:8])[0]

    @property
    def payload(self) -> bytes:
        return self.packet[8:]

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}UDP ->\n'
        result += f'{" " * offset}   Src port...: {self.src_port}\n'
        result += f'{" " * offset}   Dst port...: {self.dst_port}\n'
        result += f'{" " * offset}   Lenght.....: {self.length}\n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'

        return result

    def export(self) -> dict[str, int | str]:
        return {
            "udp.sport": self.src_port,
            "udp.dport": self.dst_port,
            "udp.len": self.length,
            "udp.checksum": self.checksum,
        }

    def __str__(self) -> str:
        return f"UDP -> Src port: {self.src_port}, Dst Port: {self.dst_port}, Length: {self.length}, Checksum: {self.checksum}"

    def get_field(self, fieldname: str):
        field = fieldname.split('.')[1]
        if field:
            if field == 'length':
                return self.length
            elif field == 'checksum':
                return self.checksum
            elif field == 'sport':
                return self.src_port
            elif field == 'dport':
                return self.dst_port
            else:
                return 0
        else:
            return 0

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

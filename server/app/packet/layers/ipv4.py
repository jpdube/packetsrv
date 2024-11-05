from struct import unpack

from packet.layers.fields import IPv4Address
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet

IHL_SHORT = 5
IHL_LONG = 6

IP_PROTO_TCP = 0x06
IP_PROTO_UDP = 0x11
IP_PROTO_ICMP = 0x01

"""
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


class IPV4(Packet):
    name = LayerID.IPV4

    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def version(self) -> int:
        return self.packet[0] >> 4

    @property
    def ihl(self) -> int:
        return self.packet[0] & 0x0F

    @property
    def tos(self) -> int:
        return unpack("!B", self.packet[1:2])[0]

    @property
    def total_len(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def identification(self) -> int:
        return unpack("!H", self.packet[4:6])[0]

    @property
    def flags(self) -> int:
        return (unpack("!H", self.packet[6:8])[0] & 0xE000) >> 13

    @property
    def frag_offset(self) -> int:
        return unpack("!H", self.packet[6:8])[0] & 0x1FF

    @property
    def ttl(self) -> int:
        return unpack("!B", self.packet[8:9])[0]

    @property
    def protocol(self) -> int:
        return unpack("!B", self.packet[9:10])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[10:12])[0]

    @property
    def src_ip(self) -> IPv4Address:
        return IPv4Address(self.packet[12:16])

    @property
    def dst_ip(self) -> IPv4Address:
        return IPv4Address(self.packet[16:20])

    @property
    def options(self) -> bytes:
        if self.ihl == 6:
            return unpack("!I", self.packet[20:25])[0]
        else:
            return bytes()

    @property
    def payload(self) -> bytes:
        offset = 0
        if self.ihl == 6:
            offset = 4
        return self.packet[20 + offset:]

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}IPv4 ->\n'
        result += f'{" " * offset}   Dst Addr...: {self.dst_ip}\n'
        result += f'{" " * offset}   Src Addr...: {self.src_ip}\n'
        result += f'{" " * offset}   Protocol...: {self.protocol},0x{self.protocol:02x} \n'
        result += f'{" " * offset}   IHL........: {self.ihl}\n'
        result += f'{" " * offset}   TTL........: {self.ttl}\n'
        result += f'{" " * offset}   Flags......: {self.flags}\n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'

        return result

    def export(self) -> dict[str, int | str]:
        return {
            "ip.dst": str(self.src_ip),
            "ip.src": str(self.dst_ip),
            "ip.protocol": self.protocol,
            "ip.ihl": self.ihl,
            "ip.ttl": self.ttl,
            "ip.flags": self.flags,
            "ip.checksum": self.checksum,
        }

    def __str__(self) -> str:
        return f"IPV4 -> src_ip: {self.src_ip}, dst_ip: {self.dst_ip}, proto: {self.protocol}, ttl: {self.ttl}, flags: {self.flags:x}, tos:{self.tos:x}"

    def get_field(self, fieldname: str):
        field = fieldname.split('.')[1]
        if field:
            if field == 'version':
                return self.version
            elif field == 'tos':
                return self.tos
            elif field == 'length':
                return self.total_len
            elif field == 'id':
                return self.identification
            elif field == 'flags':
                return self.flags
            elif field == 'frag_offset':
                return self.frag_offset
            elif field == 'ttl':
                return self.ttl
            elif field == 'protocol':
                return self.protocol
            elif field == 'checksum':
                return self.checksum
            elif field == 'src':
                return self.src_ip.value
            elif field == 'dst':
                return self.dst_ip.value
            else:
                return 0
        else:
            return 0

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

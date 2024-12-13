"""
Destination Unreachable Message

    0               1               2                   3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      3

   Code

      0 = net unreachable;

      1 = host unreachable;

      2 = protocol unreachable;

      3 = port unreachable;

      4 = fragmentation needed and DF set;

      5 = source route failed.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      If, according to the information in the gateway's routing tables,
      the network specified in the internet destination field of a
      datagram is unreachable, e.g., the distance to the network is
      infinity, the gateway may send a destination unreachable message
      to the internet source host of the datagram.  In addition, in some
      networks, the gateway may be able to determine if the internet
      destination host is unreachable.  Gateways in these networks may
      send destination unreachable messages to the source host when the
      destination host is unreachable.

      If, in the destination host, the IP module cannot deliver the
      datagram  because the indicated protocol module or process port is
      not active, the destination host may send a destination
      unreachable message to the source host.

      Another case is when a datagram must be fragmented to be forwarded
      by a gateway yet the Don't Fragment flag is on.  In this case the
      gateway must discard the datagram and may return a destination
      unreachable message.

      Codes 0, 1, 4, and 5 may be received from a gateway.  Codes 2 and
      3 may be received from a host.

"""
from struct import unpack

from packet.layers.datagram import Datagram
from packet.layers.frame import Frame
from packet.layers.ipv4 import IPV4
from packet.layers.layer_type import LayerID
# from packet.utils.print_hex import format_hex
from packet.layers.packet import Packet


class IcmpDestUnreach(Packet):
    name = LayerID.ICMP_DESTUNREACH
    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def icmp_type(self) -> int:
        return unpack("!B", self.packet[0:1])[0]

    @property
    def code(self) -> int:
        return unpack("!B", self.packet[1:2])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def datagram(self) -> Datagram:
        ipv4 = IPV4(self.packet[8:])
        self.datagram_def = Datagram(ipv4)

        return self.datagram_def

    def __str__(self):
        return f"ICMP Dest unreachable -> type: {self.icmp_type}, code: {self.code}, checksum: {self.checksum:x}, src_ip: {self.datagram.src_ip}, dst_ip: {self.datagram.dst_ip}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}ICMP-Destination unreachable ->\n'
        result += f'{" " * offset}   Type.......: {self.icmp_type}\n'
        result += f'{" " * offset}   Code.......: {self.code}\n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'
        result += f'{" " * offset}   Datagram...: {self.datagram}\n'

        return result

    def get_field(self, fieldname: str) -> int | IPV4 | None:
        match fieldname:
            case "icmp_destunreach.type":
                return self.icmp_type
            case "icmp_destunreach.code":
                return self.code
            case "icmp_destunreach.checksum":
                return self.checksum
            case "icmp_destunreach.datagram":
                return self.datagram.export()
            case "icmp_destunreach.datagram.*":
                return "datagram field"
            case _:
                return None

    def export(self) -> dict[str, str | int] | None:
        return {
            "icmp_destunreach.type": self.icmp_type,
            "icmp_destunreach.code": self.code,
            "icmp_destunreach.checksum": self.checksum,
            "icmp_destunreach.datagram": self.datagram.export(),
        }

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.packet) and (offset + length) < len(self.packet):
            return self.packet[offset: offset + length]
        else:
            return None

    @property
    def is_valid(self) -> bool:
        return self.icmp_type == 3 and (self.code == 1 or self.code == 3)

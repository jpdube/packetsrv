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
from struct import pack, unpack
from packet.layers.ipv4 import IPV4
from pql.model import IPv4
from packet.utils.print_hex import format_hex


class IcmpDestUnreach:
    name = 7

    def __init__(self, packet):
        self.packet = packet

    @property
    def type(self) -> int:
        return unpack("!B", self.packet[0:1])[0]

    @property
    def code(self) -> int:
        return unpack("!B", self.packet[1:2])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def datagram(self) -> IPV4:
        return IPV4(self.packet[8:])

    def __str__(self):
        return f"ICMP Dest unreachable -> type: {self.type}, code: {self.code}, checksum: {self.checksum:x}, src_ip: {self.datagram.src_ip}, dst_ip: {self.datagram.dst_ip}"

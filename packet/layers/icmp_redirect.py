from struct import unpack

"""
Redirect Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Gateway Internet Address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address of the original datagram's data.

   ICMP Fields:

   Type

      5

   Code

      0 = Redirect datagrams for the Network.

      1 = Redirect datagrams for the Host.

      2 = Redirect datagrams for the Type of Service and Network.

      3 = Redirect datagrams for the Type of Service and Host.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Gateway Internet Address

      Address of the gateway to which traffic for the network specified
      in the internet destination network field of the original
      datagram's data should be sent.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      The gateway sends a redirect message to a host in the following
      situation.  A gateway, G1, receives an internet datagram from a
      host on a network to which the gateway is attached.  The gateway,
      G1, checks its routing table and obtains the address of the next
      gateway, G2, on the route to the datagram's internet destination
      network, X.  If G2 and the host identified by the internet source
      address of the datagram are on the same network, a redirect
      message is sent to the host.  The redirect message advises the
      host to send its traffic for network X directly to gateway G2 as
      this is a shorter path to the destination.  The gateway forwards
      the original datagram's data to its internet destination.

      For datagrams with the IP source route options and the gateway
      address in the destination address field, a redirect message is
      not sent even if there is a better route to the ultimate
      destination than the next address in the source route.

      Codes 0, 1, 2, and 3 may be received from a gateway.
"""


class IcmpRedirect:
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
    def gw_ip_addr(self) -> int:
        return unpack("!I", self.packet[4:8])[0]

    @property
    def datagram(self) -> bytes:
        return self.packet[8:]

    def __str__(self):
        return f"ICMP Redirect -> type: {self.type}, code: {self.code}, checksum: {self.checksum}, Gateway: {self.gw_ip_addr}"

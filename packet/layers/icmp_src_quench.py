from struct import unpack

"""
Source Quench Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address of the original datagram's data.

   ICMP Fields:

   Type

      4

   Code

      0

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

      A gateway may discard internet datagrams if it does not have the
      buffer space needed to queue the datagrams for output to the next
      network on the route to the destination network.  If a gateway
      discards a datagram, it may send a source quench message to the
      internet source host of the datagram.  A destination host may also
      send a source quench message if datagrams arrive too fast to be
      processed.  The source quench message is a request to the host to
      cut back the rate at which it is sending traffic to the internet
      destination.  The gateway may send a source quench message for
      every message that it discards.  On receipt of a source quench
      message, the source host should cut back the rate at which it is
      sending traffic to the specified destination until it no longer
      receives source quench messages from the gateway.  The source host
      can then gradually increase the rate at which it sends traffic to
      the destination until it again receives source quench messages.

      The gateway or host may send the source quench message when it
      approaches its capacity limit rather than waiting until the
      capacity is exceeded.  This means that the data datagram which
      triggered the source quench message may be delivered.

      Code 0 may be received from a gateway or a host.

"""


class IcmpSrcQuench:
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
    def datagram(self) -> bytes:
        return self.packet[8:]

    def __str__(self):
        return f"ICMP Source quench -> type: {self.type}, code: {self.code}, checksum: {self.checksum}"

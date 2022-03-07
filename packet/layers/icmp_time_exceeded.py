from struct import unpack
from packet.layers.packet import Packet

"""
Time Exceeded Message

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

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      11

   Code

      0 = time to live exceeded in transit;

      1 = fragment reassembly time exceeded.

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

      If the gateway processing a datagram finds the time to live field
      is zero it must discard the datagram.  The gateway may also notify
      the source host via the time exceeded message.

      If a host reassembling a fragmented datagram cannot complete the
      reassembly due to missing fragments within its time limit it
      discards the datagram, and it may send a time exceeded message.

      If fragment zero is not available then no time exceeded need be
      sent at all.

      Code 0 may be received from a gateway.  Code 1 may be received
      from a host.
"""


class IcmpTimeExceeded(Packet):

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
        return f"ICMP Dest unreachable -> type: {self.type}, code: {self.code}, checksum: {self.checksum}"

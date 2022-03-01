from struct import unpack

"""
Parameter Problem Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Pointer    |                   unused                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      12

   Code

      0 = pointer indicates the error.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Pointer

      If code = 0, identifies the octet where an error was detected.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      If the gateway or host processing a datagram finds a problem with
      the header parameters such that it cannot complete processing the
      datagram it must discard the datagram.  One potential source of
      such a problem is with incorrect arguments in an option.  The
      gateway or host may also notify the source host via the parameter
      problem message.  This message is only sent if the error caused
      the datagram to be discarded.

      The pointer identifies the octet of the original datagram's header
      where the error was detected (it may be in the middle of an
      option).  For example, 1 indicates something is wrong with the
      Type of Service, and (if there are options present) 20 indicates
      something is wrong with the type code of the first option.

      Code 0 may be received from a gateway or a host.

"""


class IcmpParamProblem:
    name = 6

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
    def pointer(self) -> int:
        return unpack("!B", self.packet[4:5])[0]

    @property
    def datagram(self) -> bytes:
        return self.packet[8:]

    def __str__(self):
        return f"ICMP Param Problem -> type: {self.type}, code: {self.code}, checksum: {self.checksum}, pointer: {self.pointer}"

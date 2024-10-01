from struct import unpack
from packet.layers.packet import Packet
from typing import Dict

"""
Information Request or Information Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Addresses

      The address of the source in a information request message will be
      the destination of the information reply message.  To form a
      information reply message, the source and destination addresses
      are simply reversed, the type code changed to 16, and the checksum
      recomputed.

   IP Fields:

   Type

      15 for information request message;

      16 for information reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching request and replies,
      may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching request and
      replies, may be zero.

   Description

      This message may be sent with the source network in the IP header
      source and destination address fields zero (which means "this"
      network).  The replying IP module should send the reply with the
      addresses fully specified.  This message is a way for a host to
      find out the number of the network it is on.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the requests.  For example,
      the identifier might be used like a port in TCP or UDP to identify
      a session, and the sequence number might be incremented on each
      request sent.  The destination returns these same values in the
      reply.

      Code 0 may be received from a gateway or a host.

"""


class IcmpInfoReq(Packet):
    name = 6

    def __init__(self, packet: bytes):
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
    def identifier(self) -> int:
        return unpack("!H", self.packet[4:6])[0]

    @property
    def sequence_no(self) -> int:
        return unpack("!H", self.packet[6:8])[0]

    def __str__(self):
        return f"ICMP Info request -> type: {self.type}, code: {self.code}, checksum: {self.checksum}, identifier: {self.identifier}"

    def summary(self, offset: int) -> str:
        result =  f'{" " * offset}ICMP-Info request ->\n'
        result += f'{" " * offset}   Type...: {self.type}\n'
        result += f'{" " * offset}   Code...: {self.code}\n'
        result += f'{" " * offset}   Seq no.....: {self.sequence_no},0x{self.sequence_no:04x} \n'
        result += f'{" " * offset}   Identifier.: {self.identifier},0x{self.identifier:04x} \n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'

        return result

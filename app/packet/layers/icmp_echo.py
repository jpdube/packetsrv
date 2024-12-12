from struct import unpack
from packet.layers.packet import Packet
from packet.layers.layer_type import LayerID
from typing import Dict

"""
Echo or Echo Reply Message

  0               1               2               3
  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     Type      |     Code      |          Checksum             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Identifier          |        Sequence Number        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     Data ...
 +-+-+-+-+-
IP Fields:

   Addresses

      The address of the source in an echo message will be the
      destination of the echo reply message.  To form an echo reply
      message, the source and destination addresses are simply reversed,
      the type code changed to 0, and the checksum recomputed.

   IP Fields:

   Type

      8 for echo message;

      0 for echo reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      If the total length is odd, the received data is padded with one
      octet of zeros for computing the checksum.  This checksum may be
      replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching echos and replies,
      may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching echos and
      replies, may be zero.

   Description

      The data received in the echo message must be returned in the echo
      reply message.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the echo requests.  For
      example, the identifier might be used like a port in TCP or UDP to
      identify a session, and the sequence number might be incremented
      on each echo request sent.  The echoer returns these same values
      in the echo reply.

      Code 0 may be received from a gateway or a host.
"""


class IcmpEcho(Packet):
    name = LayerID.ICMP_ECHO

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

    @property
    def payload(self) -> bytes:
        return self.packet[8:]

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}ICMP-Echo ->\n'
        result += f'{" " * offset}   Type...: {self.type}\n'
        result += f'{" " * offset}   Code...: {self.code}\n'
        result += f'{" " * offset}   Seq no.....: {self.sequence_no},0x{self.sequence_no:04x} \n'
        result += f'{" " * offset}   Identifier.: {self.identifier},0x{self.identifier:04x} \n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'

        return result

    def __str__(self):
        return f"ICMP Echo -> type: {self.type}, code: {self.code}, checksum: {self.checksum:x}, identifier: {self.identifier}, sequence: {self.sequence_no}"

    def get_field(self, fieldname: str) -> int | bytes | None:
        match fieldname:
            case "icmp_echo.type":
                return self.type
            case "icmp_echo.code":
                return self.code
            case "icmp_echo.seq_no":
                return self.sequence_no
            case "icmp_echo.identifier":
                return self.identifier
            case "icmp_echo.checksum":
                return self.checksum
            case "icmp_echo.payload":
                return self.payload
            case _:
                return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

    def export(self) -> dict[str, str | int]:
        return {
            "icmp_echo.type": {self.type},
            "icmp_echo.code": {self.code},
            "icmp_echo.seq_no": {self.sequence_no},
            "icmp_echo.identifier": {self.identifier},
            "icmp_echo.checksum": {self.checksum},
        }

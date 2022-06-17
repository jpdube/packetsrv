"""
   IPv6 Header Format

   0              7              15              23               31
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Version              4-bit Internet Protocol version number = 6.

   Traffic Class        8-bit traffic class field.  See section 7.

   Flow Label           20-bit flow label.  See section 6.

   Payload Length       16-bit unsigned integer.  Length of the IPv6
                        payload, i.e., the rest of the packet following
                        this IPv6 header, in octets.  (Note that any
                        extension headers [section 4] present are
                        considered part of the payload, i.e., included
                        in the length count.)

   Next Header          8-bit selector.  Identifies the type of header
                        immediately following the IPv6 header.  Uses the
                        same values as the IPv4 Protocol field [RFC-1700
                        et seq.].

   Hop Limit            8-bit unsigned integer.  Decremented by 1 by
                        each node that forwards the packet. The packet
                        is discarded if Hop Limit is decremented to
                        zero.

   Source Address       128-bit address of the originator of the packet.
                        See [ADDRARCH].

   Destination Address  128-bit address of the intended recipient of the
                        packet (possibly not the ultimate recipient, if
                        a Routing header is present).  See [ADDRARCH]
                        and section 4.4.


"""
from typing import List
from packet.layers.packet import Packet
from struct import unpack
from packet.layers.packet import Packet


class IPV6(Packet):

    name = 5
    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def src_addr(self) -> List[int]:
        return self.packet[8:24]

    @property
    def dst_addr(self) -> List[int]:
        return self.packet[24:40]

    @property
    def protocol(self) -> int:
        return unpack("!B", self.packet[6:7])[0]

    def __str__(self) -> str:
        return f"IPv6 src addr: {self.src_addr}, dst addr: {self.dst_addr} protocol: {self.protocol}"

    def summary(self, offset: int) -> str:
        result =  f'{" " * offset}IPv4 ->\n'
        result += f'{" " * offset}   Dst Addr...: {self.dst_addr}\n'
        result += f'{" " * offset}   Src Addr...: {self.src_addr}\n'
        result += f'{" " * offset}   Protocol...: {self.protocol},0x{self.protocol:02x} \n'

        return result

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
from fw.layers.fields import ByteField, ShortField, LongField
from fw.layers.packet import Packet


class IPV6(Packet):

    name = 5

    def __init__(
        self,
        src_addr,
        dst_addr,
        version=0,
        traffic_cls=0,
        flow_label=0,
        payload_len=0,
        next_hdr=0,
        hop_limit=0,
    ):
        self._version = ByteField(version)
        self._traffic_cls = ByteField(traffic_cls)
        self._flow_label = LongField(flow_label)
        self._payload_len = ShortField(payload_len)
        self._next_hdr = ByteField(next_hdr)
        self._hop_limit = ByteField(hop_limit)
        self._src_addr = src_addr
        self._dst_addr = dst_addr

    @classmethod
    def from_packet(cls, raw_packet):
        src_addr = raw_packet[8:24]
        dst_addr = raw_packet[24:40]
        next_hdr = raw_packet[6]

        c = cls(src_addr, dst_addr, next_hdr=next_hdr)

        return c

    @property
    def protocol(self) -> int:
        return self._next_hdr.value

    def __str__(self) -> str:
        return f"IPv6 src addr: {self._src_addr}, dst addr: {self._dst_addr} protocol: {self.protocol}"

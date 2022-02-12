from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, IPv4Address, W24Field
from fw.utils.calc_checksum import calc_checksum
#  from fw.utils.print_hex import print_hex


from struct import pack, unpack

IHL_SHORT = 5
IHL_LONG = 6

IP_PROTO_TCP = 0x06
IP_PROTO_UDP = 0x11
IP_PROTO_ICMP = 0x01


class IPV4(Packet):
    name = 'ipv4'

    def __init__(self,
                 src_ip,
                 dst_ip,
                 ihl=5,
                 tos=0,
                 total_len=0,
                 identification=0,
                 flags=0,
                 frag_offset=0,
                 ttl=0x0f,
                 protocol=IP_PROTO_TCP,
                 checksum=0,
                 version=4,
                 options=0):
        self.src_ip = IPv4Address(src_ip)
        self.dst_ip = IPv4Address(dst_ip)
        self._protocol = ShortField(protocol)
        self.version = ByteField(version)
        self.ihl = ByteField(ihl)
        self.tos = ByteField(tos)
        self.total_len = ShortField(total_len)
        self.identification = ShortField(identification)
        self.flags = ByteField(flags)
        self.frag_offset = ShortField(frag_offset)
        self.ttl = ByteField(ttl)
        self.checksum = ShortField(checksum)
        self.options = W24Field(options)

    @classmethod
    def from_packet(cls, packet):
        # --- Read the first byte and get the version and ihl
        # --- If IHL <> 5 then read optional 32bits of header
        # if len(raw_packet) != 20 and len(raw_packet) != 24:
        #     print(f'Packet len: {len(raw_packet)}')
        #     return
        # print('IPV4 from packet')
        raw_packet = bytes(packet)

        octet_0 = unpack('B', raw_packet[:1])[0]
        version = (octet_0 & 0xf0) >> 4
        ihl = (octet_0 & 0x0f)

        if ihl == IHL_SHORT:
            temp = unpack('!BHHHBBHII', raw_packet[1:20])
            print(temp)
            octet_1, length, identification, fragment, ttl, protocol, checksum, src_ip, dst_ip = unpack(
                '!BHHHBBHII', raw_packet[1:20])
            options = None
        elif ihl == IHL_LONG:
            octet_1, length, identification, fragment, ttl, protocol, checksum, src_ip, dst_ip, options = unpack(
                '!BHHHBBHIII', raw_packet[1:24])
        else:
            return

        tos = (octet_1 & 0x7c) >> 2
        flags = (fragment & 0xE000) >> 13
        fragment_offset = (fragment & 0x1FF)

        c = cls(src_ip=src_ip,
                dst_ip=dst_ip,
                ihl=ihl,
                tos=tos,
                total_len=length,
                identification=identification,
                flags=flags,
                frag_offset=fragment_offset,
                ttl=ttl,
                protocol=protocol,
                checksum=checksum,
                version=version,
                options=options)

        return c

    @property
    def protocol(self) -> int:
        return self._protocol.value

    @protocol.setter
    def protocol(self, protocol):
        self._protocol = ByteField(protocol)

    #  def packet(self) -> Packet:
        #  return super().packet

    def to_bytes(self) -> bytearray:
        result = bytearray()
        print(f'Version: {self.version}, IHL: {self.ihl}')
        result += pack('B', (self.version.value << 4)
                       | (self.ihl.value & 0x0f))
        result += self.tos.binary
        result += self.total_len.binary
        result += self.identification.binary
        flag = self.flags.value
        flag_and_frag = (flag << 13) | (self.frag_offset.value & 0x1fff)
        result += pack('>H', flag_and_frag)
        result += self.ttl.binary
        result += self.protocol.binary
        result += pack('>H', 0x0000)
        result += self.src_ip.binary
        result += self.dst_ip.binary

        # print(f'IHL: {self.ihl.value}, {self.options.value:x}')
        if self.ihl.value == IHL_LONG:
            result += self.options.binary

        checksum = calc_checksum(result)
        result[10] = (checksum & 0xff00) >> 8
        result[11] = checksum & 0x00ff

        return result

    def __str__(self) -> str:
        return f'IPV4: src_ip: {self.src_ip}, dst_ip: {self.dst_ip}, proto: {self.protocol}'

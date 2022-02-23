from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, IPv4Address, MacAddress
from fw.utils.print_hex import print_hex
from struct import unpack

class ARP(Packet):
    name = "arp"

    def __init__(
        self,
        src_mac,
        src_ip,
        target_mac,
        target_ip,
        htype,
        ptype,
        hlen,
        plen,
        opcode,
    ):
        super().__init__()
        self.src_mac = MacAddress(src_mac)
        self.src_ip = IPv4Address(src_ip)
        self.target_mac = MacAddress(target_mac)
        self.target_ip = IPv4Address(target_ip)
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.opcode = opcode

    @classmethod
    def from_packet(cls, raw_packet):
        # print_hex(raw_packet)
        htype, ptype, hlen, plen, opcode = unpack(
            '!HHBBH', raw_packet[0:8])

        c = cls(
            htype=htype,
            ptype=ptype,
            hlen=hlen,
            plen=plen,
            opcode=opcode,
            src_mac=raw_packet[8:14],
            src_ip=raw_packet[14:18],
            target_mac=raw_packet[18:24],
            target_ip=raw_packet[24:28])

        return c

    @property
    def packet(self):
        return super().packet

    # @property
    # def to_bytes(self):
    #     result = bytearray()
    #     result += self.hardware_type.binary
    #     result += self.protocol_type.binary
    #     result += self.hardware_size.binary
    #     result += self.protocol_size.binary
    #     result += self.opcode.binary
    #     result += self.src_mac.binary
    #     result += self.src_ip.binary
    #     result += self.target_mac.binary
    #     result += self.target_ip.binary
    #
    #     return result

    def __str__(self):
        return f"{ARP.name}: Opcode: {self.opcode}, Htype: {self.htype}, PType: {self.ptype}, smac: {self.src_mac}, sip: {self.src_ip}, tmac: {self.target_mac}, tip: {self.target_ip}"

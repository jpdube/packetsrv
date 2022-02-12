from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, IPv4Address, MacAddress
from fw.utils.print_hex import print_hex


class ARP(Packet):
    name = 'arp'

    def __init__(self, src_mac, src_ip, target_mac, target_ip, opcode):
        super().__init__()
        self.src_mac = MacAddress(src_mac)
        self.src_ip = IPv4Address(src_ip)
        self.target_mac = MacAddress(target_mac)
        self.target_ip = IPv4Address(target_ip)
        self.hardware_type = ShortField(0x01)
        self.protocol_type = ShortField(0x0800)
        self.hardware_size = ByteField(0x06)
        self.protocol_size = ByteField(0x04)
        self.opcode = ShortField(opcode)

    @property
    def packet(self):
        return super().packet

    # @property
    def to_bytes(self):
        result = bytearray()
        result += self.hardware_type.binary
        result += self.protocol_type.binary
        result += self.hardware_size.binary
        result += self.protocol_size.binary
        result += self.opcode.binary
        result += self.src_mac.binary
        result += self.src_ip.binary
        result += self.target_mac.binary
        result += self.target_ip.binary

        return result

    def __str__(self):
        return f'{ARP.name}: smac: {self.src_mac}, sip: {self.src_ip}, tmac: {self.target_mac}, tip: {self.target_ip}'

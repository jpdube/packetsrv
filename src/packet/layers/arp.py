from packet.layers.fields import IPv4Address, MacAddress
from struct import unpack
from packet.layers.packet import Packet
from typing import Dict


class ARP(Packet):
    name = 5
    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def htype(self) -> int:
        return unpack("!H", self.packet[0:2])[0]

    @property
    def ptype(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def hlen(self) -> int:
        return self.packet[4]

    @property
    def plen(self) -> int:
        return self.packet[5]

    @property
    def opcode(self) -> int:
        return unpack("!H", self.packet[6:8])[0]

    @property
    def src_mac(self) -> MacAddress:
        return MacAddress(self.packet[8:14])

    @property
    def src_ip(self) -> IPv4Address:
        return IPv4Address(self.packet[14:18])

    @property
    def target_mac(self) -> MacAddress:
        return MacAddress(self.packet[18:24])

    @property
    def target_ip(self) -> IPv4Address:
        return IPv4Address(self.packet[24:28])

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}ARP ->\n'
        result += f'{" " * offset}   Hardware type.: {self.htype}\n'
        result += f'{" " * offset}   Hardware len..: {self.hlen}\n'
        result += f'{" " * offset}   Protocl type..: {self.ptype}\n'
        result += f'{" " * offset}   Protocol len..: {self.plen}\n'
        result += f'{" " * offset}   Opcode........: {self.opcode}\n'
        result += f'{" " * offset}   Src MAC.......: {self.src_mac}\n'
        result += f'{" " * offset}   Target MAC....: {self.target_mac}\n'
        result += f'{" " * offset}   Src IP........: {self.src_ip}\n'
        result += f'{" " * offset}   Target IP.....: {self.target_ip}\n'

        return result

    def __str__(self):
        return f"ARP -> Opcode: {self.opcode}, Htype: {self.htype}, PType: {self.ptype}, smac: {self.src_mac}, sip: {self.src_ip}, tmac: {self.target_mac}, tip: {self.target_ip}"

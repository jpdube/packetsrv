from struct import unpack
from typing import Dict

from packet.layers.fields import IPv4Address, MacAddress
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet


class ARP(Packet):
    name = LayerID.ARP

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
    def sender_mac(self) -> MacAddress:
        return MacAddress(self.packet[8:14])

    @property
    def sender_ip(self) -> IPv4Address:
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
        result += f'{" " * offset}   Src MAC.......: {self.sender_mac}\n'
        result += f'{" " * offset}   Target MAC....: {self.target_mac}\n'
        result += f'{" " * offset}   Src IP........: {self.sender_ip}\n'
        result += f'{" " * offset}   Target IP.....: {self.target_ip}\n'

        return result

    def export(self) -> dict[str, int | str]:
        return {
            "arp.htype": self.htype,
            "arp.hlen": self.hlen,
            "arp.ptype": self.ptype,
            "arp.plen": self.plen,
            "arp.opcode": self.opcode,
            "arp.srcmac": self.sender_mac,
            "arp.targetmac": self.target_mac,
            "arp.srcip": self.sender_ip,
            "arp.targetip": self.target_ip,
        }

    def __str__(self):
        return f"ARP -> Opcode: {self.opcode}, Htype: {self.htype}, PType: {self.ptype}, smac: {self.sender_mac}, sip: {self.sender_ip}, tmac: {self.target_mac}, tip: {self.target_ip}"

    def get_field(self, fieldname: str):
        if fieldname == "arp.htype":
            return self.htype
        elif fieldname == "arp.hlen":
            return self.hlen
        elif fieldname == "arp.ptype":
            return self.ptype
        elif fieldname == "arp.plen":
            return self.plen
        elif fieldname == "arp.opcode":
            return self.opcode
        elif fieldname == "arp.sender_mac":
            return str(self.sender_mac)
        elif fieldname == "arp.target_mac":
            return str(self.target_mac)
        elif fieldname == "arp.target_ip":
            return str(self.target_ip)
        elif fieldname == "arp.sender_ip":
            return str(self.sender_ip)
        elif fieldname == "arp.target_ip":
            return str(self.target_ip)

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.packet) and (offset + length) < len(self.packet):
            return self.packet[offset: offset + length]
        else:
            return None

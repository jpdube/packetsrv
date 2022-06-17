from struct import unpack

from packet.layers.fields import MacAddress
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86DD
ETHER_TYPE_ARP = 0x0806
FRAME_TYPE_8021Q = 0x8100


class Ethernet(Packet):
    name = LayerID.ETHERNET

    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def frametype(self) -> int:
        return unpack("!H", self.packet[12:14])[0]

    @property
    def ethertype(self) -> int:
        if self.frametype == FRAME_TYPE_8021Q:
            return unpack("!H", self.packet[16:18])[0]
        else:
            return unpack("!H", self.packet[12:14])[0]

    @property
    def dst_mac(self) -> MacAddress:
        return MacAddress(self.packet[:6])

    @property
    def src_mac(self) -> MacAddress:
        return MacAddress(self.packet[6:12])

    @property
    def vlan_id(self) -> int:
        if self.frametype == FRAME_TYPE_8021Q:
            return unpack("!H", self.packet[14:16])[0]
        else:
            return 1

    @property
    def payload(self) -> bytes:
        if self.frametype == FRAME_TYPE_8021Q:
            return self.packet[18:]
        else:
            return self.packet[14:]

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}Ethernet ->\n'
        result += f'{" " * offset}   Dst Mac..: {self.dst_mac}\n'
        result += f'{" " * offset}   Src Mac..: {self.src_mac}\n'
        result += f'{" " * offset}   Ethertype: {self.ethertype},0x{self.ethertype:04x} \n'
        result += f'{" " * offset}   Vlan ID..: {self.vlan_id}\n'
        return result

    def __str__(self):
        return f"Ethernet -> src_mac: {self.src_mac}, dst_mac: {self.dst_mac}, protocol: {self.ethertype}, vlan_id: {self.vlan_id}"

    def get_field(self, fieldname: str):
        field = fieldname.split('.')[1]
        if field:
            match field:
                case 'dst':
                    return self.dst_mac
                case 'src':
                    return self.src_mac
                case 'vlan':
                    return self.vlan_id
                case 'ethertype':
                    return self.ethertype
                case _:
                    return 0
        else:
            return 0

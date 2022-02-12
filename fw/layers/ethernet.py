from fw.layers.packet import Packet
from fw.layers.fields import MacAddress, ShortField


ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806


class Ethernet():
    name = 'ethernet'

    def __init__(self, src, dst, ethertype):
        self._src_mac = MacAddress(src)
        self._dst_mac = MacAddress(dst)
        self._ethertype = ShortField(ethertype)

    @classmethod
    def from_packet(cls, packet):
        if len(packet) == 0x0e:
            return cls(src=packet[:6], dst=packet[6:12], ethertype=packet[12:14])
        return None

    def to_bytes(self):
        result = bytearray()
        for name, value in self.fields.items():
            print(name, value)
            result += value.binary
        return result

    @property
    def ethertype(self):
        return self._ethertype.value

    @ethertype.setter
    def ethertype(self, value):
        self._ethertype = ShortField(value)

    @property
    def src_mac(self) -> MacAddress:
        return self._ssrc_mac

    @property
    def dst_mac(self) -> MacAddress:
        return self._dst_mac

    def __str__(self):
        return f"src_mac: {self._src_mac}, dst_mac: {self._dst_mac}, protocol: {self._ethertype}"
        # return f"src_mac: {self.src}, dst_mac: {self.dst}, ehertype: {self.ether_type}"
        #  return f"src_mac: {self.fields['src']}, dst_mac: {self.fields['dst']}, ehertype: {self.fields['ethertype']}"

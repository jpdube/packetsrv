from fw.layers.packet import Packet
from fw.layers.fields import IPv4Address


class IP(Packet):
    def __init__(self, **fields):
        super().__init__(self)
        self.fields["src_ip"] = IPv4Address("192.168.242.1")
        self.fields["dst_ip"] = IPv4Address("192.168.1.123")

    def __str__(self):
        return f"Src ip: {self.fields['src_ip']}, Dst ip: {self.fields['dst_ip']}"

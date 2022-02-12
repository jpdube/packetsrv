from fw.layers.fields import MacAddress, IPv4Address, ShortField
from fw.layers.ethernet import Ethernet
from fw.layers.ipv4 import IPV4

class RawPacket:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.ethernet = None
        self.ip = None
        self.tcp = None
        self.udp = None

    def get_ethernet(self) -> Ethernet:
        if self.ethernet is None:
            self.ethernet = Ethernet.from_packet(self.raw_bytes[:14])

        return self.ethernet

    def get_ip(self) -> IPV4:
        if self.ip is None:
            self.ip = IPV4.from_packet(self.raw_bytes[14:])

        return self.ip

    def get_tcp(self):
        pass

    def get_udp(self):
        pass

    def __str__(self) -> str:
        self.get_ip()
        return f"Ethernet:\n {self.ethernet}\nIPv4: {self.ip}\n"

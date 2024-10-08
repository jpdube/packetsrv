from enum import Enum
from enum import auto


class LayerID(Enum):
    ETHERNET = auto()
    IPV4 = auto()
    IPV6 = auto()
    TCP = auto()
    UDP = auto()
    ARP = auto()
    ICMP = auto()
    FRAME = auto()
    UNDEFINED = auto()
    DHCP = auto()
    DNS = auto()

    def __str__(self) -> str:
        return str(self.name)

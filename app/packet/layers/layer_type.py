from enum import Enum, auto


class LayerID(Enum):
    ETHERNET = auto()
    IPV4 = auto()
    IPV6 = auto()
    TCP = auto()
    UDP = auto()
    ARP = auto()
    # ICMP = auto()
    ICMP_ECHO = auto()
    ICMP_DESTUNREACH = auto()
    FRAME = auto()
    UNDEFINED = auto()
    DHCP = auto()
    DNS = auto()
    HTTP = auto()
    HTTPS = auto()
    SSH = auto()
    TELNET = auto()
    SIP = auto()
    FTP = auto()
    SMB = auto()
    RDP = auto()

    def __str__(self) -> str:
        return str(self.name)


def has_value(value) -> bool:
    value_list = [item.name for item in LayerID]

    result = value.upper() in value_list
    print(result, value, value_list)
    return result


def from_string(str_value: str) -> LayerID:
    match str_value:
        case"ETHERNET":
            return LayerID.ETHERNET
        case"IPV4":
            return LayerID.IPV4
        case"IPV6":
            return LayerID.IPV6
        case"TCP":
            return LayerID.TCP
        case"UDP":
            return LayerID.UDP
        case"ARP":
            return LayerID.ARP
        # case"ICMP":
        #     return LayerID.ICMP
        case"ICMP_DESTUNREACH":
            return LayerID.ICMP_DESTUNREACH
        case"FRAME":
            return LayerID.FRAME
        case"DHCP":
            return LayerID.DHCP
        case"DNS":
            return LayerID.DNS
        case"HTTP":
            return LayerID.HTTP
        case"HTTPS":
            return LayerID.HTTPS
        case"SSH":
            return LayerID.SSH
        case"TELNET":
            return LayerID.TELNET
        case"SIP":
            return LayerID.SIP
        case"FTP":
            return LayerID.FTP
        case"SMB":
            return LayerID.SMB
        case"ICMP_ECHO":
            return LayerID.ICMP_ECHO
        case"RDP":
            return LayerID.RDP

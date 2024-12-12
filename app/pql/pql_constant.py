import logging
from enum import Enum

log = logging.getLogger("packetdb")


class Constants(Enum):
    IP_PROTO_ICMP = "ICMP"
    IP_PROTO_TCP = "TCP"
    IP_PROTO_UDP = "UDP"
    ETH_PROTO_IPV4 = "IPV4"
    ETH_PROTO_IPV6 = "IPV6"
    ETH_PROTO_ARP = "ARP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    RDP = "RDP"
    TELNET = "TELNET"
    SMTP = "SMTP"
    POP3 = "POP3"
    POP3S = "POP3S"
    IMAP = "IMAP"
    IMAPS = "IMAPS"
    SNMP = "SNMP"
    FTP = "FTP"
    NTP = "NTP"
    RTP = "RTP"
    RTCP = "RTCP"
    SIP = "SIP"
    SIP_TLS = "SIP_TLS"
    BGP = "BGP"
    DHCP = "DHCP"
    SMB = "SMB"
    ICMP_ECHO = "ICMP_ECHO"
    ICMP_DESTUNREACH = "ICMP_DESTUNREACH"


def has_value(value: str) -> Constants | None:
    const = None

    try:
        const = Constants(value)
    except ValueError:
        const = None

    return const

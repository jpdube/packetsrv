
const_list = {
    # "IP_TOS_NET_CTRL": CONST_IP_TOS_NET_CTRL,
    # "IP_TOS_INTNET_CTRL": CONST_IP_TOS_INTNET_CTRL,
    # "IP_TOS_CRITIC_ECP": CONST_IP_TOS_CRITIC_ECP,
    # "IP_TOS_FLASH_OVERRIDE": CONST_IP_TOS_FLASH_OVERRIDE,
    # "IP_TOS_FLASH": CONST_IP_TOS_FLASH,
    # "IP_TOS_IMMEDIATE": CONST_IP_TOS_IMMEDIATE,
    # "IP_TOS_PRIORITY": CONST_IP_TOS_PRIORITY,
    # "IP_TOS_ROUTINE": CONST_IP_TOS_ROUTINE,
    # "IP_TOS_MIN_DELAY": CONST_IP_TOS_MIN_DELAY,
    # "IP_TOS_MAX_THROUGHPUT": CONST_IP_TOS_MAX_THROUGHPUT,
    # "IP_TOS_MAX_RELIABILITY": CONST_IP_TOS_MAX_RELIABILITY,
    # "IP_TOS_MIN_COST": CONST_IP_TOS_MIN_COST,
    # "IP_TOS_MIN_NORMAL": CONST_IP_TOS_NORMAL,
    # "IP_TOS_EF": CONST_IP_TOS_EF,
    "IP_PROTO_ICMP": 0x01,
    "IP_PROTO_TCP": 0x06,
    "IP_PROTO_UDP": 0x11,
    "ETH_PROTO_IPV4": 0x0800,
    "ETH_PROTO_IPV6": 0x86dd,
    "ETH_PROTO_ARP": 0x0806,
    "HTTP": 80,
    "HTTPS": 443,
    "DNS": 53,
    "SSH": 22,
    "RDP": 3389,
    "TELNET": 23,
    "SMTP": 25,
    "POP3": 110,
    "POP3S": 995,
    "IMAP": 143,
    "IMAPS": 993,
    "SNMP": 161,
    "FTP": 21,
    "NTP": 123,
    "RTP": 5004,
    "RTCP": 5005,
    "SIP": 5060,
    "SIP_TLS": 5061,
    "BGP": 179
}


def const_value(const: str) -> int:
    return const_list.get(const, 0)
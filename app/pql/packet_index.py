from packet.layers.packet_decode import PacketDecode

ETHERNET = 0x01
IPv4 = 0x02
IPv6 = 0x04
ICMP = 0x08
UDP = 0x10
TCP = 0x20
ARP = 0x40
DNS = 0x80
DHCP = 0x100
HTTPS = 0x200
SSH = 0x400
RDP = 0x800
TELNET = 0x1000
SMTP = 0x2000
IMAP = 0x4000
IMAPS = 0x8000
POP3 = 0x10000
POP3S = 0x20000
SNMP = 0x40000
FTP = 0x80000
HTTP = 0x100000
NTP = 0x200000
RTP = 0x400000
RTCP = 0x800000
SIP = 0x1000000
SIP_TLS = 0x2000000
BGP = 0x4000000
SMB = 0x8000000
ICMP_UNREACHABLE = 0x10000000


def packet_index(pd: PacketDecode) -> int:
    pindex = 0

    if pd.has_ethernet:
        pindex = pindex + ETHERNET
    if pd.has_arp:
        pindex = pindex + ARP
    if pd.has_ipv4:
        pindex = pindex + IPv4
    if pd.has_icmp_unreachable:
        pindex = pindex + ICMP_UNREACHABLE
    if pd.has_icmp:
        pindex = pindex + ICMP
    if pd.has_udp:
        pindex = pindex + UDP

    if pd.has_dns:
        pindex = pindex + DNS
    if pd.has_dhcp:
        pindex = pindex + DHCP
    if pd.has_ntp:
        pindex = pindex + NTP
    if pd.has_rtp:
        pindex = pindex + RTP
    if pd.has_rtcp:
        pindex = pindex + RTCP

    if pd.has_tcp:
        pindex = pindex + TCP

    if pd.has_https:
        pindex = pindex + HTTPS
    if pd.has_ssh:
        pindex = pindex + SSH
    if pd.has_rdp:
        pindex = pindex + RDP
    if pd.has_telnet:
        pindex = pindex + TELNET
    if pd.has_smtp:
        pindex = pindex + SMTP
    if pd.has_imap:
        pindex = pindex + IMAP
    if pd.has_imaps:
        pindex = pindex + IMAPS
    if pd.has_pop3:
        pindex = pindex + POP3
    if pd.has_pop3s:
        pindex = pindex + POP3S
    if pd.has_snmp:
        pindex = pindex + SNMP
    if pd.has_ftp:
        pindex = pindex + FTP
    if pd.has_http:
        pindex = pindex + HTTP
    if pd.has_bgp:
        pindex = pindex + BGP

    if pd.has_sip:
        pindex = pindex + SIP
    if pd.has_siptls:
        pindex = pindex + SIP_TLS
    if pd.has_smb:
        pindex = pindex + SMB

    return pindex


def build_search_index(index_set: set[int]) -> int:
    pindex = 0

    if 'ETH' in index_set:
        pindex = pindex + ETHERNET
    if 'ARP' in index_set:
        pindex = pindex + ARP
    if 'IP' in index_set:
        pindex = pindex + IPv4
    if 'ICMP' in index_set:
        pindex = pindex + ICMP
    if 'UDP' in index_set:
        pindex = pindex + UDP
    if 'TCP' in index_set:
        pindex = pindex + TCP
    if 'DNS' in index_set:
        pindex = pindex + DNS
    if 'DHCP' in index_set:
        pindex = pindex + DHCP
    if 'HTTPS' in index_set:
        pindex = pindex + HTTPS
    if 'SSH' in index_set:
        pindex = pindex + SSH
    if 'RDP' in index_set:
        pindex = pindex + RDP
    if 'TELNET' in index_set:
        pindex = pindex + TELNET
    if 'SMTP' in index_set:
        pindex = pindex + SMTP
    if 'IMAP' in index_set:
        pindex = pindex + IMAP
    if 'IMAPS' in index_set:
        pindex = pindex + IMAPS
    if 'POP3' in index_set:
        pindex = pindex + POP3
    if 'POP3S' in index_set:
        pindex = pindex + POP3S
    if 'SNMP' in index_set:
        pindex = pindex + SNMP
    if 'FTP' in index_set:
        pindex = pindex + FTP
    if 'HTTP' in index_set:
        pindex = pindex + HTTP
    if 'NTP' in index_set:
        pindex = pindex + NTP
    if 'RTP' in index_set:
        pindex = pindex + RTP
    if 'RTCP' in index_set:
        pindex = pindex + RTCP
    if 'SIP' in index_set:
        pindex = pindex + SIP
    if 'SIP_TLS' in index_set:
        pindex = pindex + SIP_TLS
    if 'BGP' in index_set:
        pindex = pindex + BGP
    if 'SMB' in index_set:
        pindex = pindex + SMB

    print(f"Search index: {pindex:x} in {index_set}")
    return pindex

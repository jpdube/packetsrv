import logging
from struct import unpack
from typing import List

from packet.layers.fields import IPv4Address
from packet.layers.packet_hdr import PktHeader
from packet.utils.print_hex import HexDump

log = logging.getLogger("packetdb")

FRAME_TYPE_8021Q = 0x8100
FRAME_TYPE_IPV4 = 0x0800
FRAME_TYPE_IPV6 = 0x86DD
FRAME_TYPE_ARP = 0x0806

ETHER_TYPE_LIST = [
    0x0800, 0x0806, 0x0842, 0x22F0, 0x22F3, 0x22EA, 0x6002,
    0x6003, 0x6004, 0x8035, 0x809B, 0x80F3, 0x8100, 0x8102,
    0x8103, 0x8137, 0x8204, 0x86DD, 0x8808, 0x8809, 0x8819,
    0x8847, 0x8848, 0x8863, 0x8864, 0x887B, 0x888E, 0x8892,
    0x889A, 0x88A2, 0x88A4, 0x88A8, 0x88AB, 0x88B8, 0x88B9,
    0x88BA, 0x88BF, 0x88CC, 0x88CD, 0x88E1, 0x88E3, 0x88E5,
    0x88E7, 0x88F7, 0x88F8, 0x88FB, 0x8902, 0x8906, 0x8914,
    0x8915, 0x891D, 0x893a, 0x892F, 0x9000, 0xF1C1
]


class PacketDecode:

    __slots__ = ["packet", "header", "offset"]

    def __init__(self):
        self.packet = bytes()
        self.header = None
        self.offset = 0

    def decode(self, header: PktHeader, packet):
        self.header = header
        self.packet = packet
        # self.packet = memoryview(packet)
        self.offset = 18 if self.has_vlan else 14

    def get_byte_field(self, field_name: str, offset: int, length: int) -> bytes | None:
        if field_name == "eth":
            return self.eth_packet(offset, length)
        elif field_name == "ip":
            return self.ipv4_packet(offset, length)
        elif field_name == "tcp":
            return self.tcp_packet(offset, length)

        return None

    def get_field(self, field_name: str) -> int:
        (proto, field) = field_name.split(".")
        if proto == "pkt":
            return self.search_pkt(field)
        elif proto == "eth":
            return self.search_eth(field)
        elif proto == "ip":
            return self.search_ipv4(field)
        elif proto == "tcp":
            return self.search_tcp(field)
        elif proto == "udp":
            return self.search_udp(field)
        elif proto == "arp":
            return self.search_arp(field)
        else:
            return False

    @property
    def has_vlan(self):
        return unpack("!H", self.packet[12:14])[0] == FRAME_TYPE_8021Q

    def search_pkt(self, field: str) -> int:

        if field == "timestamp":
            return self.timestamp

        elif field == "ts_offset":
            return self.ts_offset

        elif field == "inc_len":
            return self.inc_len

        elif field == "orig_len":
            return self.orig_len

        else:
            return 0

    @property
    def header_len(self) -> int:
        hdr_len = 0
        if self.has_ethernet:
            hdr_len += self.eth_size

        if self.has_ipv4:
            hdr_len += self.ip_hdr_len * 4

        if self.has_tcp:
            hdr_len += self.tcp_offset * 4

        if self.has_udp:
            hdr_len += 8

        return hdr_len

    @property
    def eth_size(self) -> int:
        if self.has_vlan:
            return 18
        else:
            return 14

    def eth_packet(self, offset: int, length: int) -> bytes:
        return self.packet[offset:offset + length]

    def ipv4_packet(self, offset: int, length: int) -> bytes:
        return self.packet[self.offset + offset:self.offset + offset + length]

    def tcp_packet(self, offset: int, length: int) -> bytes:
        pkt_offset = self.offset + (self.ip_hdr_len << 2)
        return self.packet[pkt_offset + offset:pkt_offset + offset + length]
        # hex_dump = HexDump()
        # hex_dump.print_hex(
        #     self.packet[pkt_offset:pkt_offset + pkt_offset + 20])
        # return result

    def search_eth(self, field: str) -> int:
        vlan_flag = self.has_vlan

        if field == "dst":
            return self.mac_dst

        elif field == "src":
            return self.mac_src

        elif field == "type":
            return self.ethertype

        elif field == "vlan":
            if vlan_flag:
                return self.vlan_id
            else:
                return 1

        elif field == "has_vlan":
            return vlan_flag

        else:
            return False

    def search_ipv4(self, field: str) -> int:
        # offset = 18 if self.has_vlan() else 14

        if field == "src":
            return self.ip_src

        elif field == "dst":
            return self.ip_dst

        elif field == "version":
            return self.ip_version

        elif field == "hdr_len":
            return self.ip_hdr_len

        elif field == "tos":
            return self.ip_tos

        elif field == "ttl":
            return self.ip_ttl

        elif field == "proto":
            return self.ip_proto

        else:
            return False

    def search_tcp(self, field: str) -> int:
        if not self.has_tcp:
            return False

        if field == "sport":
            return self.tcp_sport

        elif field == "dport":
            return self.tcp_dport

        elif field == "syn":
            return self.tcp_flag_syn

        elif field == "ack":
            return self.tcp_flag_ack

        elif field == "push":
            return self.tcp_flag_push

        elif field == "fin":
            return self.tcp_flag_fin

        elif field == "urg":
            return self.tcp_flag_urg

        elif field == "rst":
            return self.tcp_flag_rst

        else:
            return False

    def search_udp(self, field: str) -> int:

        if field == "sport":
            return self.udp_sport

        elif field == "dport":
            return self.udp_dport

        elif field == "length":
            return self.udp_length

        elif field == "checksum":
            return self.udp_checksum

        else:
            return 0

    def search_arp(self, field: str) -> int:

        if field == "htype":
            return self.arp_htype

        elif field == "hlen":
            return self.arp_hlen

        elif field == "ptype":
            return self.arp_ptype

        elif field == "plen":
            return self.arp_plen

        elif field == "opcode":
            return self.arp_opcode

        elif field == "sender_mac":
            return self.arp_sender_mac
        elif field == "target_mac":
            return self.arp_target_mac
        elif field == "sender_ip":
            return self.arp_sender_ip
        elif field == "target_ip":
            return self.arp_target_ip

        else:
            return 0

    def get_mac(self, mac_bytes) -> int:
        response = (mac_bytes[0] << 40) & 0x00_00_FF_00_00_00_00_00
        response += (mac_bytes[1] << 32) & 0x00_00_00_FF_00_00_00_00
        response += (mac_bytes[2] << 24) & 0x00_00_00_00_FF_00_00_00
        response += (mac_bytes[3] << 16) & 0x00_00_00_00_00_FF_00_00
        response += (mac_bytes[4] << 8) & 0x00_00_00_00_00_00_FF_00
        response += mac_bytes[5] & 0x00_00_00_00_00_00_00_FF

        return response

    @property
    def has_ethernet(self) -> bool:
        return self.ethertype in (ETHER_TYPE_LIST)

    @property
    def has_ipv4(self) -> bool:
        return self.ethertype == FRAME_TYPE_IPV4

    @property
    def has_arp(self) -> bool:
        return self.ethertype == FRAME_TYPE_ARP

    @property
    def has_tcp(self) -> bool:
        if self.has_ipv4:
            return self.ip_proto == 0x06
        else:
            return False

    @property
    def has_udp(self) -> bool:
        if self.has_ipv4:
            return self.ip_proto == 0x11
        else:
            return False

    @property
    def has_icmp_unreachable(self) -> bool:
        return self.ip_proto == 0x01 and self.ip_payload[0] == 3 and (self.ip_payload[1] == 1 or self.ip_payload[1] == 3)

    @property
    def has_icmp(self) -> bool:
        return self.ip_proto == 0x01

    @property
    def has_dns(self) -> bool:
        if self.has_udp:
            return self.udp_dport == 53 or self.udp_sport == 53
        else:
            return False

    @property
    def has_smb(self) -> bool:
        if self.has_ipv4:
            if self.has_udp and (self.udp_dport == 139 or self.udp_sport == 139):
                return True
            elif self.has_tcp and (self.tcp_dport == 445 or self.tcp_sport == 445):
                return True
            else:
                return False
        else:
            return False

    @property
    def has_dhcp(self) -> bool:
        if self.has_udp:
            return self.udp_dport in [67, 68] or self.udp_sport in [67, 68]
        else:
            return False

    @property
    def has_https(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 443 or self.tcp_sport == 443
        else:
            return False

    @property
    def has_ssh(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 22 or self.tcp_sport == 22
        else:
            return False

    @property
    def has_telnet(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 23 or self.tcp_sport == 23
        else:
            return False

    @property
    def has_rdp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 3389 or self.tcp_sport == 3389
        else:
            return False

    @property
    def has_smtp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 25 or self.tcp_sport == 25
        else:
            return False

    @property
    def has_imap(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 143 or self.tcp_sport == 143
        else:
            return False

    @property
    def has_imaps(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 993 or self.tcp_sport == 993
        else:
            return False

    @property
    def has_pop3(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 110 or self.tcp_sport == 110
        else:
            return False

    @property
    def has_pop3s(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 995 or self.tcp_sport == 995
        else:
            return False

    @property
    def has_ftp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 21 or self.tcp_sport == 21
        else:
            return False

    @property
    def has_http(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport in [80, 8080] or self.tcp_sport in [80, 8080]
        else:
            return False

    @property
    def has_ntp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 123 or self.tcp_sport == 123
        else:
            return False

    @property
    def has_rtp(self) -> bool:
        if self.has_ipv4 and self.has_udp:
            return self.udp_dport == 5004 or self.udp_sport == 5004
        else:
            return False

    @property
    def has_rtcp(self) -> bool:
        if self.has_ipv4 and self.has_udp:
            return self.udp_dport == 5005 or self.udp_sport == 5005
        else:
            return False

    @property
    def has_sip(self) -> bool:
        if self.has_ipv4 and self.has_udp:
            return self.udp_dport == 5060 or self.udp_sport == 5060
        else:
            return False

    @property
    def has_siptls(self) -> bool:
        if self.has_ipv4 and self.has_udp:
            return self.udp_dport == 5061 or self.udp_sport == 5061
        else:
            return False

    @property
    def has_bgp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            return self.tcp_dport == 179 or self.tcp_sport == 179
        else:
            return False

    @property
    def has_snmp(self) -> bool:
        if self.has_ipv4 and self.has_tcp:
            snmp_port = (161, 162)
            return self.tcp_dport in snmp_port or self.tcp_sport in snmp_port or self.udp_dport in snmp_port or self.udp_sport in snmp_port
        else:
            return False

    @property
    def timestamp(self) -> int:
        return self.header.timestamp

    @property
    def ts_offset(self) -> int:
        return self.header.ts_offset

    @property
    def inc_len(self) -> int:
        return self.header.incl_len

    @property
    def orig_len(self) -> int:
        return self.header.orig_len

    @property
    def mac_dst(self) -> int:
        return self.get_mac(self.packet[0:6])

    @property
    def mac_src(self) -> int:
        return self.get_mac(self.packet[6:12])

    @property
    def ethertype(self) -> int:
        if self.has_vlan:
            return unpack("!H", self.packet[16:18])[0]
        else:
            return unpack("!H", self.packet[12:14])[0]

    @property
    def vlan_id(self) -> int:
        if self.has_vlan:
            return unpack("!H", self.packet[14:16])[0] & 0xFFF
        else:
            return 1

    @property
    def ip_payload(self) -> bytes:
        return self.packet[20 + self.offset:]

    @property
    def ip_version(self) -> int:
        return (self.packet[self.offset] & 0xf0) >> 4

    @property
    def ip_hdr_len(self) -> int:
        return (self.packet[self.offset] & 0x0f)

    @property
    def ip_offset(self) -> int:
        return self.offset + (self.ip_hdr_len * 4)

    @property
    def ip_tos(self) -> int:
        return self.packet[self.offset + 1]

    @property
    def ip_ttl(self) -> int:
        return self.packet[self.offset + 8]

    @property
    def ip_src(self) -> int:
        # print(self.offset)
        return unpack("!I", self.packet[self.offset + 12:self.offset + 16])[0]

    @property
    def ip_dst(self) -> int:
        return unpack("!I", self.packet[self.offset + 16:self.offset + 20])[0]

    @property
    def ip_proto(self) -> int:
        return int(self.packet[self.offset + 9])

    @property
    def sport(self) -> int:
        return unpack("!H", self.packet[self.offset + 34:self.offset + 36])[0]

    @property
    def dport(self) -> int:
        return unpack("!H", self.packet[self.offset + 36:self.offset + 38])[0]

    @property
    def tcp_seq_no(self) -> int:
        if self.ip_proto == 0x06:
            return unpack("!I", self.packet[self.ip_offset + 4:self.ip_offset + 8])[0]
        else:
            return 0

    @property
    def tcp_ack_no(self) -> int:
        if self.ip_proto == 0x06:
            return unpack("!I", self.packet[self.ip_offset + 8:self.ip_offset + 12])[0]
        else:
            return 0

    @property
    def tcp_offset(self) -> int:
        if self.ip_proto == 0x06:
            hdr_len = int(self.packet[self.ip_offset + 12])
            hdr_len = (hdr_len >> 4) & 0x0f
            return hdr_len
        else:
            return 0

    @property
    def tcp_flag(self) -> int:
        if self.ip_proto == 0x06:
            flag = unpack(
                "!H", self.packet[self.ip_offset + 12:self.ip_offset + 14])[0]
            return flag
        else:
            return 0

    @property
    def tcp_sport(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 0:self.ip_offset + 2])[0]

    @property
    def tcp_dport(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 2:self.ip_offset + 4])[0]

    @property
    def tcp_flag_syn(self) -> bool:
        if self.ip_proto == 0x06:
            return self.tcp_flag & 0x02 == 0x02
        else:
            return False

    @property
    def tcp_flag_ack(self) -> bool:
        if self.ip_proto == 0x06:
            return (self.tcp_flag & 0x10) == 0x10
        else:
            return False

    @property
    def tcp_flag_push(self) -> bool:
        if self.ip_proto == 0x06:
            return (self.tcp_flag & 0x08) == 0x08
        else:
            return False

    @property
    def tcp_flag_fin(self) -> bool:
        if self.ip_proto == 0x06:
            return (self.tcp_flag & 0x01) == 0x01
        else:
            return False

    @property
    def tcp_flag_urg(self) -> bool:
        if self.ip_proto == 0x06:
            return (self.tcp_flag & 0x20) == 0x20
        else:
            return False

    @property
    def tcp_flag_rst(self) -> bool:
        if self.ip_proto == 0x06:
            return (self.tcp_flag & 0x04) == 0x04
        else:
            return False

    def __str__(self) -> str:
        return f"MacSrc: {self.mac_src:X}, MacDst: {self.mac_dst:X}, Vlan: {self.vlan_id}, IP src: {IPv4Address(self.ip_src)}, IP dst: {IPv4Address(self.ip_dst)} Port:{self.sport}/{self.dport}"

    @property
    def udp_sport(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 0:self.ip_offset + 2])[0]

    @property
    def udp_dport(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 2:self.ip_offset + 4])[0]

    @property
    def udp_length(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 4:self.ip_offset + 6])[0]

    @property
    def udp_checksum(self) -> int:
        return unpack("!H", self.packet[self.ip_offset + 6:self.ip_offset + 8])[0]

    # --- ARP
    @property
    def arp_htype(self) -> int:
        return unpack(
            "!H", self.packet[self.eth_size + 0:self.eth_size + 2])[0]

    @property
    def arp_ptype(self) -> int:
        return unpack(
            "!H", self.packet[self.eth_size + 2:self.eth_size + 4])[0]

    @property
    def arp_hlen(self) -> int:
        return self.packet[self.eth_size + 4]

    @property
    def arp_plen(self) -> int:
        return self.packet[self.eth_size + 5]

    @property
    def arp_opcode(self) -> int:
        return unpack(
            "!H", self.packet[self.eth_size + 6:self.eth_size + 8])[0]

    @property
    def arp_sender_mac(self):
        return self.packet[self.eth_size + 8:self.eth_size + 14]

    @property
    def arp_sender_ip(self) -> int:
        return unpack("!I", self.packet[self.eth_size + 14:self.eth_size + 18])[0]

    @property
    def arp_target_mac(self) -> int:
        return self.packet[self.eth_size + 18:self.eth_size + 24]

    @property
    def arp_target_ip(self) -> int:
        return unpack("!I", self.packet[self.eth_size + 18:self.eth_size + 24])[0]

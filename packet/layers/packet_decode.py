from struct import unpack
from packet.layers.fields import IPv4Address

FRAME_TYPE_8021Q = 0x8100


class PacketDecode:

    # __slots__ = ["packet", "offset"]

    def __init__(self):
        self.packet = bytes()
        self.header = bytes()
        self.offset = 0

    def decode(self, header: bytes, packet: bytes):
        self.header = header
        self.packet = packet
        self.offset = 18 if self.has_vlan else 14
        # print_hex(self.packet)

    def get_field(self, field_name: str) -> int:
        # def search_field(self, field_name: str, value: int) -> bool:
        (proto, field) = field_name.split(".")
        match proto:
            case "eth":
                return self.search_eth(field)
            case "ip":
                return self.search_ipv4(field)
            case "tcp":
                return self.search_tcp(field)
            case "udp":
                return self.search_udp(field)
            case _:
                return False

    @property
    def has_vlan(self):
        return unpack("!H", self.packet[12:14])[0] == FRAME_TYPE_8021Q

    def search_eth(self, field: str) -> int:
        vlan_flag = self.has_vlan

        match field:
            case "dst":
                return self.mac_dst

            case "src":
                return self.mac_src

            case "type":
                return self.ethertype

            case "vlan":
                if vlan_flag:
                    return self.vlan_id
                else:
                    return 1

            case "has_vlan":
                return vlan_flag

            case _:
                return False

    def search_ipv4(self, field: str) -> int:
        # offset = 18 if self.has_vlan() else 14

        match field:
            case "src":
                return self.ip_src

            case "dst":
                return self.ip_dst

            case "version":
                return self.ip_version

            case "hdr_len":
                return self.ip_hdr_len

            case "tos":
                return self.ip_tos

            case "ttl":
                return self.ip_ttl

            case "proto":
                return self.ip_proto

            case _:
                return False

    def search_tcp(self, field: str) -> int:
        # offset = 18 if self.has_vlan() else 14

        match field:
            case "sport":
                return self.tcp_sport

            case "dport":
                return self.tcp_dport

            case "syn":
                return self.tcp_flag_syn

            case "ack":
                return self.tcp_flag_ack

            case "push":
                return self.tcp_flag_push

            case "fin":
                return self.tcp_flag_fin

            case "urg":
                return self.tcp_flag_urg

            case "rst":
                return self.tcp_flag_rst

            case _:
                return False

    def search_udp(self, field: str) -> int:
        # offset = 18 if self.has_vlan() else 14

        match field:
            case "sport":
                return self.udp_sport

            case "dport":
                return self.udp_dport

            case "length":
                return self.udp_length

            case "checksum":
                return self.udp_checksum

            case _:
                return 0

    def get_mac(self, mac_bytes) -> int:
        response = (mac_bytes[0] << 40) & 0x00_00_FF_00_00_00_00_00
        response += (mac_bytes[1] << 32) & 0x00_00_00_FF_00_00_00_00
        response += (mac_bytes[2] << 24) & 0x00_00_00_00_FF_00_00_00
        response += (mac_bytes[3] << 16) & 0x00_00_00_00_00_FF_00_00
        response += (mac_bytes[4] << 8) & 0x00_00_00_00_00_00_FF_00
        response += mac_bytes[5] & 0x00_00_00_00_00_00_00_FF

        return response

    # @property
    # def offset(self) -> int:
    #     return 18 if self.has_vlan else 14

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
            # print_hex(self.packet)
            return unpack("!I", self.packet[self.ip_offset + 4:self.ip_offset + 8])[0]
        else:
            return 0

    @property
    def tcp_ack_no(self) -> int:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            return unpack("!I", self.packet[self.ip_offset + 8:self.ip_offset + 12])[0]
        else:
            return 0

    @property
    def tcp_flag(self) -> int:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            flag = unpack(
                "!H", self.packet[self.ip_offset + 12:self.ip_offset + 14])[0]
            # print(f"EO: {self.offset}, IPO: {self.ip_offset}, FLAG: {flag:x}")
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
            # print_hex(self.packet)
            return (self.tcp_flag & 0x10) == 0x10
        else:
            return False

    @property
    def tcp_flag_push(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            return (self.tcp_flag & 0x08) == 0x08
        else:
            return False

    @property
    def tcp_flag_fin(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            return (self.tcp_flag & 0x01) == 0x01
        else:
            return False

    @property
    def tcp_flag_urg(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            return (self.tcp_flag & 0x20) == 0x20
        else:
            return False

    @property
    def tcp_flag_rst(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
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

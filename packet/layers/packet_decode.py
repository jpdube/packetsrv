from struct import unpack

FRAME_TYPE_8021Q = 0x8100


class PacketDecode:

    # __slots__ = ["packet", "offset"]

    def __init__(self):
        self.packet = bytes()
        self.offset = 0

    def decode(self, packet: bytes):
        self.packet = packet
        self.offset = 18 if self.has_vlan else 14
        # print_hex(self.packet)

    def search_field(self, field_name: str, value: int) -> bool:
        (proto, field) = field_name.split(".")
        match proto:
            case "eth":
                return self.search_eth(field, value)
            case "ip":
                return self.search_ipv4(field, value)
            case _:
                return False

    @property
    def has_vlan(self):
        return unpack("!H", self.packet[12:14])[0] == FRAME_TYPE_8021Q

    def search_eth(self, field: str, value: int) -> bool:
        vlan_flag = self.has_vlan

        match field:
            case "dst":
                return self.mac_dst == value

            case "src":
                return self.mac_src == value

            case "type":
                return self.ethertype == value

            case "vlan":
                if vlan_flag:
                    return self.vlan_id == value
                else:
                    return False

            case _:
                return False

    def search_ipv4(self, field: str, value: int) -> bool:
        # offset = 18 if self.has_vlan() else 14

        match field:
            case "src":
                return self.ip_src == value

            case "dst":
                return self.ip_dst == value

            case _:
                return False

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
            return unpack("!H", self.packet[14:16])[0]
        else:
            return 1

    @property
    def ip_version(self) -> int:
        return (self.packet[self.offset] & 0xf0) >> 4

    @property
    def ip_hdr_len(self) -> int:
        return (self.packet[self.offset] & 0x0f) * 4

    @property
    def ip_offset(self) -> int:
        # print(f"V:{self.ip_version}, HL:{self.ip_hdr_len}")
        return self.offset + self.ip_hdr_len

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
    def tcp_flag_syn(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            print(self.offset)
            return (unpack("!H", self.packet[self.ip_offset + 12:self.ip_offset + 14])[0] & 0x20) == 0x20
        else:
            return False

    @property
    def tcp_flag_ack(self) -> bool:
        if self.ip_proto == 0x06:
            # print_hex(self.packet)
            return (unpack("!H", self.packet[self.ip_offset + 12:self.ip_offset + 14])[0] & 0x10) == 0x10
        else:
            return False

from struct import unpack

FRAME_TYPE_8021Q = 0x8100


class PacketDecode:

    __slots__ = ["packet"]

    def __init__(self):
        self.packet = bytes()

    def search_field(self, field_name: str, value: int) -> bool:
        (proto, field) = field_name.split(".")
        match proto:
            case "eth":
                return self.search_eth(field, value)
            case "ip":
                return self.search_ipv4(field, value)
            case _:
                return False

    def has_vlan(self):
        return unpack("!H", self.packet[12:14])[0] == FRAME_TYPE_8021Q

    def search_eth(self, field: str, value: int) -> bool:
        vlan_flag = self.has_vlan()

        match field:
            case "dst":
                return unpack("!L", self.packet[0:6])[0] == value

            case "src":
                return unpack("!L", self.packet[6:12])[0] == value

            case "type":
                if vlan_flag:
                    return unpack("!H", self.packet[16:18])[0] == value
                else:
                    return unpack("!H", self.packet[12:14])[0] == value

            case "vlan":
                if vlan_flag:
                    return unpack("!H", self.packet[12:14])[0] == value
                else:
                    return False

            case _:
                return False

    def search_ipv4(self, field: str, value: int) -> bool:
        offset = 18 if self.has_vlan() else 14

        match field:
            case "src":
                return unpack("!I", self.packet[offset + 12:offset + 16])[0] == value

            case "dst":
                return unpack("!I", self.packet[offset + 16:offset + 20])[0] == value

            case _:
                return False

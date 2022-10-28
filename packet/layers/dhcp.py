from packet.layers.fields import IPv4Address, MacAddress
from struct import unpack
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet
from typing import Tuple


params_req_list = {
    1: "Subnet mask",
    2: "Time offset",
    3: "Router",
    6: "Domain name server",
    7: "Log server",
    15: "Domain name",
    31: "Perform router discover",
    33: "Static route",
    35: "ARP cache timeout",
    42: "NTP Network time protocol",
    43: "Vendor specific information",
    44: "NetBIOS over TCP/IP name server",
    46: "NetBIOS over TCP/IP node type",
    47: "NetBIOS over TCP/IP scope",
    58: "Renewal time value",
    59: "Rebinding time value",
    66: "TFTP server name",
    119: "Domain search",
    121: "Classless staic route",
    150: "TFTP server address",
    159: "Portparams",
    160: "Unassigned (ex DHCP Captive-Portal)",
    249: "Private/Classless static route (Microsoft)",
    252: "Private/Proxy autodiscovery",
}


def print_bytes(bytes_list):
    result = ""
    for i, b in enumerate(bytes_list):
        result += f"{b:02x}"
        if i < len(bytes_list) - 1:
            result += ","
    return result


class DHCPOption:
    def __init__(self, opt_len, option, option_no, option_name):
        self.opt_len = opt_len
        self.option = option
        self.option_no = option_no
        self.option_name = option_name

    def decode(self):
        pass

    def summary(self, offset: int) -> str:
        return ""

    def __str__(self) -> str:
        return f"{self.option_no:02}: {self.option_name} -> "


# 5303
class Request(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 3, "DHCP request")

    def __str__(self) -> str:
        return f"{super().__str__()}53{self.opt_len:02}{self.option[0]:02}"


# 5305
class Ack(DHCPOption):
    def __init__(self, option_len, option):
        super().__init__(option_len, option, 5, "DHCP Ack")

    def __str__(self) -> str:
        return f"{super().__str__()}53{self.opt_len:02}{self.option[0]:02}"


# 54
class ServerIP(DHCPOption):
    pass


# 1
class Netmask(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 1, "Subnet mask")
        self.mask = 0

        self.decode()

    def decode(self):
        self.mask = IPv4Address(self.option)

    def __str__(self) -> str:
        return f"{super().__str__()}{self.mask}"


# 3
class Router(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 3, "Router")
        self.router_list = []

        self.decode()

    def decode(self):
        nbr_router = int(self.opt_len / 4)
        offset = 0

        for _ in range(nbr_router):
            # if offset + 4 < len(self.option):
            ip = IPv4Address(self.option[offset : offset + 4])
            self.router_list.append(ip)
            offset += 4

    def __str__(self) -> str:
        result = f"{super().__str__()}"
        for i, r in enumerate(self.router_list):
            result += f"{i}: {r}"
            if i < len(self.router_list) - 1:
                result += ', '

        return result

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 6
class DomainNameServer(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 6, "Domain name server")
        self.dns_list = []

        self.decode()

    def decode(self):
        nbr_dns = int(self.opt_len / 4)
        offset = 0
        for _ in range(nbr_dns):
            ip = IPv4Address(self.option[offset : offset + 4])
            self.dns_list.append(ip)
            offset += 4

    def __str__(self) -> str:
        result = f"{super().__str__()}"
        for i, r in enumerate(self.dns_list):
            result += f"{i}: {r}"
            if i < len(self.dns_list) - 1:
                result += ', '

        return result

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 12
class Hostname(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 12, "Host Name")
        self.hostname = ""

        self.decode()

    def decode(self):
        self.hostname = unpack(f"!{self.opt_len}s", self.option)[0].decode("utf-8")

    def __str__(self) -> str:
        return f"{super().__str__()}{self.hostname}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 15
class DomainName(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 15, "Domain name")
        self.domain_name = ""

        self.decode()

    def decode(self):
        self.domain_name = unpack(f"!{self.opt_len - 1}s", self.option[:-1])[0].decode(
            "utf-8"
        )

    def __str__(self) -> str:
        return f"{super().__str__()}{self.domain_name}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 50
class RequestedIPAddr(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 50, "Requested IP address")
        self.ip_address = None

        self.decode()

    def decode(self):
        self.ip_address = IPv4Address(self.option)

    def __str__(self) -> str:
        return f"{super().__str__()}{self.ip_address}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 51
class IPAddrLeaseTime(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 51, "IP Address lease time")
        self.time = 0

        self.decode()

    def decode(self):
        self.time = unpack("!I", self.option)[0] / 3600

    def __str__(self) -> str:
        return f"{super().__str__()}{self.time}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 55
class ParamReqList(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 55, "Parameter request list")
        self.params = []

        self.decode()

    def decode(self):
        self.params = unpack(f"!{self.opt_len}B", self.option)

    def __str__(self) -> str:
        result = ""
        for i,p in enumerate(self.params):
            result += f'{p:03}:{params_req_list.get(p, "Undefined param")}'
            if i < len(self.params) - 1:
                result += ', '

        return f"{super().__str__()} {result}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 58
class RenewalTime(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 58, "Renewal time")
        self.time = 0

        self.decode()

    def decode(self):
        self.time = unpack("!I", self.option)[0] / 3600

    def __str__(self) -> str:
        return f"{super().__str__()}{self.time}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 59
class RebindingTime(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 59, "Rebinding time value")
        self.time = 0

        self.decode()

    def decode(self):
        self.time = unpack("!I", self.option)[0] / 3600

    def __str__(self) -> str:
        return f"{super().__str__()}{self.time}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 60
class VendorClassId(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 60, "Vendor class identifier")
        self.vci = ""

        self.decode()

    def decode(self):
        self.vci = unpack(f"!{self.opt_len - 1}s", self.option[:-1])[0].decode("utf-8")

    def __str__(self) -> str:
        return f"{super().__str__()}{self.vci}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 61
class ClientIdentifier(DHCPOption):
    def __init__(self, opt_len: int, option) -> None:
        super().__init__(opt_len, option, 61, "Client identifier")
        self.hw_type = 0x01
        self.mac_addr = None

        self.decode()

    def decode(self):
        self.hw_type = unpack("!B", self.option[0:1])[0]
        self.mac_addr = MacAddress(self.option[1:7])

    def __str__(self) -> str:
        return f"{super().__str__()}Hw Type: {self.hw_type}, Mac: {self.mac_addr}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 81
class ClientFQDN(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 81, "Client fully qualified domain name")
        self.fqdn = ""
        self.flag = 0
        self.a_rr = 0
        self.ptr_rr = 0

        self.decode()

    def decode(self):
        self.flag = unpack("!B", self.option[0:1])[0]
        self.a_rr = unpack("!B", self.option[1:2])[0]
        self.ptr_rr = unpack("!B", self.option[2:3])[0]
        self.fqdn = unpack(f"!{self.opt_len - 3}s", self.option[3:])[0].decode("utf-8")

    def __str__(self) -> str:
        return f"{super().__str__()}Flag: {self.flag} A-RR: {self.a_rr} PTR-RR: {self.ptr_rr} FQDN: {self.fqdn}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 125
class VendorSpecInfo(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 125, "V-I Vendor specific info")
        self.vci = []

        self.decode()

    def decode(self):
        self.vci = unpack(f"!{self.opt_len}B", self.option)

    def __str__(self) -> str:
        return f"{super().__str__()}{self.vci}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}   {self.__str__()}\n'
        return result


# 255
class End(DHCPOption):
    pass


class MagicCookie(DHCPOption):
    pass


class Dhcp(Packet):
    name = LayerID.DHCP

    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet
        self.option_list = []
        self.index = 0

        self.get_options()

    def fetch(self) -> Tuple[int, int, list]:
        option_id = 0xFF
        option_len = 0
        option_data = []

        if self.index < len(self.packet) - 1:
            option_id, option_len = unpack(
                "!BB", self.packet[self.index : self.index + 2]
            )
            self.index += 2

            option_data = self.packet[self.index : self.index + option_len]
            self.index += option_len

        return (option_id, option_len, option_data)

    def get_options(self) -> None:
        self.index = 0xF0
        while True:
            option_id, option_len, option_data = self.fetch()

            if option_id == 0xFF:
                break

            if option_id == 0x35:
                if option_data[0] == 0x05:
                    ack = Ack(option_len, option_data)
                    self.option_list.append(ack)
                elif option_data[0] == 0x03:
                    req = Request(option_len, option_data)
                    self.option_list.append(req)

            elif option_id == 0x03:
                response = Router(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x0C:
                response = Hostname(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x37:
                response = ParamReqList(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x3A:
                response = RenewalTime(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x3B:
                response = RebindingTime(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x3C:
                response = VendorClassId(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x7D:
                response = VendorSpecInfo(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x3D:
                response = ClientIdentifier(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x32:
                response = RequestedIPAddr(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x33:
                response = IPAddrLeaseTime(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x01:
                response = Netmask(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x51:
                response = ClientFQDN(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x06:
                response = DomainNameServer(option_len, option_data)
                self.option_list.append(response)

            elif option_id == 0x0F:
                response = DomainName(option_len, option_data)
                self.option_list.append(response)

    @property
    def msg_type(self) -> int:
        return unpack("!B", self.packet[0:1])[0]

    @property
    def htype(self) -> int:
        return unpack("!B", self.packet[1:2])[0]

    @property
    def hlen(self) -> int:
        return unpack("!B", self.packet[2:3])[0]

    @property
    def hops(self) -> int:
        return unpack("!B", self.packet[3:4])[0]

    @property
    def xid(self) -> int:
        return unpack("!L", self.packet[4:8])[0]

    @property
    def sec(self) -> int:
        return unpack("!H", self.packet[8:10])[0]

    @property
    def flags(self) -> int:
        return unpack("!H", self.packet[10:12])[0]

    @property
    def ciaddr(self) -> IPv4Address:
        return IPv4Address(self.packet[12:16])

    @property
    def yiaddr(self) -> IPv4Address:
        return IPv4Address(self.packet[16:20])

    @property
    def siaddr(self) -> IPv4Address:
        return IPv4Address(self.packet[20:24])

    @property
    def giaddr(self) -> IPv4Address:
        return IPv4Address(self.packet[24:28])

    @property
    def chaddr(self) -> MacAddress:
        return MacAddress(self.packet[28:44])

    @property
    def sname(self) -> str:
        return str(self.packet[44:108])

    @property
    def filename(self) -> str:
        return str(self.packet[108:236])

    # """    
    # 00e0: 00 00 00 00 00 00 00 00  00 00 00 00 63 82 53 63   ············c·Sc
    # 00f0: 35 01 05 3a 04 00 03 f4  80 3b 04 00 06 eb e0 33   5··:·····;·····3
    # 0100: 04 00 07 e9 00 36 04 c0  a8 03 e6 01 04 ff ff ff   ·····6··········
    # 0110: 00 51 03 03 ff 00 03 04  c0 a8 03 01 06 08 c0 a8   ·Q··············
    # 0120: 03 e6 c0 a8 02 e6 0f 0e  6c 61 6c 6c 69 65 72 2e   ········lallier.
    # 0130: 6c 6f 63 61 6c 00 ff                               local··
    # """

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}DHCP ->\n'
        result += f'{" " * offset}   Opcode.....: {self.msg_type}\n'

        for opt in self.option_list:
            result += opt.summary(offset)

        return result

    def get_field(self, fieldname: str) -> int | str | None:
        ...

    def __str__(self):
        result = f"DHCP -> Opcode: {self.msg_type}, Xid: {self.xid:x}, Lease sec: {self.sec}\n{format_hex(self.packet)}\n********\n"
        for opt in self.option_list:
            result += f" {opt}\n"
        return result

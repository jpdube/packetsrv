"""  
   0               1               2               3
   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)  |
   +---------------+---------------+---------------+-------------+
   |                            xid (4)                          |
   +-------------------------------+-----------------------------+
   |           secs (2)            |           flags (2)         |
   +-------------------------------+-----------------------------+
   |                          ciaddr  (4)                        |
   +-------------------------------------------------------------+
   |                          yiaddr  (4)                        |
   +-------------------------------------------------------------+
   |                          siaddr  (4)                        |
   +-------------------------------------------------------------+
   |                          giaddr  (4)                        |
   +-------------------------------------------------------------+
   |                                                             |
   |                          chaddr  (16)                       |
   |                                                             |
   |                                                             |
   +-------------------------------------------------------------+
   |                                                             |
   |                          sname   (64)                       |
   +-------------------------------------------------------------+
   |                                                             |
   |                          file    (128)                      |
   +-------------------------------------------------------------+
   |                                                             |
   |                          options (variable)                 |
   +-------------------------------------------------------------+

   DHCP defines a new 'client identifier' option that is used to pass an
   explicit client identifier to a DHCP server.  This change eliminates
   the overloading of the 'chaddr' field in BOOTP messages, where
   'chaddr' is used both as a hardware address for transmission of BOOTP
   reply messages and as a client identifier.  The 'client identifier'
   is an opaque key, not to be interpreted by the server; for example,
   the 'client identifier' may contain a hardware address, identical to
   the contents of the 'chaddr' field, or it may contain another type of
   identifier, such as a DNS name.  The 'client identifier' chosen by a
   DHCP client MUST be unique to that client within the subnet to which
   the client is attached. If the client uses a 'client identifier' in
   one message, it MUST use that same identifier in all subsequent
   messages, to ensure that all servers correctly identify the client.

   DHCP clarifies the interpretation of the 'siaddr' field as the
   address of the server to use in the next step of the client's
   bootstrap process.  A DHCP server may return its own address in the
   'siaddr' field, if the server is prepared to supply the next
   bootstrap service (e.g., delivery of an operating system executable
   image).  A DHCP server always returns its own address in the 'server
   identifier' option.

   FIELD      OCTETS       DESCRIPTION
   -----      ------       -----------

   op            1  Message op code / message type.
                    1 = BOOTREQUEST, 2 = BOOTREPLY
   htype         1  Hardware address type, see ARP section in "Assigned
                    Numbers" RFC; e.g., '1' = 10mb ethernet.
   hlen          1  Hardware address length (e.g.  '6' for 10mb
                    ethernet).
   hops          1  Client sets to zero, optionally used by relay agents
                    when booting via a relay agent.
   xid           4  Transaction ID, a random number chosen by the
                    client, used by the client and server to associate
                    messages and responses between a client and a
                    server.
   secs          2  Filled in by client, seconds elapsed since client
                    began address acquisition or renewal process.
   flags         2  Flags (see figure 2).
   ciaddr        4  Client IP address; only filled in if client is in
                    BOUND, RENEW or REBINDING state and can respond
                    to ARP requests.
   yiaddr        4  'your' (client) IP address.
   siaddr        4  IP address of next server to use in bootstrap;
                    returned in DHCPOFFER, DHCPACK by server.
   giaddr        4  Relay agent IP address, used in booting via a
                    relay agent.
   chaddr       16  Client hardware address.
   sname        64  Optional server host name, null terminated string.
   file        128  Boot file name, null terminated string; "generic"
                    name or null in DHCPDISCOVER, fully qualified
                    directory-path name in DHCPOFFER.
   options     var  Optional parameters field.  See the options
                    documents for a list of defined options.

   The 'options' field is now variable length. A DHCP client must be
   prepared to receive DHCP messages with an 'options' field of at least
   length 312 octets.  This requirement implies that a DHCP client must
   be prepared to receive a message of up to 576 octets, the minimum IP
"""

from ctypes import resize
from packet.layers.fields import IPv4Address, MacAddress
from struct import unpack
from packet.layers.ip import IP
from packet.layers.packet import Packet
from packet.utils.print_hex import format_hex, print_hex
from typing import List, Tuple
from datetime import datetime

params_req_list = {
    1:      'Subnet mask',
    2:      'Time offset',
    3:      'Router',
    6:      'Domain name server',
    7:      'Log server',
    15:     'Domain name',
    31:     'Perform router discover',
    33:     'Static route',
    35:     'ARP cache timeout',
    42:     'NTP Network time protocol',
    43:     'Vendor specific information',
    44:     'NetBIOS over TCP/IP name server',
    46:     'NetBIOS over TCP/IP node type',
    47:     'NetBIOS over TCP/IP scope',
    58:     'Renewal time value',
    59:     'Rebinding time value',
    66:     'TFTP server name',
    119:    'Domain search',
    121:    'Classless staic route',
    150:    'TFTP server address',
    159:    'Portparams',
    160:    'Unassigned (ex DHCP Captive-Portal)',
    249:    'Private/Classless static route (Microsoft)',
    252:    'Private/Proxy autodiscovery'
}


def print_bytes(bytes_list):
    result = ''
    for i, b in enumerate(bytes_list):
        result += f'{b:02x}'
        if i < len(bytes_list) - 1:
            result += ','
    return result    

class DHCPOption:
    def __init__(self, opt_len, option, option_no, option_name):
        self.opt_len = opt_len
        self.option = option
        self.option_no = option_no
        self.option_name = option_name

    def decode(self):
        pass

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
            result += f"{i}: {r}, "

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
            result += f"{i}: {r}, "

        return result


# 12
class Hostname(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 12, "Host Name")
        self.hostname = ""

        self.decode()

    def decode(self):
        self.hostname = unpack(f"!{self.opt_len}s", self.option)[0].decode(
            "utf-8"
        )

    def __str__(self) -> str:
        return f"{super().__str__()}{self.hostname}"


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

# 55
class ParamReqList(DHCPOption):
    def __init__(self, opt_len, option):
        super().__init__(opt_len, option, 55, 'Parameter request list')
        self.params = []

        self.decode()

    def decode(self):
        self.params = unpack(f"!{self.opt_len}B", self.option)

    def __str__(self) -> str:
        result = ''
        for p in self.params:
            result += f'{p:03} {params_req_list.get(p, "Undefined param")}\n'

        return f"{super().__str__()}\n{result}"

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
        self.flag = unpack('!B', self.option[0:1])[0]
        self.a_rr = unpack('!B', self.option[1:2])[0]
        self.ptr_rr = unpack('!B', self.option[2:3])[0]
        self.fqdn = unpack(f'!{self.opt_len - 3}s', self.option[3:])[0].decode('utf-8') 

    def __str__(self) -> str:
        return f"{super().__str__()}Flag: {self.flag} A-RR: {self.a_rr} PTR-RR: {self.ptr_rr} FQDN: {self.fqdn}"


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


# 255
class End(DHCPOption):
    pass


class MagicCookie(DHCPOption):
    pass


class Dhcp(Packet):
    name = 5
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

    # @property
    # def magic_no(self) -> int:
    #     return unpack('!I', self.packet[0xec:0xf0])[0]
    #
    # @property
    # def opcode(self) -> int:
    #     return unpack('!B', self.packet[0xf2:0xf3])[0]
    #
    # @property
    # def has_ack(self) -> bool:
    #     return self.packet[0xf2] == 0x05
    #
    # @property
    # def server_ip(self) -> IPv4Address:
    #     if self.has_ack and self.packet[0xf3] == 0x36:
    #         nbr_ip = self.packet[0xf3] / 4
    #         return IPv4Address(self.packet[0xf5:0xfa])
    #     else:
    #         return IPv4Address(0)
    #
    # @property
    # def netmask(self) -> IPv4Address:
    #     if self.has_ack and self.packet[0xf9] == 0x01:
    #         nbr_ip = self.packet[0xfa] / 4
    #         return IPv4Address(self.packet[0xfb:0xff])
    #     else:
    #         return IPv4Address(0)
    #
    # @property
    # def gateway(self) -> IPv4Address:
    #     if self.has_ack and self.packet[0x106] == 0x03:
    #         nbr_ip = self.packet[0x107] / 4
    #         return IPv4Address(self.packet[0x108:0x10c])
    #     else:
    #         return IPv4Address(0)
    #
    # @property
    # def dns_servers(self) -> List[IPv4Address]:
    #     dns_list = []
    #     if self.has_ack and self.packet[0x10c] == 0x06:
    #
    #         nbr_ip = self.packet[0x10d] / 4
    #         print(f'*** NBR IP: {nbr_ip}')
    #         offset = 0
    #         for i in range(int(nbr_ip)):
    #             dns_ip = IPv4Address(self.packet[0x10e + offset:0x10e + offset + 4])
    #             dns_list.append(dns_ip)
    #             offset += 4
    #
    #         return dns_list
    #     else:
    #         return [IPv4Address(0)]
    #
    """    
    00e0: 00 00 00 00 00 00 00 00  00 00 00 00 63 82 53 63   ············c·Sc
    00f0: 35 01 05 3a 04 00 03 f4  80 3b 04 00 06 eb e0 33   5··:·····;·····3
    0100: 04 00 07 e9 00 36 04 c0  a8 03 e6 01 04 ff ff ff   ·····6··········
    0110: 00 51 03 03 ff 00 03 04  c0 a8 03 01 06 08 c0 a8   ·Q··············
    0120: 03 e6 c0 a8 02 e6 0f 0e  6c 61 6c 6c 69 65 72 2e   ········lallier.
    0130: 6c 6f 63 61 6c 00 ff                               local··
    """

    def __str__(self):
        result = f"DHCP -> Opcode: {self.msg_type}, Xid: {self.xid:x}, Lease sec: {self.sec}\n{format_hex(self.packet)}\n********\n"
        for opt in self.option_list:
            result += f" {opt}\n"
        return result

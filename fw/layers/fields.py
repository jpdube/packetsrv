from struct import pack
from time import time_ns


class FieldList:
    def __init__(self):
        self.field_list = {}

    def add(self, name, field):
        if field is not None:
            self.field_list[name] = field

    def get(self, name):
        field = self.field_list.get(name, None)
        return field


class Field:
    def __init__(self, value):
        self.value = value

    @property
    def binary(self):
        pass


class ByteField(Field):
    def __init__(self, value):
        super().__init__(value)

    @property
    def binary(self):
        return pack('B', self.value)

    def __str__(self):
        return f'{self.value:02x}'


class ShortField(Field):
    def __init__(self, value):
        if isinstance(value, bytes):
            svalue = (value[0] << 8) & 0xff00
            svalue += value[1] & 0x00ff
            # print(f'svalue: {svalue}, 0: {value[0]}, 1: {value[1]}')

            super().__init__(svalue)
        else:
            super().__init__(value)

    @property
    def binary(self):
        return pack('>H', self.value)

    def __str__(self):
        return f'{self.value:04x}'


class LongField(Field):
    def __init__(self, value):
        super().__init__(value)

    @property
    def binary(self):
        return pack('>I', self.value)


class W24Field(Field):
    def __init__(self, value):
        super().__init__(value)

    @property
    def binary(self):
        return pack('>L', self.value & 0xffffff00)


class Timestamp(Field):
    def __init__(self, value=0):
        super().__init__(int(value))

    def set_time(self):
        ts = time_ns()
        print(f'Timestamp: {int(ts):08x}')
        self.value = int(ts)

    @property
    def binary(self):
        return pack('>Q', self.value)


class BitGroup(Field):
    def __init__(self, name, group_size) -> None:
        self.name = name
        self.group_size = group_size
        self.field_list = []

    def add(self, bit_field):
        if isinstance(bit_field, BitField):
            self.field_list.append(bit_field)

    @property
    def binary(self):
        ...


class BitField(Field):
    def __init__(self, name, offset, size, value):
        super().__init__(value)
        self.name = name
        self.offset = offset
        self.size = size


class MacAddress(Field):
    def __init__(self, mac) -> None:
        super().__init__(mac)

        if isinstance(mac, str):
            self.value = self.from_string(mac)

    def from_string(self, mac_addr):
        if mac_addr.count(':') == 5:
            fields = mac_addr.split(':')
            result = []
            for f in fields:
                result.append(int(f, 16))

            return result

    def __str__(self) -> str:
        return f'{self.value[0]:02x}:{self.value[1]:02x}:{self.value[2]:02x}:{self.value[3]:02x}:{self.value[4]:02x}:{self.value[5]:02x}'

    def __eq__(self, other) -> bool:
        return other.value == self.value

    @property
    def binary(self):
        result = pack('>BBBBBB', self.value[0], self.value[1],
                      self.value[2], self.value[3], self.value[4], self.value[5])

        return result


class IPv4Address(Field):
    def __init__(self, ipaddr):
        super().__init__(ipaddr)
        if isinstance(ipaddr, str):
            self.value = self.from_string(ipaddr)
        elif isinstance(ipaddr, int):
            self.value = ipaddr

    def from_string(self, address):
        if address.count('.') == 3:
            split_addr = address.split('.')
            bin_addr = int(split_addr[0]) << 24
            bin_addr += (int(split_addr[1]) << 16) & 0x00ff0000
            bin_addr += (int(split_addr[2]) << 8) & 0x0000ff00
            bin_addr += int(split_addr[3]) & 0x000000ff

            # print(f'IPV4 Address: {bin_addr:04X}')
            return bin_addr

    def __eq__(self, other) -> bool:
        return self.value == other.value

    @property
    def ip_str(self):
        byte1 = (self.value & 0xff000000) >> 24
        byte2 = (self.value & 0x00ff0000) >> 16
        byte3 = (self.value & 0x0000ff00) >> 8
        byte4 = self.value & 0x000000ff

        return f'{byte1}.{byte2}.{byte3}.{byte4}'

    @property
    def binary(self):
        return pack('>L', self.value)

    def __str__(self) -> str:
        return f'IPv4 address: {self.value:04X}:{self.ip_str}'

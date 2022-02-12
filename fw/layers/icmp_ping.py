from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, Timestamp
from fw.utils.print_hex import print_hex
from fw.utils.calc_checksum import calc_checksum

from struct import *


class ICMP_Ping(Packet):
    name = 'icmp_ping'

    def __init__(self):
        super().__init__()
        self.icmp_type = ByteField(0x08)
        self.code = ByteField(0x00)
        self.checksum = ShortField(0x00)
        self.identifier = ShortField(0x001a)
        self.sequence = ShortField(0xb2c3)
        self.timestamp = Timestamp(0)
        self.data = bytearray(b'\x41') * 48

    @property
    def packet(self):
        return super().packet

    # @property
    def to_bytes(self):
        result = bytearray()
        result += self.icmp_type.binary
        result += self.code.binary
        result += self.checksum.binary
        result += self.identifier.binary
        result += self.sequence.binary

        ts = Timestamp()
        ts.set_time()
        result += ts.binary
        result += self.data

        checksum = calc_checksum(result)
        checksum_bytes = pack('>H', checksum)
        result[2] = checksum_bytes[0]
        result[3] = checksum_bytes[1]

        print(f'Checksum: {checksum:04x}')

        return result

    def __str__(self):
        return f"""
        {ICMP_Ping.name}: type: {self.icmp_type}, code: {self.code},
        checksum: {self.checksum}, identifier: {self.identifier}, sequence: {self.sequence}
        """

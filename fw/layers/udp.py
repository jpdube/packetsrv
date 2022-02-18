from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, IPv4Address
from fw.utils.print_hex import print_hex
from fw.utils.calc_checksum import calc_checksum
from struct import *


class UDP(Packet):
    name = 'udp'

    def __init__(self,
                 src_port: int,
                 dst_port: int,
                 data: bytearray,
                 length=0,
                 checksum=0) -> None:

        super().__init__()

        self.src_port = ShortField(src_port)
        self.dst_port = ShortField(dst_port)
        self.data = data
        self.length = ShortField(length)
        self.checksum = ShortField(checksum)

    @classmethod
    def from_packet(cls, packet: list):
        raw_packet = bytes(packet)

        src_port, dst_port, length, checksum = unpack(
            '!HHHH', raw_packet[:8])

        return cls(src_port=src_port,
                   dst_port=dst_port,
                   length=length,
                   checksum=checksum,
                   data=raw_packet[8:])

    def to_bytes(self, src_ip: IPv4Address, dst_ip: IPv4Address) -> bytearray:
        packet = bytearray()
        packet += self.src_port.binary
        packet += self.dst_port.binary
        packet += self.length.binary
        packet += ShortField(0).binary
        packet += self.data

        checksum = self.calc_checksum(packet, src_ip, dst_ip)
        self.checksum = checksum
        packet[6] = (checksum >> 8) & 0x00ff
        packet[7] = checksum & 0x00ff

        return packet

    def calc_checksum(self, packet: bytearray, src_ip: IPv4Address, dst_ip: IPv4Address) -> int:
        chk_packet = bytearray()
        chk_packet += src_ip.binary
        chk_packet += dst_ip.binary

        # --- Protocol
        chk_packet += ByteField(0).binary
        chk_packet += ByteField(0x11).binary

        # --- UPD length
        chk_packet += ShortField(self.length.value + 0).binary

        print_hex(chk_packet)
        chk_packet += packet
        print_hex(chk_packet)

        csum = calc_checksum(chk_packet)
        print(f'{csum:x}')

        return csum

    def __str__(self) -> str:
        return f'UDP: Src port: {self.src_port.value}, Dst Port: {self.dst_port.value}'

from struct import unpack
from typing import Dict

from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet

"""
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            TCP Header Format
"""


class TCP(Packet):
    name = LayerID.TCP

    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet

    @property
    def src_port(self) -> int:
        return unpack("!H", self.packet[0:2])[0]

    @property
    def dst_port(self) -> int:
        return unpack("!H", self.packet[2:4])[0]

    @property
    def seq_no(self) -> int:
        return unpack("!I", self.packet[4:8])[0]

    @property
    def ack_no(self) -> int:
        return unpack("!I", self.packet[8:12])[0]

    @property
    def header_len(self) -> int:
        return unpack("!B", self.packet[12:13])[0] >> 4

    @property
    def flags(self) -> int:
        fl = (unpack("!B", self.packet[12:13])[0] & 0x0F) << 8
        fl += unpack("!B", self.packet[13:14])[0]
        return fl

    @property
    def window(self) -> int:
        return unpack("!H", self.packet[14:16])[0]

    @property
    def checksum(self) -> int:
        return unpack("!H", self.packet[16:18])[0]

    @property
    def urgent_ptr(self) -> int:
        return unpack("!H", self.packet[18:20])[0]

    @property
    def options(self):
        if self.header_len > 5:
            offset = (self.header_len - 5) * 4
            return self.packet[20: 20 + offset]
        else:
            return None

    @property
    def payload(self) -> bytes:
        if self.header_len > 5:
            offset = (self.header_len - 5) * 4
            return self.packet[20 + offset:]
        else:
            return self.packet[20:]

    @property
    def flag_ns(self) -> bool:
        return False

    @property
    def flag_cwr(self) -> bool:
        return self.flags & 0x80 == 0x80

    @property
    def flag_ece(self) -> bool:
        return self.flags & 0x40 == 0x40

    @property
    def flag_urg(self) -> bool:
        return self.flags & 0x20 == 0x20

    @property
    def flag_ack(self) -> bool:
        return self.flags & 0x10 == 0x10

    @property
    def flag_push(self) -> bool:
        return self.flags & 0x08 == 0x08

    @property
    def flag_rst(self) -> bool:
        return self.flags & 0x04 == 0x04

    @property
    def flag_syn(self) -> bool:
        return self.flags & 0x02 == 0x02

    @property
    def flag_fin(self) -> bool:
        return self.flags & 0x01 == 0x01

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}TCP ->\n'
        result += f'{" " * offset}   Src port...: {self.src_port}\n'
        result += f'{" " * offset}   Dst port...: {self.dst_port}\n'
        result += f'{" " * offset}   Seq no.....: {self.seq_no},0x{self.seq_no:04x} \n'
        result += f'{" " * offset}   Ack no.....: {self.ack_no}\n'
        result += f'{" " * offset}   Header len.: {self.header_len}\n'
        result += f'{" " * offset}   Flags......: {self.flags}\n'
        result += f'{" " * offset}   Checksum...: {self.checksum},0x{self.checksum:04x}\n'

        return result

    def __str__(self) -> str:
        return f"TCP -> sport: {self.src_port} dport: {self.dst_port} SYN:{self.flag_syn} ACK:{self.flag_ack} FIN:{self.flag_fin} PUSH:{self.flag_push} URG:{self.flag_urg} RST:{self.flag_rst}"

    def get_field(self, fieldname: str) -> None | int:
        field = fieldname.split('.')[1]
        if field:
            if field == 'seq_no':
                return self.seq_no
            elif field == 'ack_no':
                return self.ack_no
            elif field == 'length':
                return self.header_len
            elif field == 'window':
                return self.window
            elif field == 'checksum':
                return self.checksum
            elif field == 'urgent_ptr':
                return self.urgent_ptr
            elif field == 'flag_syn':
                return self.flag_syn
            elif field == 'flag_ack':
                return self.flag_ack
            elif field == 'checksum':
                return self.checksum
            elif field == 'sport':
                return self.src_port
            elif field == 'dport':
                return self.dst_port
            else:
                return 0
        else:
            return None

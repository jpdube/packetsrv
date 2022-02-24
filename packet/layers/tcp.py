from struct import unpack

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


class TCP:
    name = 3

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
        fl += unpack("!H", self.packet[13:14])
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
    def options(self) -> bytes | None:
        if self.header_len > 5:
            offset = (self.header_len - 5) * 4
            return self.packet[20 : 20 + offset]
        else:
            return None

    @property
    def payload(self) -> bytes:
        if self.header_len > 5:
            offset = (self.header_len - 5) * 4
            return self.packet[20 + offset :]
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

    def __str__(self) -> str:
        return f"TCP -> sport: {self.src_port} dport: {self.dst_port} SYN:{self.flag_syn} ACK:{self.flag_ack}"

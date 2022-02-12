from fw.layers.packet import Packet
from fw.layers.fields import ByteField, ShortField, LongField, IPv4Address, W24Field
from fw.utils.print_hex import print_hex
from fw.utils.calc_checksum import calc_checksum
from struct import pack, unpack


class TCP(Packet):
    name = 'tcp'

    def __init__(self,
                 src_port: int,
                 dst_port: int,
                 data: bytearray = None,
                 sequence_no: int = 0,
                 ack_no: int = 0,
                 data_offset: int = 5,
                 ctrl_bits: int = 0,
                 window: int = 0,
                 checksum: int = 0,
                 urgent_ptr: int = 0,
                 options: int = 0):
        super().__init__()
        self.src_port = ShortField(src_port)
        self.dst_port = ShortField(dst_port)
        self.data = data
        self.sequence_no = LongField(sequence_no)
        self.ack_no = LongField(ack_no)
        self.data_offset = ByteField(data_offset)
        self.ctrl_bits = ByteField(ctrl_bits)
        self.window = ShortField(window)
        self.checksum = ShortField(checksum)
        self.urgent_ptr = ShortField(urgent_ptr)
        self.options = W24Field(options)
        self.opt_pad = ByteField(0)

    @classmethod
    def from_packet(cls, packet: list):
        raw_packet = bytes(packet)
        print(f'TCP raw packet for conversion:')
        # print_hex(raw_packet)
        src_port, dst_port, seq_no, ack_no, hl, flags, window, checksum, urgent_ptr = unpack(
            '!HHIIBBHHH', raw_packet[:20])

        print(f'Decode hl: {hl:x}, flags: {flags:x}')
        return cls(src_port=src_port,
                   dst_port=dst_port,
                   data=bytearray(raw_packet[21:]),
                   sequence_no=seq_no,
                   ack_no=ack_no,
                   data_offset=hl,
                   ctrl_bits=flags,
                   window=window,
                   checksum=checksum,
                   urgent_ptr=urgent_ptr)

    def packet(self) -> Packet:
        return super().packet

    def to_bytes(self, src_ip: IPv4Address, dst_ip: IPv4Address) -> bytearray:
        print(f'TCP src: {src_ip}, dst: {dst_ip}')
        result = bytearray()
        result += self.src_port.binary
        result += self.dst_port.binary
        result += self.sequence_no.binary
        result += self.ack_no.binary

        print(f'Data offset: {self.data_offset.value}')
        result += self.data_offset.binary
        result += self.ctrl_bits.binary

        result += self.window.binary

        # --- Set checksum to 0
        result += ShortField(0).binary
        result += self.urgent_ptr.binary

        print(f'Length of TCP: {len(result)}')

        result[16] = 0
        result[17] = 0

        checksum = self.calc_checksum(result, src_ip, dst_ip)
        result[16] = (checksum & 0xff00) >> 8
        result[17] = checksum & 0x00ff

        if self.data:
            result += self.data
        return result

    def calc_checksum(self,
                      packet: bytearray,
                      src_ip: IPv4Address,
                      dst_ip: IPv4Address) -> int:

        chk_packet = bytearray()
        chk_packet += src_ip.binary
        chk_packet += dst_ip.binary
        chk_packet += ByteField(0).binary
        chk_packet += ByteField(6).binary

        print(f'Checksum HEADER LEN: {self.data_offset.value >> 4}')
        data_len = 0
        if self.data is not None:
            data_len = len(self.data)

        chk_packet += ShortField((self.data_offset.value >> 4)
                                 * 4 + data_len).binary

        print_hex(chk_packet)
        chk_packet += packet
        print_hex(chk_packet)

        # if len(chk_packet) % 2 != 0:
        # chk_packet += ByteField(0).binary

        csum = calc_checksum(chk_packet)
        print(f'{csum:x}')

        return csum

    def __str__(self) -> str:
        return f'{TCP.name}: sport: {self.src_port} dport: {self.dst_port}'

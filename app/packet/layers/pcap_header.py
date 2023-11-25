from struct import unpack
from datetime import datetime
from packet.layers.packet import Packet


class PcapHeader(Packet):
    name = 0xFF

    def __init__(self, header: bytes):
        self.header = header

    @property
    def ts_sec(self) -> int:
        return unpack("!I", self.header[0:4])[0]

    @property
    def ts_format(self) -> datetime:
        return datetime.fromtimestamp(self.ts_sec)

    @property
    def ts_usec(self) -> int:
        return unpack("!I", self.header[4:8])[0]

    @property
    def orig_len(self) -> int:
        return unpack("!I", self.header[8:12])[0]

    @property
    def incl_len(self) -> int:
        return unpack("!I", self.header[12:16])[0]

    def __str__(self) -> str:
        return f"Packet info -> Time date/sec: {self.ts_format}/{self.ts_sec}, Offset: {self.ts_usec}usec, Orig len: {self.orig_len}, Incl len: {self.incl_len}"

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}Frame ->\n'
        result += f'{" " * offset}   Time......: {self.ts_format}\n'
        result += f'{" " * offset}   Offset ms.: {self.ts_usec}\n'
        result += f'{" " * offset}   Orig len..: {self.orig_len},0x{self.orig_len:04x} \n'
        result += f'{" " * offset}   Incl len..: {self.incl_len},0x{self.incl_len:04x} \n'

        return result

    def get_field(self, fieldname: str):
        ...

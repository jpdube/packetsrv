from struct import unpack
from datetime import datetime
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet


class Frame(Packet):
    name = LayerID.HEADER

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
        field = fieldname.split('.')[1]
        if field:
            if field == 'ts_sec':
                return self.ts_sec
            elif field == 'timestamp':
                return self.ts_format
            elif field == 'ts_usec':
                return self.ts_usec
            elif field == 'origlen':
                return self.orig_len
            elif field == 'inclen':
                return self.incl_len

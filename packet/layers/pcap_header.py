from struct import unpack
from datetime import datetime


class PcapHeader:
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
        return f"Packet info -> Time sec: {self.ts_format},{self.ts_sec}, Time usec: {self.ts_usec}, Orig len: {self.orig_len}, Incl len: {self.incl_len}"

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class PktHeader:
    timestamp: int
    ts_offset: int
    incl_len: int
    orig_len: int
    file_ptr: Optional[int] = 0
    pkt_ptr: Optional[int] = 0

    def packet_id(self) -> str:
        return f"{self.file_ptr}:{self.pkt_ptr}"

    def packet_id_int(self) -> int:
        id = self.file_ptr << 32

        id += self.pkt_ptr & 0xffff

        return id

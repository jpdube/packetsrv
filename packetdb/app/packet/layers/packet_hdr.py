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

from dataclasses import dataclass


@dataclass(slots=True)
class PktHeader:
    timestamp: int
    ts_offset: int
    incl_len: int
    orig_len: int

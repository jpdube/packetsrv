from dataclasses import dataclass
from typing import Optional

from packet.layers.packet_hdr import PktHeader


@dataclass(slots=True)
class PktPtr:
    file_id: int
    ptr: int
    ip_dst: int
    ip_src: int
    pkt_hdr_size: int
    header: Optional[PktHeader] = None
    packet: Optional[bytes] = None

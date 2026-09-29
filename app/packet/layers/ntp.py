
from enum import Enum
from struct import unpack

from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet


class Ntp(Packet):
    name = LayerID.NTP

    __slots__ = ["packet"]

    def __init__(self, packet) -> None:
        self.packet = packet

    # LI
    @property
    def leap_indicator(self) -> int:
        return (self.packet[0] & 0b11000000) >> 6

    # VN
    @property
    def version_no(self) -> int:
        return (self.packet[0] & 0b00111000) >> 3

    @property
    def mode(self) -> int:
        return (self.packet[0] & 0b00000111)

    @property
    def stratum(self) -> int:
        return self.packet[1]

    @property
    def poll(self) -> int:
        return self.packet[2]

    @property
    def precision(self) -> int:
        return self.packet[3]

    @property
    def root_delay(self) -> int:
        return unpack("!I", self.packet[4:8])[0]

    @property
    def root_dispersion(self) -> int:
        return unpack("!I", self.packet[8:12])[0]

    @property
    def ref_id(self) -> int:
        return unpack("!I", self.packet[12:16])[0]

    @property
    def ref_timestamp(self) -> int:
        return unpack("!Q", self.packet[16:24])[0]

    @property
    def origin_timestamp(self) -> int:
        return unpack("!Q", self.packet[24:32])[0]

    @property
    def recv_timestamp(self) -> int:
        return unpack("!Q", self.packet[32:40])[0]

    @property
    def transmit_timestamp(self) -> int:
        return unpack("!Q", self.packet[40:48])[0]

    @property
    def optional_ext(self) -> int:
        return unpack("!I", self.packet[48:52])[0]

    @property
    def key_id(self) -> int:
        return unpack("!I", self.packet[52:56])[0]

    @property
    def msg_digest(self) -> bytes:
        return self.packet[52:]

    @property
    def payload(self) -> bytes:
        return self.packet[5:]

    def summary(self, offset: int) -> str:
        result = f"{' ' * offset}NTP -> \n"

        return result

    def export(self) -> dict[str, int | str]:
        return {
        }

    def get_field(self, fieldname: str) -> None | int | str:
        field = fieldname.split('.')[1]
        # match field:
        #     case 'content_type':
        #         return self.content_type
        #     case 'tls_version':
        #         return self.tls_version
        #     case 'tls_version_str':
        #         return self.tls_version_str
        #     case 'length':
        #         return self.length
        #     case 'payload':
        #         return str(self.payload)
        #     case _:
        #         return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

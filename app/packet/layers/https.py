from enum import Enum
from struct import unpack

from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet


class TlsVersion(Enum):
    V1_0 = 0x0301
    V1_1 = 0x0302
    V1_2 = 0x0303
    V_UNKNOWN = 0

    # @classmethod
    # def is_valid_version(cls, version_code) -> bool:
    #     return version_code.value in [cls.V1_0.value, cls.V1_1.value, cls.V1_2.value]


CONTENT_TYPE = [0x15, 0x16, 0x17]


class Https(Packet):
    name = LayerID.HTTPS

    __slots__ = ["packet"]

    def __init__(self, packet) -> None:
        self.packet = packet

    @property
    def is_valid(self):
        valid = self.content_type in CONTENT_TYPE and self.tls_version in (
            TlsVersion.V1_0.value, TlsVersion.V1_1.value, TlsVersion.V1_2.value)
        return valid

    @property
    def content_type(self) -> int:
        if len(self.packet) > 0:
            return self.packet[0]
        else:
            return -1

    @property
    def tls_version(self) -> int:
        if len(self.packet) > 0:
            version = int(unpack("!H", self.packet[1:3])[0])
            return version
        else:
            return 0

    @property
    def tls_version_str(self) -> str:
        if len(self.packet) > 0:
            version = int(unpack("!H", self.packet[1:3])[0])
            match version:
                case TlsVersion.V1_0.value:
                    return "tls 1.0"
                case TlsVersion.V1_1.value:
                    return "tls 1.1"
                case TlsVersion.V1_2.value:
                    return "tls 1.2"
                case _:
                    return f"unknown {version:x}"

        else:
            return "unknown version"

    @property
    def length(self) -> int:
        if len(self.packet) > 0:
            return unpack("!H", self.packet[3:5])[0]
        else:
            return -1

    @property
    def payload(self) -> bytes:
        return self.packet[5:]

    def summary(self, offset: int) -> str:
        result = f"{' ' * offset}HTTPS -> \n"
        result += f"{' ' * offset} Content type.: {self.content_type}"
        result += f"{' ' * offset} TLS version..: {self.tls_version}"
        result += f"{' ' * offset} Length.......: {self.length}"

        return result

    def export(self) -> dict[str, int | str]:
        return {
            "https.content_type": self.content_type,
            "https.tls_version": f"{self.tls_version:x}",
            "https.tls_version_str": self.tls_version_str,
            "https.length": self.length
        }

    def get_field(self, fieldname: str) -> None | int | str:
        field = fieldname.split('.')[1]
        match field:
            case 'content_type':
                return self.content_type
            case 'tls_version':
                return self.tls_version
            case 'tls_version_str':
                return self.tls_version_str
            case 'length':
                return self.length
            case 'payload':
                return str(self.payload)
            case _:
                return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.payload) and (offset + length) < len(self.payload):
            return self.payload[offset: offset + length]
        else:
            return None

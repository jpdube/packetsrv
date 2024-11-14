from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet
from struct import unpack


class Https(Packet):
    name = LayerID.HTTPS

    __slots__ = ["packet"]

    def __init__(self, packet) -> None:
        self.packet = packet

    @property
    def is_valid(self):
        valid = self.content_type in (0x15, 0x16, 0x17)
        print(f"HTTPS VALID: {valid}")
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
            match version:
                case 0x0303:
                    return "tls 1.2"
                case _:
                    return "unknown version"

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
            "https.tls_version": self.tls_version,
            "https.length": self.length
        }

    def get_field(self, fieldname: str) -> None | int:
        field = fieldname.split('.')[1]
        match field:
            case 'content_type':
                return self.content_type
            case 'tls_version':
                return self.tls_version
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

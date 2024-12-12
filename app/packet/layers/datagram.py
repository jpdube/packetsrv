from packet.layers.ipv4 import IPV4
from packet.layers.udp import UDP
from packet.layers.tcp import TCP


class Datagram:
    def __init__(self, ipv4: IPV4) -> None:
        self.layers = []

        self.layers.append(ipv4)

        match ipv4.protocol:
            case 0x11:
                udp = UDP(ipv4.payload)
                self.layers.append(udp)
            case 0x06:
                tcp = TCP(ipv4.payload)
                self.layers.append(tcp)

    def export(self) -> dict[str, str | int]:
        result = {}
        for l in self.layers:
            result.update(l.export())

        return result

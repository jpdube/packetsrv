from packet.layers.ethernet import (
    ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6,
    Ethernet,
)
from packet.layers.ipv4 import IPV4, IP_PROTO_UDP, IP_PROTO_TCP, IP_PROTO_ICMP
from packet.layers.ipv6 import IPV6
from packet.layers.tcp import TCP
from packet.layers.udp import UDP
from packet.layers.arp import ARP
from packet.layers.pcap_header import PcapHeader
from typing import Dict
from packet.layers.packet import Packet

ID_ETHERNET = 0
ID_IPV4 = 1
ID_IPV6 = 2
ID_TCP = 3
ID_UDP = 4
ID_ARP = 5
ID_HEADER = 1024


class PacketBuilder:
    name = "packet"

    def __init__(self) -> None:
        self.layers: Dict[int, Packet] = {}

    def _add_layer(self, layer: Packet):
        self.layers[layer.name] = layer

    def add(self, layer):
        self._add_layer(layer)

    def print_layers(self) -> None:
        print("-" * 40)
        for v in self.layers.values():
            print(f"{v}")

    def from_bytes(self, raw_packet, header=None):
        if header is not None:
            hdr = PcapHeader(header)
            self.add(hdr)

        e = Ethernet(raw_packet)
        offset = 0
        if e.frametype == 0x8100:
            offset = 4
        self.add(e)
        if e.ethertype == ETHER_TYPE_ARP:
            arp = ARP(raw_packet[offset + 14 :])
            self.add(arp)

        if e.ethertype == ETHER_TYPE_IPV4:
            ip = IPV4(raw_packet[offset + 14 :])

            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP(raw_packet[offset + 34 :])
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP(raw_packet[offset + 34 :])
                self.add(udp)
            elif ip.protocol == IP_PROTO_ICMP:
                pass

        if e.ethertype == ETHER_TYPE_IPV6:
            ip = IPV6(raw_packet[offset + 14 :])

            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP(raw_packet[offset + 40 :])
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP(raw_packet[offset + 40 :])
                self.add(udp)
            elif ip.protocol == IP_PROTO_ICMP:
                pass

    def __str__(self) -> str:
        result = ""
        for l in self.layers.values():
            result += f"{l}\n"
        return str(result)

    @property
    def layers_count(self) -> int:
        return len(self.layers)

    def has_layer(self, layer_name) -> bool:
        result = self.layers.get(layer_name, None)
        return result is not None

    def get_layer(self, layer_name):
        return self.layers.get(layer_name, None)
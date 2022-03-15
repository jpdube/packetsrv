from os import wait
from packet.layers.ethernet import (
    ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6,
    Ethernet,
)
from packet.layers.icmp_builder import icmp_builder
from packet.layers.ipv4 import IPV4, IP_PROTO_UDP, IP_PROTO_TCP, IP_PROTO_ICMP
from packet.layers.ipv6 import IPV6
from packet.layers.tcp import TCP
from packet.layers.udp import UDP
from packet.layers.arp import ARP
from packet.layers.dhcp import Dhcp
from packet.layers.dns import Dns
from typing import Dict
from packet.layers.packet import Packet
from packet.layers.layer_type import LayerID
from json import dumps
import base64

from packet.utils.print_hex import print_hex


class PacketBuilder:
    def __init__(self) -> None:
        self.layers: Dict[int, Packet] = {}
        self.packet = None

    def add(self, layer: Packet):
        self.layers[layer.name] = layer

    def print_layers(self) -> None:
        print("-" * 40)
        for v in self.layers.values():
            print(f"{v}")

    def from_bytes(self, raw_packet, header=None):
        self.packet = raw_packet
        if header is not None:
            self.add(header)

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
                if udp.src_port in [67, 68] and udp.dst_port in [67, 68]:
                    dhcp = Dhcp(udp.payload)
                    self.add(dhcp)
                elif udp.dst_port == 53 or udp.src_port == 53:
                    dns = Dns(udp.payload)
                    self.add(dns)
            elif ip.protocol == IP_PROTO_ICMP:
                icmp = icmp_builder(raw_packet[offset + 34 :])
                self.add(icmp)

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
                icmp = icmp_builder(raw_packet[offset + 34 :])
                self.add(icmp)

    def __str__(self) -> str:
        result = ""
        for l in self.layers.values():
            result += f"{l}\n"
        return str(result)

    def export(self) -> Dict:
        eth = self.layers[0]
        ipv4 = self.layers[1]
        header = self.layers[0xff]

        r = bytearray(header.header) + bytearray(self.packet)

        result = {
            "ether.src": str(eth.src_mac),
            "ether.dst": str(eth.dst_mac),
            "ether.ethertype": eth.ethertype,
            "ether.vlan": eth.vlan_id,
            "ip.src": str(ipv4.src_ip),
            "ip.dst": str(ipv4.dst_ip),
            "ip.proto": ipv4.protocol,
            "packet": str(base64.b64encode(r), "ascii"),
        }

        return result

    @property
    def layers_count(self) -> int:
        return len(self.layers)

    def has_layer(self, layer_name) -> bool:
        result = self.layers.get(layer_name, None)
        return result is not None

    def get_layer(self, layer_id) -> Packet | None:
        return self.layers.get(layer_id, None)

from os import wait
from packet.layers.ethernet import (
    ETHER_TYPE_ARP,
    ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6,
    Ethernet,
)
from packet.layers.icmp_builder import ICMP_ECHO_MSG, icmp_builder
from packet.layers.ipv4 import IPV4, IP_PROTO_UDP, IP_PROTO_TCP, IP_PROTO_ICMP
from packet.layers.ipv6 import IPV6
from packet.layers.tcp import TCP
from packet.layers.udp import UDP
from packet.layers.arp import ARP
from packet.layers.dhcp import Dhcp
from packet.layers.dns import Dns
from packet.layers.icmp_echo import IcmpEcho
from typing import Dict
from packet.layers.packet import Packet
from packet.layers.pcap_header import PcapHeader
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
            arp = ARP(raw_packet[offset + 14:])
            self.add(arp)

        if e.ethertype == ETHER_TYPE_IPV4:
            ip = IPV4(raw_packet[offset + 14:])

            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP(raw_packet[offset + 34:])
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP(raw_packet[offset + 34:])
                self.add(udp)
                if udp.src_port in [67, 68] and udp.dst_port in [67, 68]:
                    dhcp = Dhcp(udp.payload)
                    self.add(dhcp)
                elif udp.dst_port == 53 or udp.src_port == 53:
                    dns = Dns(udp.payload)
                    self.add(dns)
            elif ip.protocol == IP_PROTO_ICMP:
                icmp = icmp_builder(raw_packet[offset + 34:])
                self.add(icmp)

        if e.ethertype == ETHER_TYPE_IPV6:
            ip = IPV6(raw_packet[offset + 14:])

            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP(raw_packet[offset + 40:])
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP(raw_packet[offset + 40:])
                self.add(udp)
            elif ip.protocol == IP_PROTO_ICMP:
                icmp = icmp_builder(raw_packet[offset + 34:])
                self.add(icmp)

    def __str__(self) -> str:
        result = ""
        for l in self.layers.values():
            result += f"{l}\n"
        return str(result)

    def export(self) -> Dict:

        result = {}
        for layer in self.layers.values():
            if isinstance(layer, Ethernet):
                result["ether.src"] = layer.src_mac.to_int()
                result["ether.dst"] = layer.dst_mac.to_int()
                result["ether.ethertype"] = layer.ethertype
                result["ether.vlan"] = layer.vlan_id

            elif isinstance(layer, ARP):
                result["arp.opcode"] = layer.opcode
                result["arp.src_ip"] = layer.src_ip.value
                result["arp.target_ip"] = layer.target_ip.value

            elif isinstance(layer, IPV4):
                result["ip.src"] = layer.src_ip.value
                result["ip.dst"] = layer.dst_ip.value
                result["ip.proto"] = layer.protocol

            elif isinstance(layer, TCP):
                result["tcp.src"] = layer.src_port
                result["tcp.dst"] = layer.dst_port

            elif isinstance(layer, UDP):
                result["udp.src"] = layer.src_port
                result["udp.dst"] = layer.dst_port

            elif isinstance(layer, IcmpEcho):
                result["icmp.type"] = layer.type
                result["icmp.code"] = layer.code
                result["icmp.seq"] = layer.sequence_no

            elif isinstance(layer, PcapHeader):
                r = bytearray(layer.header) + bytearray(self.packet)
                result["packet"] = str(base64.b64encode(r), "ascii")
                result["orig_len"] = layer.orig_len
                result["incl_len"] = layer.incl_len

        return result

    @property
    def layers_count(self) -> int:
        return len(self.layers)

    def has_layer(self, layer_name) -> bool:
        result = self.layers.get(layer_name, None)
        return result is not None

    def get_layer(self, layer_id) -> Packet | None:
        return self.layers.get(layer_id, None)

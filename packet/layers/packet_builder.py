import base64
from ipaddress import IPv4Address
from json import dumps
from os import wait
from typing import Dict, List, Tuple

from packet.layers.arp import ARP
from packet.layers.dhcp import Dhcp
from packet.layers.dns import Dns
from packet.layers.ethernet import (ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
                                    ETHER_TYPE_IPV6, Ethernet)
from packet.layers.icmp_builder import ICMP_ECHO_MSG, icmp_builder
from packet.layers.icmp_echo import IcmpEcho
from packet.layers.ipv4 import IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, IPV4
from packet.layers.ipv6 import IPV6
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet
from packet.layers.pcap_header import PcapHeader
from packet.layers.tcp import TCP
from packet.layers.udp import UDP
from packet.utils.print_hex import HexDump


class PacketBuilder:
    __slots__ = ["packet", "layers", "fields_list", "color_range"]

    def __init__(self) -> None:
        self.layers: Dict[LayerID, Packet] = {}
        self.fields_list = {}

    def init_colors(self):
        self.color_range: List[Tuple[int, int, str]] = []
        self.color_range.append((0, 18, "yellow"))

        if self.has_layer(LayerID.IPV4):
            self.color_range.append((18, 38, "red"))
        if self.has_layer(LayerID.UDP):
            self.color_range.append((38, 54, "green"))
            self.color_range.append((54, 8192, "magenta"))
        if self.has_layer(LayerID.TCP):
            self.color_range.append((38, 58, "cyan"))
            self.color_range.append((58, 8192, "magenta"))

    def add(self, layer: Packet):
        self.layers[layer.name] = layer
        self.init_colors()

    def print_layers(self) -> None:
        print("-" * 40)
        for v in self.layers.values():
            print(f"{v}")

    def from_bytes(self, raw_packet, header=None):
        self.layers: Dict[LayerID, Packet] = {}
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
        return result

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
                result["sport"] = layer.src_port
                result["dport"] = layer.dst_port

            elif isinstance(layer, UDP):
                result["sport"] = layer.src_port
                result["dport"] = layer.dst_port

            elif isinstance(layer, IcmpEcho):
                result["icmp.type"] = layer.type
                result["icmp.code"] = layer.code
                result["icmp.seq"] = layer.sequence_no

            elif isinstance(layer, PcapHeader):
                result["orig_len"] = layer.orig_len
                result["incl_len"] = layer.incl_len
                result["ts_offset"] = layer.ts_usec
                result["timestamp"] = layer.ts_format

        return result

    def summary(self):
        for i, p in enumerate(self.layers.values()):
            print(f"{i}:{p.summary(offset=i * 2)}")

    @property
    def layers_count(self) -> int:
        return len(self.layers)

    def has_layer(self, layer_name) -> bool:
        result = self.layers.get(layer_name, None)
        return result is not None

    def get_layer(self, layer_id) -> Packet | None:
        return self.layers.get(layer_id, None)

    def get_field(self, field: str):
        pkt_name = field.split('.')[0]
        match pkt_name:
            case 'eth':
                eth = self.get_layer(LayerID.ETHERNET)
                if eth:
                    return eth.get_field(field)
            case 'ip':
                ip = self.get_layer(LayerID.IPV4)
                if ip:
                    return ip.get_field(field)
            case 'tcp':
                tcp = self.get_layer(LayerID.TCP)
                if tcp:
                    return tcp.get_field(field)

            case 'udp':
                udp = self.get_layer(LayerID.UDP)
                if udp:
                    return udp.get_field(field)
            case _:
                return 0

        return 0
        # return None

    def print_hex(self):
        HexDump.print_hex(self.packet, self.color_range)

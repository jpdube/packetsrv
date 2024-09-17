import base64
import logging
from typing import Dict, List, Tuple

from packet.layers.arp import ARP
from packet.layers.dhcp import Dhcp
from packet.layers.dns import Dns
from packet.layers.ethernet import (ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
                                    ETHER_TYPE_IPV6, Ethernet)
from packet.layers.frame import Frame
from packet.layers.icmp_builder import icmp_builder
from packet.layers.icmp_echo import IcmpEcho
from packet.layers.ipv4 import IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, IPV4
from packet.layers.ipv6 import IPV6
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet
from packet.layers.packet_hdr import PktHeader
from packet.layers.tcp import TCP
from packet.layers.udp import UDP
from packet.utils.print_hex import HexDump

log = logging.getLogger("packetdb")


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

    def get_byte_field(self, proto: str, offset: int, length: int) -> bytes | None:
        layer = self.get_layer_by_proto(proto)
        if layer:
            return layer.get_array(offset, length)

        return None

    def get_layer_by_proto(self, str_proto: str):
        match str_proto:
            case "eth": return self.get_layer(LayerID.ETHERNET)
            case "ip": return self.get_layer(LayerID.IPV4)
            case "tcp": return self.get_layer(LayerID.TCP)

            case other:
                return None

    def from_bytes(self, raw_packet, header: PktHeader | Frame = None):
        self.layers: Dict[LayerID, Packet] = {}
        self.packet = raw_packet

        if header is not None:
            if isinstance(header, PktHeader):
                ph = Frame(header)
                self.add(ph)
            elif isinstance(header, Frame):
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

    def __repr__(self) -> str:
        result = ""
        for l in self.layers.values():
            result += f"{l}\n"
        return result

    def export(self) -> Dict:
        result = {}
        for layer in self.layers.values():
            result.update(layer.export())

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

    def get_layer(self, layer_id):
        return self.layers.get(layer_id, None)

    def get_field(self, field: str) -> None | int | str | Dict:
        pkt_name = field.split('.')[0]
        if pkt_name == 'eth':
            eth = self.get_layer(LayerID.ETHERNET)
            if eth:
                return eth.get_field(field)
        elif pkt_name == 'frame':
            frame = self.get_layer(LayerID.FRAME)
            if field == 'frame.packet':
                return self.to_base64()
            elif field == 'frame.all':
                return self.export()
            elif frame:
                return frame.get_field(field)
        elif pkt_name == 'arp':
            arp = self.get_layer(LayerID.ARP)
            if arp:
                return arp.get_field(field)
        elif pkt_name == 'ip':
            arp = self.get_layer(LayerID.IPV4)
            if arp:
                return arp.get_field(field)
        elif pkt_name == 'tcp':
            tcp = self.get_layer(LayerID.TCP)
            if tcp:
                return tcp.get_field(field)

        elif pkt_name == 'udp':
            dhcp = self.get_layer(LayerID.UDP)
            if dhcp:
                return dhcp.get_field(field)
        elif pkt_name == 'dhcp':
            dhcp = self.get_layer(LayerID.DHCP)
            if dhcp:
                return dhcp.get_field(field)
        elif pkt_name == 'dns':
            dns = self.get_layer(LayerID.DNS)
            if dns:
                return dns.get_field(field)

        return None

    def to_base64(self) -> str:
        return base64.b64encode(self.packet).decode("ascii")

    def print_hex(self):
        HexDump.print_hex(self.packet, self.color_range)

from fw.layers.ethernet import ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, Ethernet
from fw.layers.ipv4 import IPV4, IP_PROTO_UDP, IP_PROTO_TCP, IP_PROTO_ICMP
from fw.layers.ipv6 import IPV6
from fw.layers.tcp import TCP
from fw.layers.udp import UDP
from typing import Dict
from fw.layers.fields import ByteField
from fw.utils.print_hex import print_hex
from fw.layers.packet import Packet


class PacketBuilder:
    name = 'packet'
    layer_types = ['ethernet', 'ipv4', 'ipv6', 'tcp', 'udp', 'arp', 'icmp_ping']

    def __init__(self) -> None:
        self.layers: Dict[str, Packet] = {}

    def _add_layer(self, layer: Packet):
        self.layers[layer.name] = layer

    def add(self, layer):
        # print(f'--> Add protocol: {layer.name}')
        if layer.name in self.layer_types:
            if layer.name == 'ethernet':
                if self.layers_count == 0:
                    self._add_layer(layer)

            if layer.name == 'arp':
                if self.layers_count == 1 and self.has_layer('ethernet'):
                    ethernet = self.layers.get('ethernet')
                    if ethernet is not None:
                        ethernet.ether_type = ETHER_TYPE_ARP
                        self._add_layer(layer)

            elif layer.name == 'ipv4':
                if self.layers_count == 1 and self.has_layer('ethernet'):
                    self.layers.get('ethernet').ether_type = ETHER_TYPE_IPV4
                    self._add_layer(layer)

            elif layer.name == 'ipv6':
                if self.layers_count == 1 and self.has_layer('ethernet'):
                    # self.layers.get('ethernet').ether_type = ETHER_TYPE_IPV6
                    self._add_layer(layer)

            elif layer.name == 'tcp':
                if self.layers_count == 2 and self.has_layer('ipv4'):
                    self.layers.get('ipv4').protocol = 0x06
                    self._add_layer(layer)

            elif layer.name == 'udp':
                if self.layers_count == 2 and self.has_layer('ipv4'):
                    self.layers.get('ipv4').protocol = 0x17
                    self._add_layer(layer)

            # ToDo: Fix this protocol assignation using a property setter
            elif layer.name == 'icmp_echo':
                if self.layers_count == 2 and self.has_layer('ipv4') and self.has_layer('ethernet'):
                    self.layers.get('ipv4').protocol = ByteField(0x01)
                    self._add_layer(layer)

    def print_layers(self) -> None:
        print('-'*40)
        for k, v in self.layers.items():
            print(f'Key: {k}, Value: {v}')

    def packet(self) -> bytearray:
        packet = bytearray()
        for l in self.layers.values():
            if l.name in ('tcp', 'udp'):
                ip = self.get_layer('ipv4')
                if ip:
                    packet += l.to_bytes(ip.src_ip, ip.dst_ip)
            else:
                packet += l.to_bytes()

        return packet

    def from_bytes(self, raw_packet):
        e = Ethernet.from_packet(raw_packet)
        # print(f'Frametype: {e.frametype.value}')
        if e.frametype.value == 0x8100:
            offset = 4
        else:
            offset = 0
        # print(f'Offset: {offset}')
        self.add(e)
        if e.ethertype == ETHER_TYPE_IPV4:
            # print(f'In ipv4 packet: {e.ethertype}')
            ip = IPV4.from_packet(raw_packet[offset + 14:])
            # print(f'IP packet: {ip}')

            # print('Adding ethernet to ipV4')
            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP.from_packet(raw_packet[offset + 34:])
                # print('Adding to TCP to IP')
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP.from_packet(raw_packet[offset + 34:])
                # print('Adding to UDP to IP')
                self.add(udp)
            elif ip.protocol == IP_PROTO_ICMP:
                pass
                # udp = UDP.from_packet(raw_packet[34:])
                # print('Adding to ICMP to IP')
                # self.add(udp)

        if e.ethertype == ETHER_TYPE_IPV6:
            # print('********* IPV6 **********')
            # print(f'In ipv4 packet: {e.ethertype}')
            ip = IPV6.from_packet(raw_packet[offset + 14:])
            # print_hex(raw_packet[offset + 14:])

            # print('Adding ethernet to ipV4')
            self.add(ip)
            if ip.protocol == IP_PROTO_TCP:
                tcp = TCP.from_packet(raw_packet[offset + 40:])
                # print('Adding to TCP to IP')
                self.add(tcp)
            elif ip.protocol == IP_PROTO_UDP:
                udp = UDP.from_packet(raw_packet[offset + 40:])
                # print('Adding to UDP to IP')
                self.add(udp)
            elif ip.protocol == IP_PROTO_ICMP:
                pass
                # udp = UDP.from_packet(raw_packet[34:])
                # print('Adding to ICMP to IP')
                # self.add(udp)

    def __str__(self) -> str:
        result = ''
        for _, l in self.layers.items():
            result += f'{l.name}: {l}\n'
        return str(result)

    @property
    def layers_count(self) -> int:
        return len(self.layers)

    def has_layer(self, layer_name) -> bool:
        result = self.layers.get(layer_name, None)
        return result is not None

    def get_layer(self, layer_name):
        return self.layers.get(layer_name, None)

    # def __add__(self, p):
    #     if p.name in self.layer_types:
    #         if len(self.layers) == 0:
    #             self.add(self)

    #         if p.name == 'arp':
    #             if self.layers_count == 1 and self.has_layer('ethernet'):
    #                 self.layers.get('ethernet').set_ether_type(0x0806)
    #                 return self.add(p)

    #         elif p.name == 'ipv4':
    #             if self.layers_count == 1 and self.has_layer('ethernet'):
    #                 self.layers.get('ethernet').set_ether_type(0x0800)
    #                 return self.add(p)

    #         elif p.name == 'tcp':
    #             if self.layers_count == 2 and self.has_layer('ipv4'):
    #                 return self.add(p)

    #         elif p.name == 'udp':
    #             if self.layers_count == 2 and self.has_layer('ipv4'):
    #                 return self.add(p)

    #         # ToDo: Fix this protocol assignation using a property setter
    #         elif p.name == 'icmp_echo':
    #             if self.layers_count == 2 and self.has_layer('ipv4') and self.has_layer('ethernet'):
    #                 self.layers.get('ipv4').protocol = ByteField(0x01)
    #                 return self.add(p)

    #         self.print_layers()
    #         return None

    # def __iadd__(self, p):
    #     return self.__add__(p)

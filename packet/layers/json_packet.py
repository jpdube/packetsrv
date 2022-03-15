from dataclasses import dataclass


@dataclass()
class JsonPacket:
    eth_src: str
    eth_dst: str
    eth_type: int
    eth_vlan_id: int
    ip_src: str
    ip_dst: str
    ip_proto: int
    packet: str

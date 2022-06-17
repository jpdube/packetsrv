class Field:
    def __init__(self, field: str, index: bool = False) -> None:
        self.field = field
        self.index = index

    def __str__(self) -> str:
        return f'Field: {self.field}, Index: {self.index}'

field_list = {
    "packet":               Field("packet", False),
    "timestamp":            Field("timestamp", True),
    "*":                    Field("*", True),
    "ether.mac.src":        Field("mac_src", True),
    "ether.mac.dst":        Field("mac_dst", True),
    "ether.type":           Field("ether_type", True),
    "ether.vlan":           Field("vlan_id", True),
    "ip.src":               Field("ip_src", True),
    "ip.dst":               Field("ip_dst", True),
    "ip.version":           Field("ip_version", False),
    "ip.header_len":        Field("ip_header_len", False),
    "ip.tos":               Field("ip_tos", False),
    "ip.total_len":         Field("ip_total_len", False),
    "ip.identification":    Field("ip_identification", False),
    "ip.flags":             Field("ip_flags", False),
    "ip.frag_offset":       Field("ip_frag_offset", False),
    "ip.ttl":               Field("ip_ttl", False),
    "ip.ttl":               Field("ip_ttl", False),
    "ip.proto":             Field("ip_proto", True),
    "ip.checksum":          Field("ip_checksum", False),
    "ip.checksum":          Field("ip_checksum", False),
    "ip.options":           Field("ip_options", False),
    "icmp.type":            Field("icmp_type", False),
    "icmp.code":            Field("icmp_code", False),
    "udp.sport":            Field("sport", True),
    "udp.dport":            Field("dport", True),
    "tcp.sport":            Field("sport", True),
    "tcp.dport":            Field("dport", True),
}

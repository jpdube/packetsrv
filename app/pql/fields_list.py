class Field:
    def __init__(self, field: str, index: bool = False) -> None:
        self.field = field
        self.index = index

    def __str__(self) -> str:
        return f'Field: {self.field}, Index: {self.index}'


field_list = {
    "packet":               Field("packet", False),
    "pkt.timestamp":        Field("pkt.timestamp", True),
    "pkt.ts_offset":        Field("pkt.ts_offset", True),
    "pkt.orig_len":         Field("pkt.org_len", True),
    "pkt.incl_len":         Field("pkt.incl_len", True),
    "*":                    Field("*", True),
    "eth.src":              Field("eth.src", True),
    "eth.dst":              Field("eth.dst", True),
    "eth.type":             Field("eth.type", True),
    "eth.vlan":             Field("eth.vlan", True),
    "eth.has_vlan":         Field("eth.has_vlan", True),
    "eth":                  Field("eth", False),
    "ip.src":               Field("ip.src", True),
    "ip.dst":               Field("ip.dst", True),
    "ip.version":           Field("ip.version", False),
    "ip.hdr_len":           Field("ip.hdr_len", False),
    "ip.tos":               Field("ip.tos", False),
    "ip.total_len":         Field("ip.total_len", False),
    "ip.identification":    Field("ip.identification", False),
    "ip.flags":             Field("ip.flags", False),
    "ip.frag_offset":       Field("ip.frag_offset", False),
    "ip.ttl":               Field("ip.ttl", False),
    "ip.proto":             Field("ip.proto", True),
    "ip.checksum":          Field("ip.checksum", False),
    "ip.checksum":          Field("ip.checksum", False),
    "ip.options":           Field("ip.options", False),
    "icmp.type":            Field("icmp.type", False),
    "icmp.code":            Field("icmp.code", False),
    "tcp.sport":            Field("tcp.sport", True),
    "tcp.dport":            Field("tcp.dport", True),
    "tcp.syn":              Field("tcp.syn", True),
    "tcp.ack":              Field("tcp.ack", True),
    "tcp.push":             Field("tcp.push", True),
    "tcp.fin":              Field("tcp.fin", True),
    "tcp.urg":              Field("tcp.urg", True),
    "tcp.rst":              Field("tcp.rst", True),
    "udp.sport":            Field("udp.sport", True),
    "udp.dport":            Field("udp.dport", True),
    "udp.length":           Field("udp.length", True),
    "udp.checksum":         Field("udp.checksum", True),
}

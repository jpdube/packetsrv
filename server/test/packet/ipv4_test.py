
from app.packet.layers.ipv4 import IPV4


def test_ipv4_packet_no_extensions():
    packet = [
        0x45, 0x00, 0x01, 0x88, 0xf9, 0x6c, 0x40, 0x00, 0x80, 0x06, 0xe9, 0x87, 0x0a, 0x00,
        0x00, 0xa5, 0x0a, 0xc0, 0x01, 0x17
    ]

    pkt = IPV4(bytes(packet))

    assert(pkt.version == 4)
    assert(pkt.ihl == 5)
    assert(pkt.tos == 0x00)
    assert(pkt.total_len == 0x0188)
    assert(pkt.identification == 0xf96c)
    assert(pkt.flags == 0x02)
    assert(pkt.frag_offset == 0x00)
    assert(pkt.ttl == 0x80)
    assert(pkt.protocol == 0x06)
    assert(pkt.checksum == 0xe987)
    assert(pkt.src_ip.value == 0x0a0000a5)
    assert(pkt.dst_ip.value == 0x0ac00117)

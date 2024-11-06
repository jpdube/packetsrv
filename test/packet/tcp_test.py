from app.packet.layers.tcp import TCP


def test_tcp_packet():
    packet = [
        0x01, 0xbb, 0xe4, 0x27, 0x5b, 0xf1, 0xb1, 0xaa, 0xcf, 0xf3, 0x9a, 0x04, 0x50, 0x18, 0x00, 0x3c,
        0x49, 0xb9, 0x00, 0x00
    ]

    pkt = TCP(bytes(packet))

    assert(pkt.src_port == 0x01bb)
    assert(pkt.dst_port == 0xe427)
    assert(pkt.seq_no == 0x5bf1b1aa)
    assert(pkt.ack_no == 0xcff39a04)
    assert(pkt.header_len == 0x05)
    assert(pkt.flags == 0x018)
    assert(pkt.window == 0x003c)
    assert(pkt.checksum == 0x49b9)
    assert(pkt.urgent_ptr == 0x00)
    assert(pkt.options == None)

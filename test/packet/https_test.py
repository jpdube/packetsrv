from app.packet.layers.https import Https


def test_https_packet():
    packet = [
        0x17, 0x03, 0x03, 0x3b, 0xfb, 0x01, 0x02, 0x03
    ]

    https = Https(bytes(packet))

    assert (https.content_type == 0x17)
    assert (https.tls_version == 0x0303)
    assert (https.length == 0x3bfb)
    assert (https.payload == bytes([0x01, 0x02, 0x03]))


def test_https_invalid_field():
    packet = [
        0x17, 0x03, 0x03, 0x3b, 0xfb, 0x01, 0x02, 0x03
    ]

    https = Https(bytes(packet))

    assert (https.get_field("https.unknown") == None)

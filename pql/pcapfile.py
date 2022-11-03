from struct import unpack
from packet.layers.packet_decode import PacketDecode

db_filename = "/Users/jpdube/hull-voip/db/index.db"
pcap_path = "/Users/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


class PcapFile:

    def __init__(self):
        self.filename = ""

    def open(self, filename: str):
        self.filename = filename

    def next(self):
        with open(f"{pcap_path}/{self.filename}.pcap", "rb") as f:
            _ = f.read(PCAP_GLOBAL_HEADER_SIZE)

            while True:
                header = f.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break

                incl_len = unpack("!I", header[12:16])[0]
                packet = f.read(incl_len)

                pd = PacketDecode()
                pd.decode(packet)

                yield pd

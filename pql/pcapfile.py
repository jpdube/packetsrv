from struct import unpack
from config.config import Config


PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


class PcapFile:

    def __init__(self):
        self.filename = ""
        self.offset = 0

    def open(self, filename: str):
        self.filename = filename

    def next(self):
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as f:
            _ = f.read(PCAP_GLOBAL_HEADER_SIZE)
            self.offset += 24

            while True:
                header = f.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break

                incl_len = unpack("!I", header[12:16])[0]
                packet = f.read(incl_len)

                yield (header, packet, self.offset)
                self.offset += incl_len + 16

    def get(self, ptr: int):
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as f:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                return None

            incl_len = unpack("!I", header[12:16])[0]
            packet = f.read(incl_len)

            return (header, packet)

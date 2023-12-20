from struct import pack, unpack

import pql.packet_index as pkt_index
from config.config import Config
from packet.layers.packet_decode import PacketDecode

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


class PcapFile:

    def __init__(self):
        self.filename = ""
        self.offset = 0

    def open(self, filename: str):
        self.filename = filename

    def next(self):
        try:
            with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as fd:
                _ = fd.read(PCAP_GLOBAL_HEADER_SIZE)
                self.offset += 24

                while True:
                    header = fd.read(PCAP_PACKET_HEADER_SIZE)
                    if len(header) == 0:
                        break

                    incl_len = unpack("!I", header[12:16])[0]
                    packet = fd.read(incl_len)

                    yield (header, packet, self.offset)
                    self.offset += incl_len + 16
        except IOError:
            print("IO error")

    def get(self, ptr: int, hdr_size: int = 0):
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as f:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                return None

            if hdr_size == 0:
                incl_len = unpack("!I", header[12:16])[0]
                packet = f.read(incl_len)
            else:
                packet = f.read(hdr_size)

            return (header, packet)

    #  0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                          Timestamp                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Packet pointer                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                          Index field                          |
    # |                            64 bits                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Destination ip                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                           Source ip                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |    Packet header len         |           Not used             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def create_index(self, file_id):
        offset = 0
        pd = PacketDecode()
        raw_index = bytearray()
        # index_list = []
        first_ts = None
        last_ts = None
        with open(f"{Config.pcap_path()}/{file_id}.pcap", "rb") as fd:
            _ = fd.read(PCAP_GLOBAL_HEADER_SIZE)
            offset += 24

            while True:
                header = fd.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break

                incl_len = unpack("!I", header[12:16])[0]
                packet = fd.read(incl_len)

                pd.decode(header, packet)
                ts = pd.get_field('pkt.timestamp')
                last_ts = ts
                if first_ts is None:
                    first_ts = ts

                raw_index.extend(
                    pack("!IIQIIH", ts, offset, pkt_index.packet_index(pd), pd.ip_dst, pd.ip_src, pd.header_len))
                offset += incl_len + 16

        with open(f"{Config.pcap_index()}/{file_id}.pidx", "wb") as f:
            f.write(raw_index)

        return (first_ts, last_ts, int(file_id))

    def build_master_index(self, master_index):
        with open(f"{Config.pcap_master_index()}/master.pidx", "wb") as f:
            for idx in master_index:
                f.write(pack('!III', *idx))

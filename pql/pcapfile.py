from struct import unpack
from config.config import Config
from packet.layers.packet_decode import PacketDecode
from struct import pack
from packet.utils.print_hex import HexDump

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

    def get(self, ptr: int):
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as f:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                return None

            incl_len = unpack("!I", header[12:16])[0]
            packet = f.read(incl_len)

            return (header, packet)

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
                    pack("!III", ts, offset, self.packet_index(pd)))
                offset += incl_len + 16

        # print(f"Index file: {Config.pcap_path()}/{file_id}.pidx")
        with open(f"{Config.pcap_index()}/{file_id}.pidx", "wb") as f:
            f.write(raw_index)

        return (first_ts, last_ts, int(file_id))

    def packet_index(self, pd: PacketDecode) -> int:
        pindex = 0

        if pd.has_ethernet:
            pindex = pindex + 0x01
        if pd.has_ipv4:
            pindex = pindex + 0x04
        if pd.has_icmp:
            pindex = pindex + 0x08
        if pd.has_udp:
            pindex = pindex + 0x10
        if pd.has_tcp:
            pindex = pindex + 0x20
        if pd.has_dns:
            pindex = pindex + 0x40
        if pd.has_dhcp:
            pindex = pindex + 0x80
        if pd.has_https:
            pindex = pindex + 0x100

        # print(f"Bit index: {pindex:x}")
        return pindex

    def build_master_index(self, master_index):
        with open(f"{Config.pcap_index()}/master.pidx", "wb") as f:
            for idx in master_index:
                # print(idx)
                f.write(pack('!III', *idx))

from datetime import datetime
from multiprocessing import Pool
from struct import unpack

from packet.layers.packet_decode import PacketDecode
from packet.layers.packet_builder import PacketBuilder
from packet.utils.print_hex import format_hex

db_filename = "/Users/jpdube/hull-voip/db/index.db"
pcap_path = "/Users/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


def packet_search(params):
    result = []

    start_time = datetime.now()

    # field = params["filter"][0]
    # value = params["filter"][1]

    filename = f'{pcap_path}/{params["file"]}.pcap'

    pd = PacketDecode()
    with open(filename, "rb") as f:
        _ = f.read(PCAP_GLOBAL_HEADER_SIZE)

        while True:
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                break
            incl_len = unpack("!I", header[12:16])[0]
            packet = f.read(incl_len)

            pd.decode(packet)
            if pd.ip_src == 0xc0a803e6:
                pb = PacketBuilder()
                pb.from_bytes(packet)
                result.append(pb)

    print(
        f"File: [{filename}] Found:{len(result)}, Time:{datetime.now() - start_time}")

    for p in result:
        print(p)

    return len(result)


def search_parallel():
    pool = Pool()
    flist = []
    start_time = datetime.now()
    for i in range(1):
        params = {
            "file": i,
            "filter": ("ip.src", 0xc0a80301)
        }
        flist.append(params)
    result = pool.map(packet_search, flist)

    print(
        f"---> Total Time: {datetime.now() - start_time} Result: {sum(result)}")
    print("main script")

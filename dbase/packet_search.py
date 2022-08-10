from datetime import datetime
from multiprocessing import Pool
from struct import unpack
from typing import Dict

from packet.layers.packet_decode import PacketDecode
from packet.utils.print_hex import format_hex

db_filename = "/home/jpdube/hull-voip/db/index.db"
pcap_path = "/home/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


def packet_search(params):
    result = []

    start_time = datetime.now()

    pd = PacketDecode()
    field = params["filter"][0]
    value = params["filter"][1]

    with open(f'{pcap_path}/{params["file"]}.pcap', "rb") as f:
        _ = f.read(PCAP_GLOBAL_HEADER_SIZE)

        while True:
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                break
            incl_len = unpack("!I", header[12:16])[0]
            # hl = int(header[16])
            # packet = f.read(hl)
            # print(f"{format_hex(packet)}")
            # f.seek(incl_len - hl, 1)
            packet = f.read(incl_len)

            pd.packet = packet

            # if unpack("!I", packet[30:34])[0] == value:
            if pd.search_field(field, value):
                # pb = PacketBuilder()
                # pb.from_bytes(packet)
                # result.append(pb)
                result.append(True)

    # print(f"Found:{len(result)}, Time:{datetime.now() - start_time}")
    return result


def search_parallel():
    pool = Pool()
    flist = []
    start_time = datetime.now()
    for i in range(400):
        params = {
            "file": i,
            "filter": ("ip.src", 0xc0a80301)
        }
        flist.append(params)
    # result = packet_search(params)
    result = pool.map(packet_search, flist)

    print(f"---> Total Time: {datetime.now() - start_time}")
    print("main script")
    total = 0

    # for i,r in enumerate(result):
    # print(f'file: {i}, Count: {len(r)}')
    # total += len(r)
    # for p in r:
    #     print(f'file: {i}, Count: {len(r)}')
    # print(f"Total packet found: {total}")

from ipaddress import ip_address
from packet.layers.fields import IPv4Address
from typing import Dict, List
from packet.layers import pcap_header
from packet.layers.pcap_header import PcapHeader
from packet.layers.packet_builder import PacketBuilder
from packet.layers.layer_type import LayerID
from struct import unpack
from multiprocessing import Pool
from datetime import datetime
from packet.layers.packet_decode import PacketDecode

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

    with open(params["file"], "rb") as f:
        _ = f.read(PCAP_GLOBAL_HEADER_SIZE)        
        
        while True: 
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                break
            incl_len = unpack("!I", header[12:16])[0]
            packet = f.read(incl_len)

            pd.packet = packet

            # if unpack("!I", packet[30:34])[0] == value:
            if pd.search_field(field, value):
                pb = PacketBuilder(packet)
                # result.append(pb)
                result.append(pb)

    print(f"Time: {datetime.now() - start_time}")
    return result 

def search_parallel():
    pool = Pool()
    flist = []
    for i in range(25):
        params = {
            "file": f"{pcap_path}/{i}.pcap",
            "filter": ("ip.src", 0xc0a803e6)
        }
        flist.append(params)

    result = pool.map(packet_search, flist)
    
    print("main script")
    total = 0
    for i,r in enumerate(result):
        print(f'file: {i}, Count: {len(r)}')
        total += len(r)
        # for p in r:
        #     print(f'file: {i}, Count: {len(r)}')
    print(f"Total packet found: {total}")


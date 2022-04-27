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

db_filename = "/Users/jpdube/hull-voip/db/index.db"
pcap_path = "/Users/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

def packet_search(filename: str):
    result = []

    start_time = datetime.now()
    with open(filename, "rb") as f:
        _ = f.read(PCAP_GLOBAL_HEADER_SIZE)        
        
        ip_lookup = 0xc0a803e6 
        # ip_lookup = IPv4Address("192.168.3.124")
        while True: 
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                break
            # pcap_hdr = PcapHeader(header)
            incl_len = unpack("!I", header[12:16])[0]
            packet = f.read(incl_len)
            # ip_addr = IPv4Address(packet[30:34])
            # print(f"IP: {unpack('!I', packet[30:34])}")
            if unpack("!I", packet[30:34])[0] == ip_lookup:
                # print(f"{ip_lookup:x}")
                # pb = PacketBuilder(packet)
                # pb.from_bytes(packet)
                result.append(True)

    print(f"Time: {datetime.now() - start_time}")
    return result 

def search_parallel():
    pool = Pool()
    flist = []
    for i in range(200):
        flist.append(f"/Users/jpdube/hull-voip/db/pcap/{i}.pcap")

    result = pool.map(packet_search, flist)
    
    print("main script")
    # for i,r in enumerate(result):
    #     for p in r:
    #         print(f'file: {i}, Packet: {p}')
    print("end main script")



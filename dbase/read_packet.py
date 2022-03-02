from sqlite3.dbapi2 import Cursor
import sys
import sqlite3
from datetime import datetime
from packet.layers.pcap_header import PcapHeader
from packet.layers.packet_builder import PacketBuilder 

db_filename = "/Users/jpdube/hull-voip/db/index.db"
pcap_path = "/Users/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 12
FILE_ID = 11
PACKET_PTR = 10

filter_count = 0


def get_packet(file_id: int, ptr_list):
    global filter_count
    print(f"Getting from: {file_id}, {len(ptr_list)}")
    # print('.', end='', flush=True)
    with open(f"{pcap_path}/{file_id}.pcap", "rb") as f:
        for ptr in ptr_list:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            pcap_hdr = PcapHeader(header)

            packet = f.read(pcap_hdr.incl_len)

            pb = PacketBuilder()
            pb.from_bytes(packet, pcap_hdr)

            pb.print_layers()
            filter_count += 1
            print(filter_count)


# id integer not null primary key,
#          ip_src integer,
#          ip_dst integer,
#          mac_src integer,
#          mac_dst integer,
#          ether_type integer,
#          ip_proto integer,
#          vlan_id integer,
#          sport integer,
#          dport integer,
#          file_ptr integer,
#          file_id integer,
#          timestamp timestamp);
def sql(pql: str) -> Cursor:
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    conn.execute("""PRAGMA synchronous = OFF""")
    conn.execute("""PRAGMA journal_mode = MEMORY;""")
    conn.execute("""PRAGMA threads = 4;""")
    conn.execute("""PRAGMA temp_store = memory;""")
    conn.execute("""PRAGMA locking_mode = EXCLUSIVE;""")
    cursor.execute(pql)
    rows = cursor

    return rows


def query(pql: str, header=False):
    packet_list = sql(pql)
    start_time = datetime.now()
    count = 0
    current_id = -1
    ptr_list = []
    if packet_list:
        for p in packet_list:
            if current_id == -1:
                current_id = p[FILE_ID]

            if p[FILE_ID] == current_id:
                ptr_list.append(p[PACKET_PTR])
            else:
                get_packet(current_id, ptr_list)
                current_id = p[FILE_ID]
                ptr_list = []
                ptr_list.append(p[PACKET_PTR])

            count += 1
        get_packet(current_id, ptr_list)

    print(f"Count: {count}")
    print(f"Execution time: {datetime.now() - start_time}")

import sqlite3
from datetime import datetime
from sqlite3.dbapi2 import Cursor

# from dbase.dbcache import IndexCache
from dbase.sql_statement import SqlStatement
# from dbengine import Index
from packet.layers.packet_builder import PacketBuilder
from packet.layers.pcap_header import PcapHeader
from config.config import Config

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 12
FILE_ID = 11
PACKET_PTR = 10
ID = 0

filter_count = 0


def get_packet(file_id: int, ptr_list):
    global filter_count
    # print(f"=============================================")
    # print(f"===> Getting from: {file_id}, {len(ptr_list)}")
    # print(f"=============================================")
    # print('.', end='', flush=True)
    packet_list = []
    cache_hit = 0
    file_hit = 0
    with open(f"{Config.get('pcap_path')}/{file_id}.pcap", "rb") as f:
        for ptr in ptr_list:
            # print(f"ID: {ptr[1]}")
            # cached_packet = IndexCache.get_packet(ptr[1])
            # if cached_packet is not None:
            #     cache_hit += 1
            #     packet_list.append(cached_packet.export())
            #     f.seek(ptr[0] + cached_packet.get_layer(0xff).incl_len)
            # else:
            file_hit += 1
            f.seek(ptr[0])
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            pcap_hdr = PcapHeader(header)
            packet = f.read(pcap_hdr.incl_len)
            pb = PacketBuilder()
            pb.from_bytes(packet, pcap_hdr)
            packet_list.append(pb.export())
            # IndexCache.save_packet(ptr[1], pb)
            # filter_count += 1
        # print(
        #     f"Excution plan: Total:{filter_count}, Cache hit: {cache_hit}, File hit: {file_hit}")
    return packet_list


def sql(pql: SqlStatement) -> Cursor:
    conn = sqlite3.connect(Config.get("db_filename"))
    cursor = conn.cursor()

    conn.execute("""PRAGMA synchronous = OFF""")
    conn.execute("""PRAGMA journal_mode = MEMORY;""")
    conn.execute("""PRAGMA threads = 4;""")
    conn.execute("""PRAGMA temp_store = memory;""")
    cursor.execute(pql.build())
    # cursor.execute(pql)

    # IndexCache.get(pql)
    # IndexCache.save(pql)
    # print(f"Index row count: {IndexCache.count()}")
    # rows = cursor.fetchall()

    return cursor


def query(pql: str):
    start_time = datetime.now()
    packet_list = sql(pql)
    # print(f"*** PACKET LIST: {len(list(packet_list))}")
    return_list = []
    count = 0
    current_id = -1
    ptr_list = []
    if packet_list:
        for p in packet_list:
            if current_id == -1:
                current_id = p[FILE_ID]

            if p[FILE_ID] == current_id:
                ptr_list.append((p[PACKET_PTR], p[ID]))
            else:
                return_list.extend(get_packet(current_id, ptr_list))
                current_id = p[FILE_ID]
                ptr_list = []
                ptr_list.append((p[PACKET_PTR], p[ID]))

            count += 1
        if current_id != -1:
            return_list.extend(get_packet(current_id, ptr_list))

    print(f'*** Packet list length: {len(return_list)}')

    print(f"Count: {count}")
    print(f"Execution time: {datetime.now() - start_time}")

    return return_list

import sys
import sqlite3
from datetime import datetime
from fw.utils.print_hex import print_hex
from fw.layers.fields import MacAddress, ShortField
from fw.layers.packet_builder import PacketBuilder, ID_ETHERNET
from query_processor import QueryProcessor
from struct import unpack

db_filename = "/Users/jpdube/hull-voip/db.hull/index.db"
pcap_path = "/Users/jpdube/hull-voip/db.hull/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 9
FILE_ID = 8
PACKET_PTR = 7


filter_count = 0


def get_packet(file_id: int, ptr_list):
    global filter_count
    print(f"Getting from: {file_id}, {len(ptr_list)}")
    # print('.', end='', flush=True)
    with open(f"{pcap_path}/{file_id}.pcap", "rb") as f:
        for ptr in ptr_list:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            pkt_len = unpack("!I", header[8:12])[0]

            # print(f'Packet header for: {file_id}:{ptr}:{pkt_len}')
            # print_hex(header)

            packet = f.read(pkt_len)

            pb = PacketBuilder()
            pb.from_bytes(packet)

            e = pb.get_layer(ID_ETHERNET)
            if e.vlan_id == 51:  # and e.ethertype == 0x0806:
                pb.print_layers()
                filter_count += 1
                print(filter_count)


def sql(start_date: datetime, end_date: datetime) -> list:
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    conn.execute("""PRAGMA synchronous = OFF""")
    conn.execute("""PRAGMA journal_mode = MEMORY;""")
    conn.execute("""PRAGMA threads = 4;""")
    conn.execute("""PRAGMA temp_store = memory;""")
    conn.execute("""PRAGMA locking_mode = EXCLUSIVE;""")
    # cursor.execute(
    # f'select * from packet where file_id = 0 and file_ptr < 32768 order by timestamp desc')
    cursor.execute(
        f"select * from packet where timestamp between {int(start_date.timestamp())} and {int(end_date.timestamp())}"
    )
    rows = cursor.fetchall()

    return rows
    # for row in rows:
    #     print(f'{datetime.fromtimestamp(row[9])}, {row[8]}, {row[7]}')


def query(start_date, end_date):
    start = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

    packet_list = sql(start, end)
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
            # print(
            #     f'Timestamp: {datetime.fromtimestamp(p[9])}, file_id: {p[FILE_ID]}, ptr: {p[PACKET_PTR]}')
            # get_packet(p[FILE_ID], p[PACKET_PTR])

    print(f"Count: {count}")
    print(f"Execution time: {datetime.now() - start_time}")


if __name__ == "__main__":
    qp = QueryProcessor()
    qp.get(ip_src="192.168.242.22")
    query(sys.argv[1], sys.argv[2])

import sys
import sqlite3
from datetime import datetime
from fw.utils.print_hex import print_hex
from fw.layers.fields import MacAddress, ShortField
from fw.layers.raw_packet import RawPacket
from fw.layers.packet_builder import PacketBuilder
from query_processor import QueryProcessor

db_filename = '/Users/jpdube/hull-voip/db.hull/index.db'
pcap_path = '/Users/jpdube/hull-voip/db.hull/pcap'

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 9
FILE_ID = 8
PACKET_PTR = 7


def get_packet(file_id: int, ptr_list):
    print(f'Getting from: {file_id}, {ptr_list[0]}')
    # print('.', end='', flush=True)
    with open(f'{pcap_path}/{file_id}.pcap', 'rb') as f:
        for ptr in ptr_list:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            pkt_len = 0
            pkt_len += header[8] << 24
            pkt_len += header[9] << 16
            pkt_len += header[10] << 8
            pkt_len += header[11]

            # print(f'Packet header for: {file_id}:{ptr}:{pkt_len}')
            # print_hex(header)

            packet = f.read(pkt_len)
            # print_hex(packet)
            pb = PacketBuilder()
            pb.from_bytes(packet)

            e = pb.get_layer('ethernet')
            if e.vlan_id.value == 51:
                print(f'==============> {e.vlan_id.value}')
                pb.print_layers()
                print('-' * 50)

            # p = RawPacket(packet)
            # e = p.get_ethernet()
            # print(e)
            # print(p)


def sql(start_date: datetime, end_date: datetime) -> list:
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    conn.execute('''PRAGMA synchronous = OFF''')
    conn.execute('''PRAGMA journal_mode = MEMORY;''')
    conn.execute('''PRAGMA threads = 4;''')
    conn.execute('''PRAGMA temp_store = memory;''')
    conn.execute('''PRAGMA locking_mode = EXCLUSIVE;''')
    # cursor.execute(
    # f'select * from packet where file_id = 0 and file_ptr < 32768 order by timestamp desc')
    cursor.execute(
        f'select * from packet where timestamp between {int(start_date.timestamp())} and {int(end_date.timestamp())} order by timestamp')
    rows = cursor.fetchall()

    return rows
    # for row in rows:
    #     print(f'{datetime.fromtimestamp(row[9])}, {row[8]}, {row[7]}')


def query(start_date, end_date):
    start = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

    packet_list = sql(start, end)
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

            count += 1
            # print(
            #     f'Timestamp: {datetime.fromtimestamp(p[9])}, file_id: {p[FILE_ID]}, ptr: {p[PACKET_PTR]}')
            # get_packet(p[FILE_ID], p[PACKET_PTR])

    print(f'Count: {count}')

if __name__ == '__main__':
    qp = QueryProcessor()
    qp.get(ip_src='192.168.242.22')
    start_time = datetime.now()
    query(sys.argv[1], sys.argv[2])
    print(f'Execution time: {datetime.now() - start_time}')

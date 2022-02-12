import sys
import sqlite3
from datetime import datetime
from fw.utils.print_hex import print_hex
from fw.layers.fields import MacAddress, ShortField
from fw.layers.raw_packet import RawPacket
from fw.layers.packet_builder import PacketBuilder


db_filename = '/Users/jpdube/softdev/rust/pcapdb/db/index.db'
pcap_path = '/Users/jpdube/softdev/rust/pcapdb/db/pcap'

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 9
FILE_ID = 8
PACKET_PTR = 7

def get(mac_src=None,
        mac_dst=None, 
        ip_src=None, 
        ip_dst=None, 
        sport=None, 
        dport=None, 
        start_ts=datetime.now(), 
        end_ts=datetime.now()):
   
    params = locals()
    select_fields = {}

    for k, v in params.items():
        # print(f'K:{k}, V:{v}')
        if v is not None:
            select_fields[k] = v

    print('-----------------')
    print(select_fields)
    print('-----------------')
        
    sql = 'SELECT '
    for i, f in enumerate(select_fields.keys()):
        sql += f
        
        if i < len(select_fields) - 1:
            sql += ', '
    
    sql += ' FROM packet '

    sql += f' WHERE timestamp between {int(start_ts.timestamp())} and {int(end_ts.timestamp())} '

    print(sql)

def get_packet(file_id: int, ptr: int):
    with open(f'{pcap_path}/{file_id}.pcap', 'rb') as f:
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
        # pb.print_layers()

        # p = RawPacket(packet)
        # e = p.get_ethernet()
        # print(e)
        # print(p)


def sql(start_date: datetime, end_date: datetime) -> list:
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    # cursor.execute(
    # f'select * from packet where file_id = 0 and file_ptr < 32768 order by timestamp desc')
    cursor.execute(
        f'select * from packet where timestamp between {int(start_date.timestamp())} and {int(end_date.timestamp())} order by timestamp desc')
    rows = cursor.fetchall()

    return rows
    # for row in rows:
    #     print(f'{datetime.fromtimestamp(row[9])}, {row[8]}, {row[7]}')


def query(start_date, end_date):
    start = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

    packet_list = sql(start, end)
    count = 0
    if packet_list:
        for p in packet_list:
            count += 1
            # print(
            #     f'Timestamp: {datetime.fromtimestamp(p[9])}, file_id: {p[FILE_ID]}, ptr: {p[PACKET_PTR]}')
            # get_packet(p[FILE_ID], p[PACKET_PTR])

    print(f'Count: {count}')

if __name__ == '__main__':
    get(ip_src='192.168.242.22')
    start_time = datetime.now()
    query(sys.argv[1], sys.argv[2])
    print(f'Execution time: {datetime.now() - start_time}')

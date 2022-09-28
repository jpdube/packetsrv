import sqlite3
from datetime import datetime
from multiprocessing import Pool
from struct import unpack
from packet.layers.packet_decode import PacketDecode

pcap_path = "/Users/jpdube/hull-voip/db/pcap"
index_path = "/Users/jpdube/hull-voip/db"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

class Indexer:
    def __init__(self):
        self.index_name = f"{index_path}/index3.db"
        print(f"Index filename is: {self.index_name}")

    def pcap_read(self, file_id):
        result = []
        count = 0

        start_time = datetime.now()
        pcap_file = f"{pcap_path}/{file_id}.pcap"
        pd = PacketDecode()
        with open(pcap_file, "rb") as f:
            _ = f.read(PCAP_GLOBAL_HEADER_SIZE)

            while True:
                header = f.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break
                timestamp = unpack("!I", header[0:4])[0]
                incl_len = unpack("!I", header[12:16])[0]
                packet = f.read(incl_len)

                pd.decode(packet)

                pkt = [pd.ip_src, pd.ip_dst, pd.mac_src, pd.mac_dst, pd.ethertype,
                       pd.ip_proto, pd.vlan_id, pd.sport, pd.dport, f.tell(), timestamp]

                packet_info = { "pkt": pkt }    
                # print(f"{pd.ip_proto:x}")
                if pd.ip_proto == 0x06:
                    tcp = [pd.tcp_ack_no, pd.tcp_seq_no, pd.tcp_flag]
                    packet_info["tcp"] = tcp

                result.append(packet_info)
                count += 1

                if len(result) == 4096:
                    self.insert(result)
                    result = []

        self.insert(result)
        exec_time = datetime.now() - start_time
        print(
            f"Found:{count}, Time:{exec_time}, Packet per sec: {count / exec_time.microseconds * 1_000_000:8}")
        return count

    def search_parallel(self):
        pool = Pool()
        flist = []
        start_time = datetime.now()
        for i in range(16):
            flist.append(i)
        # result = packet_search(params)
        result = pool.map(self.indexer, flist)

        exec_time = datetime.now() - start_time
        print(
            f"---> Total Time: {exec_time}, Pkts count: {sum(result)}, Pkts per sec: {int(float(sum(result))/exec_time.total_seconds())}")
        print("main script")

    def insert(self, packet_info):

        for p in packet_info:
            insert_stmt = f"""INSERT OR IGNORE INTO packet
                                    (ip_src,
                                    ip_dst,
                                    mac_src,
                                    mac_dst,
                                    ether_type,
                                    ip_proto,
                                    vlan_id,
                                    sport,
                                    dport,
                                    file_ptr,
                                    timestamp)
                                VALUES(?,?,?,?,?,?,?,?,?,?,?)"""
            result = self.cursor.execute(insert_stmt, p["pkt"])

            if tcp_info := p.get("tcp", None):
                insert_tcp = f"""INSERT OR IGNORE INTO tcp_packet
                                        (packet_id,
                                        ack,
                                        syn,
                                        tcp_flag
                                        )
                                    VALUES(?,?,?,?)"""
                self.cursor.execute(insert_tcp, [result.lastrowid] + tcp_info)

            # print(result.lastrowid)

        self.conn.commit()

    def indexer(self, file_id):
        # index_name = f"{pcap_path}/{file_id}.db"
        # print(f"Base filename is: {index_name}")

        self.conn = sqlite3.connect(":memory")
        # self.conn = sqlite3.connect(self.index_name)
        self.cursor = self.conn.cursor()

        # PRAGMA cache_size = 1000000;
        # PRAGMA temp_store = MEMORY;
        # PRAGMA threads=8;
        # PRAGMA locking_mode = EXCLUSIVE;
        # PRAGMA journal_mode = WAL;
        self.cursor.executescript("""
                PRAGMA synchronous = OFF;
                PRAGMA temp_store = MEMORY;
                """)

        self.create_tables()
        # self.conn.execute("DROP TABLE if exists packet;")

        count = self.pcap_read(file_id)
        return count

    def create_tables(self):
        self.conn.execute("""create table if not exists packet(
                id integer not null primary key,
                ip_src integer,
                ip_dst integer,
                mac_src integer,
                mac_dst integer,
                ether_type integer,
                ip_proto integer,
                vlan_id integer,
                sport integer,
                dport integer,
                file_ptr integer,
                timestamp timestamp
                )""", [],)

        self.conn.execute("""create table if not exists tcp_packet(
                id integer not null primary key,
                packet_id integer not null,
                ack integer,
                syn integer,
                tcp_flag integer,
                window_size integer,
                foreign key (packet_id) references packet(id) on delete cascade

                )""", [],)
        self.conn.commit()

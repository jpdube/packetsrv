import sqlite3
from struct import pack, unpack

import pql.packet_index as pkt_index
from config.config import Config
from packet.layers.packet_decode import PacketDecode

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


class PcapFile:

    def __init__(self):
        self.filename = ""
        self.offset = 0

    def open(self, filename: str):
        self.filename = filename

    def next(self):
        try:
            with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as fd:
                _ = fd.read(PCAP_GLOBAL_HEADER_SIZE)
                self.offset += 24

                while True:
                    header = fd.read(PCAP_PACKET_HEADER_SIZE)
                    if len(header) == 0:
                        break

                    incl_len = unpack("!I", header[12:16])[0]
                    packet = fd.read(incl_len)

                    yield (header, packet, self.offset)
                    self.offset += incl_len + 16
        except IOError:
            print("IO error")

    def get(self, ptr: int, hdr_size: int = 0):
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as f:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                return None

            if hdr_size == 0:
                incl_len = unpack("!I", header[12:16])[0]
                packet = f.read(incl_len)
            else:
                packet = f.read(hdr_size)

            return (header, packet)

    def create_index(self, file_id):
        offset = 0
        pd = PacketDecode()
        # raw_index = bytearray()
        index_list = []
        first_ts = None
        last_ts = None
        with open(f"{Config.pcap_path()}/{file_id}.pcap", "rb") as fd:
            _ = fd.read(PCAP_GLOBAL_HEADER_SIZE)
            offset += 24

            while True:
                header = fd.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break

                incl_len = unpack("!I", header[12:16])[0]
                packet = fd.read(incl_len)

                pd.decode(header, packet)
                ts = pd.get_field('pkt.timestamp')
                last_ts = ts
                if first_ts is None:
                    first_ts = ts

                dport = 0
                sport = 0
                if pd.has_tcp:
                    dport = pd.tcp_dport
                    sport = pd.tcp_sport
                elif pd.has_udp:
                    dport = pd.udp_dport
                    sport = pd.udp_sport

                index_list.append((ts, offset, pkt_index.packet_index(
                    pd), pd.ip_dst, pd.ip_src, pd.header_len, dport, sport))

                offset += incl_len + 16

        db_name = f"{Config.pcap_index()}/{file_id}.db"
        self.create_db_index(db_name, index_list)
        print(f"{db_name} completed...")

        return (first_ts, last_ts, int(file_id))

    def create_db_index(self, db_name: str, index_list):
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute("drop table if exists pkt_index;")
        c.execute("""
                  create table if not exists pkt_index (
                      id integer primary key autoincrement,
                      timestamp integer not null,
                      pkt_ptr integer not null,
                      pindex integer not null,
                      ip_dst integer,
                      ip_src integer,
                      header_len integer not null,
                      dport integer,
                      sport integer
                      );
                  """)
        c.execute('''PRAGMA synchronous = EXTRA''')
        c.execute('''PRAGMA journal_mode = WAL''')
        c.executemany(
            "INSERT INTO pkt_index (timestamp, pkt_ptr, pindex, ip_dst, ip_src, header_len, dport, sport) VALUES (?,?,?,?,?,?,?,?)", index_list)
        conn.commit()

        c.execute("""
                  create index idx_ip_src
                  on pkt_index (ip_src);
                  """)
        c.execute("""
                  create index idx_ip_dst
                  on pkt_index (ip_dst);
                  """)
        c.execute("""
                  create index idx_pindex
                  on pkt_index (pindex);
                  """)

        conn.close()

    def build_master_index(self, master_index):
        db_name = f"{Config.pcap_master_index()}/master.db"
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute("drop table if exists master_index;")
        c.execute("""
                  create table if not exists master_index (
                      id integer primary key autoincrement,
                      start_ts integer not null,
                      end_ts integer not null,
                      file_id integer not null
                      );
                  """)
        c.execute('''PRAGMA synchronous = EXTRA''')
        c.execute('''PRAGMA journal_mode = WAL''')
        c.executemany(
            "INSERT INTO master_index (start_ts, end_ts, file_id) VALUES (?,?,?)", master_index)
        conn.commit()

        c.execute("""
                  create index idx_timestamp
                  on master_index (start_ts, end_ts);
                  """)

        conn.close()

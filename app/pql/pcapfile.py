import logging
import os
import sqlite3
import time
from struct import unpack
from typing import Any, Generator, Tuple
from collections import defaultdict

import pql.packet_index as pkt_index
from config.config import Config
from packet.layers.packet_decode import PacketDecode
from packet.layers.packet_hdr import PktHeader
from struct import pack

log = logging.getLogger("packetdb")


PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16
MAGIC_BE = 0xa1b2c3d4
MAGIC_LE = 0xd4c3b2a1


def decode_header(header: bytes, byte_order: str) -> PktHeader:
    timestamp = unpack(byte_order, header[0:4])[0]
    ts_offset = unpack(byte_order, header[4:8])[0]
    orig_len = unpack(byte_order, header[8:12])[0]
    inc_len = unpack(byte_order, header[12:16])[0]

    return PktHeader(timestamp=timestamp, ts_offset=ts_offset, orig_len=orig_len, incl_len=inc_len)


class PcapFile:

    def __init__(self):
        self.filename = ""
        self.offset = 0

    def open(self, filename: str):
        self.filename = filename

    def next(self):
        try:
            with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as fd:
                glob_header = fd.read(PCAP_GLOBAL_HEADER_SIZE)
                if unpack("!I", glob_header[0:4])[0] == MAGIC_BE:
                    byte_order = "!I"
                else:
                    byte_order = "<I"

                self.offset += 24

                while True:
                    header = fd.read(PCAP_PACKET_HEADER_SIZE)
                    if len(header) == 0:
                        break
                    else:
                        pkt_header = decode_header(header, byte_order)

                    incl_len = pkt_header.incl_len
                    packet = fd.read(incl_len)

                    yield (pkt_header, packet, self.offset)
                    self.offset += incl_len + 16
        except IOError:
            log.error("IO error")

    def get(self, ptr: int, hdr_size: int = 0) -> Tuple[PktHeader, bytes] | None:
        with open(f"{Config.pcap_path()}/{self.filename}.pcap", "rb") as fd:
            glob_header = fd.read(PCAP_GLOBAL_HEADER_SIZE)
            if unpack("!I", glob_header[0:4])[0] == MAGIC_BE:
                byte_order = "!I"
            else:
                byte_order = "<I"

            fd.seek(ptr)
            header = fd.read(PCAP_PACKET_HEADER_SIZE)
            if len(header) == 0:
                return None

            pkt_header = decode_header(header, byte_order)
            pkt_header.file_ptr = int(self.filename)
            pkt_header.pkt_ptr = ptr

            if hdr_size == 0:
                incl_len = pkt_header.incl_len
                packet = fd.read(incl_len)
            else:
                packet = fd.read(hdr_size)

            return (pkt_header, packet)

    def create_index(self, file_id):
        offset = 0
        pd = PacketDecode()
        index_list = []
        first_ts = None
        last_ts = None
        ip_src_index = defaultdict(list)

        start_ts = time.time()

        with open(f"{Config.pcap_path()}/{file_id}.pcap", "rb") as fd:
            glob_header = fd.read(PCAP_GLOBAL_HEADER_SIZE)
            if unpack("!I", glob_header[0:4])[0] == MAGIC_BE:
                byte_order = "!I"
            else:
                byte_order = "<I"

            offset += 24

            while True:
                header = fd.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break

                pkt_header = decode_header(header, byte_order)
                incl_len = pkt_header.incl_len
                packet = fd.read(incl_len)

                pd.decode(pkt_header, packet)
                ts = pd.get_field('pkt.timestamp')
                end_ts_decode = time.time()

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

                ip_src_index[pd.ip_src].append(offset)
                index_list.append((ts, offset, pkt_index.packet_index(
                    pd), pd.ip_dst, pd.ip_src, pd.header_len, dport, sport))

                offset += incl_len + 16

        db_name = f"{Config.pcap_index()}/{file_id}.pidx"
        end_time = time.time() - start_ts

        self.create_db_index(db_name, index_list)
        log.info(f"{db_name} completed, {len(index_list)} packets indexed, time: {end_time:.3} {(end_time / len(index_list)) * 1_000_000:.2f}us/packet")
        # log.info(ip_src_index)
        # self.save_ip_index(file_id, ip_src_index)

        return (first_ts, last_ts, int(file_id))

    def create_db_index(self, db_name: str, index_list):
        with open(db_name, "wb") as f:
            for ix in index_list:
                index_line = pack(">IIIIIHHH", *ix)
                f.write(index_line)

    def build_master_index(self, master_index, clean=False):
        db_name = f"{Config.pcap_master_index()}"
        conn = sqlite3.connect(db_name)
        c = conn.cursor()

        if clean:
            c.execute("drop table if exists master_index;")

        c.execute("""
                    create table if not exists master_index (
                        id integer primary key autoincrement,
                        start_ts integer not null,
                        end_ts integer not null,
                        file_id integer not null
                        );
                    """)
        c.execute('''PRAGMA synchronous = OFF''')
        c.execute('''PRAGMA journal_mode = MEMORY''')

        c.executemany(
            "INSERT INTO master_index (start_ts, end_ts, file_id) VALUES (?,?,?)", master_index)
        conn.commit()

        c.execute("""
                    create index if not exists  idx_timestamp
                    on master_index (start_ts, end_ts);
                    """)

        conn.close()

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]

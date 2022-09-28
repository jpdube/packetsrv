import sqlite3
import os
from datetime import datetime
from multiprocessing import Pool
from struct import unpack
from packet.layers.packet_builder import PacketBuilder

# from packet.layers.packet_decode import PacketDecode
from packet.layers.layer_type import LayerID
from packet.utils.print_hex import format_hex

pcap_path = "/home/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16


class Indexer:
    def __init__(self, filename):
        self.pcap_file = filename
        self.index_name = os.path.splitext(filename)[0] + ".db"

    def pcap_read(self):
        result = []

        start_time = datetime.now()

        with open(self.pcap_file, "rb") as f:
            _ = f.read(PCAP_GLOBAL_HEADER_SIZE)

            while True:
                header = f.read(PCAP_PACKET_HEADER_SIZE)
                if len(header) == 0:
                    break
                timestamp = unpack("!I", header[0:4])[0]
                incl_len = unpack("!I", header[12:16])[0]
                # hl = int(header[16])
                # packet = f.read(hl)
                # print(f"{format_hex(packet)}")
                # f.seek(incl_len - hl, 1)
                packet = f.read(incl_len)

                pb = PacketBuilder()
                pb.from_bytes(packet)

                self.insert(pb, f.tell(), timestamp)

        print(f"Found:{len(result)}, Time:{datetime.now() - start_time}")
        return result

    def insert(self, pb: PacketBuilder, ptr: int, timestamp: int):
        mac_dst = 0
        mac_src = 0
        ethertype = 0
        vlan_id = 1
        ip_dst = 0
        ip_src = 0
        ip_proto = 0
        sport = 0
        dport = 0

        e = pb.get_layer(LayerID.ETHERNET)
        vlan_id = e.vlan_id
        ethertype = e.ethertype

        ip = pb.get_layer(LayerID.IPV4)

        if ip is not None:
            ip_src = pb.get_field("ip.src").value
            ip_dst = pb.get_field("ip.src").value
            if ip.protocol == 0x11:
                sport = pb.get_layer(LayerID.UDP).src_port
                dport = pb.get_layer(LayerID.UDP).dst_port
            elif ip.protocol == 0x06:
                sport = pb.get_layer(LayerID.TCP).src_port
                dport = pb.get_layer(LayerID.TCP).dst_port

            ip_proto = ip.protocol

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
                         VALUES({ip_src},
                                {ip_dst},
                                {pb.get_field("eth.src").to_int()}, 
                                {pb.get_field("eth.dst").to_int()}, 
                                {ethertype}, 
                                {ip_proto}, 
                                {vlan_id}, 
                                {sport}, 
                                {dport}, 
                                {ptr}, 
                                {timestamp});  
                            """
        # print(insert_stmt)
        self.cursor.execute(insert_stmt)

    def indexer(self):
        print(f"Base filename is: {self.index_name}")

        self.conn = sqlite3.connect(self.index_name)
        self.cursor = self.conn.cursor()

        self.cursor.executescript("""
                PRAGMA journal_mode = MEMORY;
                PRAGMA synchronous = OFF;
                PRAGMA cache_size = 1000000;
                PRAGMA temp_store = MEMORY;
                PRAGMA threads=8;
                PRAGMA locking_mode = EXCLUSIVE;
                """)
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

        self.pcap_read()
        self.conn.commit()

import sqlite3

from packet.layers.packet_builder import PacketBuilder
from server.config import config


class IndexCache:
    db_name = "index.db"
    packet_cache = {}

    @classmethod
    def init(cls):
        cls.conn = sqlite3.connect(":memory:")
        cls.cursor = cls.conn.cursor()
        cls.conn.execute("""create table if not exists packet(
            id integer,
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
            file_id integer,
            timestamp timestamp,
            UNIQUE(id))""", [],)

        _ = cls.cursor.execute(f"attach '{config.db_filename}' as A;")

    @classmethod
    def clear(cls):
        cls.cursor.execute("delete from packet;")

    @classmethod
    def save(cls, sql):
        sql.sfrom = 'A.packet'
        cls.cursor.execute(
            f"insert or ignore into packet {sql.build()}")

        cls.conn.commit()

    @classmethod
    def count(cls) -> int:
        cls.cursor.execute("select count(1) from packet;")
        return cls.cursor.fetchall()[0][0]

    @classmethod
    def get(cls, sql):
        print(f"Index cache getting from sql: {sql}")
        result = cls.cursor.execute(sql.build())

        id_list = []
        for r in result:
            id_list.append(r[0])

        print(f"Cache id size:{len(id_list)}, ids: {id_list}")

        # if len(id_list) > 0:
        #     sql.add_where(f" AND id NOT IN ({','.join(map(str,id_list))})")
        #     print(sql)
        #     conn = sqlite3.connect(db_filename)
        #     cursor = conn.cursor()
        #     result = cursor.execute(sql.build())
        #     for r in result:
        #         print(r)

    @classmethod
    def save_packet(cls, id: int, packet: PacketBuilder):
        cls.packet_cache[id] = packet

    @classmethod
    def get_packet(cls, id) -> PacketBuilder | None:
        return cls.packet_cache.get(id, None)

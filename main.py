# from api.server2 import start
from dbase.dbengine import DBEngine


def search():
    engine = DBEngine()
    result = engine.exec_parallel(
        """
        select ip.src, ip.dst, ip.proto 
        from a 
        where 
              ip.proto == 17 and
              pkt.timestamp < now() 
              top 15;
        """)
    # start()

    # udp.length < 64 and
    # pkt.timestamp >= 2022-03-15 13:08:00 and
    # pkt.timestamp <= 2022-03-15 14:55:00


if __name__ == "__main__":
    # Config.load("./config-jpd/server.toml")
    search()

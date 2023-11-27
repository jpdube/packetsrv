# from api.server import app
# import uvicorn
from config.config import Config
from dbase.dbengine import DBEngine


def search():
    engine = DBEngine()
    # engine.index_db()
    for _ in range(1):
        _ = engine.run(
            """
                    select udp.sport,ip.dst, ip.src, udp.dport, pkt.timestamp, pkt.origlen
        from s1
        where eth[16:2] == [0x08, 0x00] and (ip.dst == 192.168.2.230 and ip.src == 192.168.3.0/24)
        top 8500;
                    """)


if __name__ == "__main__":
    Config.load()
    search()

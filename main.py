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
                    select udp.sport,ip.dst, ip.src, udp.dport, frame.timestamp, frame.origlen
        from s1
         where udp.dport == 53 and (ip.dst == 192.168.2.230 and ip.src == 192.168.3.0/24)
        top 1000;
                    """)


if __name__ == "__main__":
    Config.load()
    search()

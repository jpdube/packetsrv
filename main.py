# from api.server import app
# import uvicorn
from dbase.dbengine import DBEngine
from config.config import Config

# APP_CONFIG


def search():
    engine = DBEngine()
    result = engine.exec_parallel(
        """
        select ip.src, ip.dst, ip.proto
        from a
        where
            ip.src == 192.168.3.235 and  ip.proto == 6 
 
        top 15;
        """)
    # uvicorn.run(app=app, host="localhost", port=8080)
 # eth.vlan == 61 and (pkt.timestamp >= 2022-03-14 00:00:00 and pkt.timestamp <= 2022-03-15 23:59:59)


if __name__ == "__main__":
    Config.load()
    search()

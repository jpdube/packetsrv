from api.server2 import start
from dbase.dbcache import IndexCache
# from dbase.packet_search import search_parallel

if __name__ == "__main__":
    # search_parallel()
    IndexCache.init()
    start()
    # uvicorn.run(app=app, host="127.0.0.1", port=8080)

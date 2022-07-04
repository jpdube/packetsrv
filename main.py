# import uvicorn

# import dbengine
from api.server2 import start
# from api.server import app
from dbase.dbcache import IndexCache
from dbase.packet_search import *

if __name__ == "__main__":

    IndexCache.init()
    start()
    # uvicorn.run(app=app, host="127.0.0.1", port=8080)

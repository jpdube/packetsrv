from api.server2 import start
from dbase.dbcache import IndexCache

if __name__ == "__main__":
    IndexCache.init()
    start()
    # uvicorn.run(app=app, host="127.0.0.1", port=8080)

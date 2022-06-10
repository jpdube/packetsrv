# from datetime import datetime
import uvicorn

from api.server import app
from dbase.packet_search import *

if __name__ == "__main__":
    uvicorn.run(app=app, host="127.0.0.1", port=8080)

    # search_parallel()

from fastapi import FastAPI
from dbase.exec_query import exec_query
from pydantic import BaseModel
from dbase.dbengine import DBEngine
# import uvicorn

app = FastAPI()


class PqlRequest(BaseModel):
    query: str


class SnifferStart(BaseModel):
    alias: str
    iface: str
    file_size: int
    file_count: int
    filter: str


class SnifferStop(BaseModel):
    alias: str


@app.post("/pql")
async def exec_pql(pql: PqlRequest):
    db = DBEngine()
    result = db.exec_parallel(pql.query)
    # result = exec_query(pql.query)
    return {"result": result}


# @app.post("/sniffer/start")
# async def sniffer_start(cmd: SnifferStart):
#     result = cmd
#     return {"result": result}


# @app.post("/sniffer/stop")
# async def sniffer_stop(cmd: SnifferStop):
#     result = cmd
#     return {"result": result}


# @app.get("/sniffer/show")
# async def sniffer_show():
#     result = [
#         {
#             "name": "sniffer_01",
#             "state": "running",
#             "iface": "en0",
#             "file_size": "2G",
#             "rotation_count": 16,
#             "alias": "trunk"
#         },
#         {
#             "name": "sniffer_02",
#             "state": "running",
#             "iface": "en1",
#             "file_size": "2G",
#             "rotation_count": 16,
#             "alias": "firewall"
#         }
#     ]
#     return {"result": result}


# def start():
#     uvicorn.run(app=app, host="localhost", port=8080)

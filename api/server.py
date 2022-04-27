from fastapi import FastAPI
from dbase.exec_query import exec_query
from pydantic import BaseModel

app = FastAPI()


class PqlRequest(BaseModel):
    query: str


@app.post("/pql")
async def exec_pql(pql: PqlRequest):
    result = exec_query(pql.query)
    return {"result": result}


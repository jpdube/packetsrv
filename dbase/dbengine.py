from pql.interp import interpret_program
from pql.parse import parse_source
from pql.interp_raw import interpret_program
from datetime import datetime
from typing import List
from packet.layers.packet_builder import PacketBuilder
from multiprocessing import Pool


class DBEngine:
    def __init__(self):
        pass

    def _execute(self, params):
        file_id, pql = params
        model = parse_source(pql)
        # print(model)

        result = []
        start_time = datetime.now()
        for m in model:
            if m.where_expr is not None:
                result = interpret_program(m.where_expr, pcapfile=f"{file_id}")

        print(f"Time:{(datetime.now() - start_time).total_seconds()}")
        return result

    def exec_parallel(self, pql: str):
        pool = Pool()
        start_time = datetime.now()
        flist = []
        for i in range(10):
            flist.append((i, pql))
        result = pool.map(self._execute, flist)
        found = 0
        for r in result:
            for _ in r:
                #         print(p)
                found += 1

        ttl_time = datetime.now() - start_time
        print(
            f"---> Total Time: {ttl_time} Result: {found}")

    def file_list(self):
        pass

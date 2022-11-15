from pql.interp import interpret_program
from pql.parse import parse_source
from pql.interp_raw import interpret_program
from datetime import datetime
from typing import List, Tuple
from packet.layers.packet_builder import PacketBuilder
from multiprocessing import Pool


class DBEngine:
    def __init__(self):
        self.pkt_found = 0

    def select(self) -> List[str]:
        model = parse_source(self.pql)
        for m in model:
            if m.select_expr is not None:
                field_list = []
                for f in m.select_expr:
                    field_list.append(f.value)
                return field_list

        return []

    def top(self) -> int:
        model = parse_source(self.pql)
        for m in model:
            if m.top_expr is not None:
                return int(m.top_expr.value)

        return 2

    def _execute(self, params):
        file_id, pql = params
        model = parse_source(pql)
        # print(model)

        result = []
        # start_time = datetime.now()
        for m in model:
            if m.where_expr is not None:
                result = interpret_program(m.where_expr, pcapfile=f"{file_id}")

        # print(f"Time:{(datetime.now() - start_time).total_seconds()}")
        return result

    def exec_parallel(self, pql: str):
        self.pql = pql
        pool = Pool()
        start_time = datetime.now()
        flist = []
        for i in range(240):
            flist.append((i, pql))
        result = pool.map(self._execute, flist)

        found = 0

        pkt_list = self.build_result(result)
        for p in pkt_list:
            pb = PacketBuilder()
            pb.from_bytes(*p)
            print(pb)
            pb.print_hex()
            found += 1
            if found >= self.top():
                break

        ttl_time = datetime.now() - start_time
        print(
            f"---> Total Time: {ttl_time} Result: {self.pkt_found} TOP: {self.top()} SELECT: {self.select()}")

    def build_result(self, raw_result: List[List[Tuple[bytes, bytes]]]) -> List[Tuple[bytes, bytes]]:
        result = []
        self.pkt_found = 0
        for r in raw_result:
            for p in r:
                result.append(p)
                self.pkt_found += 1

        return result

    def file_list(self):
        pass

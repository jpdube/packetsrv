import multiprocessing as mp
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Generator

from dbase.index_manager import IndexManager, PktPtr
from packet.layers.packet_builder import PacketBuilder
from pql.interp_raw import exec_program
from pql.parse import parse_source


class DBEngine:
    def __init__(self):
        self.pkt_found = 0
        self.index_mgr = IndexManager()
        self.result = []

    def index_db(self):
        self.index_mgr.create_index()

    def run(self, pql: str):
        print(pql)
        start_time = datetime.now()
        self.pql = pql
        self.model = parse_source(pql)
        # field_index = self.index_mgr.build_search_value(self.model.index_field)
        index_result = self.index_mgr.search(
            self.model.index_field, self.model.ip_list)
        # index_result = self.index_mgr.search(field_index, self.model.ip_list)
        searched = 0
        self.pkt_found = 0

        print(self.model.has_interval)
        print(self.model.interval)

        search_result = []

        pool = mp.Pool()
        for idx in index_result:
            params = []
            for chunk_pkt in self.chunks(idx, mp.cpu_count()):
                for pkt in chunk_pkt:
                    params.append((pkt, self.model.where_expr))

                result = pool.starmap(self.search_pkt, params)
                for r in result:
                    searched += 1
                    if r is not None:
                        search_result.append(r)
                        self.pkt_found += 1

                    if self.pkt_found >= self.model.top_expr:
                        break

                if self.pkt_found >= self.model.top_expr:
                    break

            if self.pkt_found >= self.model.top_expr:
                break

        ttl_time = datetime.now() - start_time
        print(self.model.select_expr)

        print(
            f"---> Index scan in Time: {ttl_time} Result: {searched}:{self.pkt_found} TOP: {self.model.top_expr} SELECT: {self.model.select_expr}")

        for p in search_result:
            self.get_fields(p)

        return self.result

    def search_pkt(self, pkt_ptr: PktPtr, where_expr):
        pkt_result = exec_program(where_expr, pkt_ptr)
        if pkt_result is not None:
            pb = PacketBuilder()
            pb.from_bytes(pkt_result.packet, pkt_result.header)
            self.get_fields(pb)
            return pb

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def process(self, index_result):
        ...

    def get_fields(self, pb: PacketBuilder):
        record = {}
        for f in self.model.select_expr:
            if f.value in ["ip.dst", "ip.src"]:
                field_value = f"{IPv4Address(pb.get_field(f.value))}"
            else:
                field_value = pb.get_field(f.value)
            record[f.value] = field_value
        self.result.append(record)

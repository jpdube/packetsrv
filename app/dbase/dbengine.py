from datetime import datetime
from ipaddress import IPv4Address

from dbase.index_manager import IndexManager
from packet.layers.fields import IPv4Address
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
        count = 0
        searched = 0
        self.pkt_found = 0

        print(self.model.has_interval)
        print(self.model.interval)

        for idx in index_result:
            for i in idx:
                searched += 1
                pkt_result = exec_program(self.model.where_expr, i)
                if pkt_result is not None:
                    pb = PacketBuilder()
                    pb.from_bytes(pkt_result.packet, pkt_result.header)
                    self.get_fields(pb)
                    count += 1
                    self.pkt_found += 1

                if count == self.model.top_expr:
                    break

            if count == self.model.top_expr:
                break

        ttl_time = datetime.now() - start_time
        print(self.model.select_expr)

        print(
            f"---> Scaneed: {searched} in Time: {ttl_time} Result: {self.pkt_found} TOP: {self.model.top_expr} SELECT: {self.model.select_expr}")

        return self.result

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

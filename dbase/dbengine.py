from datetime import datetime
from multiprocessing import Pool
# from pathlib import Path
# from struct import unpack
from typing import Dict, List, Tuple

from config.config import Config
from dbase.index_manager import IndexManager
from packet.layers.packet_builder import PacketBuilder
from pql.interp_raw import exec_program
from pql.parse import parse_source
from pql.pcapfile import PcapFile

# NBR_FILES_TO_PROCESS = 1


class DBEngine:
    def __init__(self):
        self.pkt_found = 0
        self.index_mgr = IndexManager()

    def index_db(self):
        self.index_mgr.create_index()

    def run(self, pql: str):
        start_time = datetime.now()
        self.pql = pql
        self.model = parse_source(pql)
        field_index = self.index_mgr.build_search_value(self.model.index_field)
        index_result = self.index_mgr.search(field_index, self.model.ip_list)
        result = []
        count = 0
        searched = 0
        self.pkt_found = 0
        print(self.model.where_expr)
        # for idx in index_result:
        # print(f"Found index: {idx}")

        for idx in index_result:
            for i in idx:
                # print(i)
                searched += 1
                pkt_result = exec_program(self.model.where_expr, i)
                if pkt_result is not None:
                    # pb = PacketBuilder()
                    # pb.from_bytes(pkt_result.packet, pkt_result.header)
                    # print(pb)
                    count += 1
                    self.pkt_found += 1

                if count == self.model.top_expr:
                    break

            if count == self.model.top_expr:
                break
        ttl_time = datetime.now() - start_time
        print(
            f"---> Scaneed: {searched} in Time: {ttl_time} Result: {self.pkt_found} TOP: {self.model.top_expr} SELECT: {self.model.select_expr}")

        return result

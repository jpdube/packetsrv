import logging
import multiprocessing as mp
from datetime import datetime
from typing import Any, Generator

from config.config import Config
from dbase.index_manager import IndexManager, PktPtr
from dbase.query_result import QueryResult
from packet.layers.packet_builder import PacketBuilder
from pql.interp_raw import exec_program
from pql.parse import parse_source
from scapy.all import IP, TCP, UDP, Ether, sr1
from scapy.layers import *

log = logging.getLogger("packetdb")


class DBEngine:
    def __init__(self):
        self.pkt_found = 0

    def index_db(self):
        index_mgr = IndexManager()
        index_mgr.create_index()

    def run(self, pql: str):
        log.debug(pql)
        start_time = datetime.now()
        self.pql = pql
        self.model = parse_source(pql)
        log.debug(self.model.index_field)
        index_mgr = IndexManager()
        index_result = index_mgr.search(self.model)
        searched = 0
        self.pkt_found = 0
        offset_ptr = 0

        query_result = QueryResult(self.model)

        pool = mp.Pool(Config.nbr_threads())
        for idx in index_result:
            params = []
            for chunk_pkt in self.chunks(idx, Config.nbr_threads()):
                for pkt in chunk_pkt:
                    params.append((pkt, self.model.where_expr))

                result = pool.starmap(self.search_pkt, params)
                for r in result:
                    searched += 1
                    if r is not None:
                        if offset_ptr > self.model.offset:
                            query_result.add_packet(r)
                            self.pkt_found += 1
                        else:
                            log.debug(
                                f"Skipping for offset: {self.model.offset}:{offset_ptr}")
                        offset_ptr += 1

                    if query_result.count_reach:
                        break

                if query_result.count_reach:
                    break

            if query_result.count_reach:
                break

        ttl_time = datetime.now() - start_time

        log.info(
            f"---> Index scan time: {ttl_time} Result: {searched}:{self.pkt_found} TOP: {self.model.top_expr} OFFSET: {self.model.offset} TO_FETCH: {self.model.packet_to_fetch} SELECT: {self.model.select_expr}")

        return query_result.get_result()

    def search_pkt(self, pkt_ptr: PktPtr, where_expr):
        pkt_result = exec_program(where_expr, pkt_ptr)
        if pkt_result is not None:
            # spkt = Ether(pkt_result.packet)
            # spkt.show()

            # if IP in spkt:
            #     ip_val = spkt[IP]
            #     print(ip_val)
            # log.info(spkt[IP].src)

            pb = PacketBuilder()
            pb.from_bytes(pkt_result.packet, pkt_result.header)
            return pb

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]

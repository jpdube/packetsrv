# import cProfile
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

# from scapy.all import IP, TCP, UDP, Ether, sr1
# from scapy.layers import *

log = logging.getLogger("packetdb")


class DBEngine:
    def __init__(self):
        self.pkt_found = 0
        self.index_mgr = IndexManager()

    def index_db(self):
        index_mgr = IndexManager()
        index_mgr.create_index()

    def exec(self, pql: str):
        self.model = parse_source(pql)
        log.debug(self.model)
        log.debug(self.model.index_field)
        log.debug(f"FOUND ID: {self.model.id}:{self.model.has_id}")

        if not self.model.has_id:
            return self._run()
        else:
            return self._run_id()

    def _run_id(self):
        query_result = QueryResult(self.model)
        log.debug("Running with ID")
        result = []

        start_time = datetime.now()
        result = self.index_mgr.search_id(self.model.id)

        for pkt in result:
            query_result.add_packet(pkt)

        log.debug(query_result)

        ttl_time = datetime.now() - start_time

        log.info(
            f"---> Get by ID time: {ttl_time} for {len(result)} packet")
        return query_result.get_result()

    def _run(self):
        # def _run(self, pql: str):
        searched = 0
        self.pkt_found = 0
        offset_ptr = 0

        # self.model = parse_source(pql)
        log.debug(self.model)
        log.debug(self.model.index_field)
        log.debug(f"FOUND ID: {self.model.id}:{self.model.has_id}")
        query_result = QueryResult(self.model)
        index_result = self.index_mgr.search(self.model)

        start_time = datetime.now()
        for idx in index_result:
            r = self.search_pkt(idx, self.model.where_expr)
            if r is not None:
                if offset_ptr > self.model.offset:
                    query_result.add_packet(r)
                    self.pkt_found += 1
                offset_ptr += 1

            if self.model.has_top:
                if query_result.count_reach:
                    break

            searched += 1

        ttl_time = datetime.now() - start_time

        log.info(
            f"---> Index scan time: {ttl_time} Result: {searched}:{self.pkt_found} TOP: {self.model.top_expr} OFFSET: {self.model.offset} TO_FETCH: {self.model.packet_to_fetch} SELECT: {self.model.select_expr}")

        return query_result.get_result()

    def run_parallel(self, pql: str):
        log.debug(pql)
        self.pql = pql
        index_mgr = IndexManager()
        searched = 0
        self.pkt_found = 0
        offset_ptr = 0

        self.model = parse_source(pql)
        log.debug(self.model.index_field)
        query_result = QueryResult(self.model)
        index_result = index_mgr.search(self.model)

        start_time = datetime.now()
        pool = mp.Pool(Config.nbr_threads())

        for idx in index_result:
            params = []
            for chunk_pkt in self.chunks(idx, Config.nbr_threads()):
                for pkt in chunk_pkt:
                    params.append((pkt, self.model.where_expr))

                # dump_params(params)
                result = pool.starmap(self.search_pkt, params)
                # log.debug(f"Search PKT:{len(result)} {result}")
                for r in result:
                    searched += 1
                    if r is not None:
                        if offset_ptr > self.model.offset:
                            # log.debug(f"Before Query Result add: {r}")
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

    def search_pkt(self, pkt_ptr: PktPtr, where_expr) -> PacketBuilder | None:
        # log.debug(pkt_ptr)
        if pkt_result := exec_program(where_expr, pkt_ptr):
            return pkt_result
        else:
            return None

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]


def dump_params(params):
    for p in params:
        log.debug(p)

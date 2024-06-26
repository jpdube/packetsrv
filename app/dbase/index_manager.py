import logging
import multiprocessing as mp
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Tuple

import pql.packet_index as pkt_index
from config.config import Config
from dbase.packet_ptr import PktPtr
from pql.model import SelectStatement
from pql.pcapfile import PcapFile

log = logging.getLogger("packetdb")


class IndexManager:
    def __init__(self):
        pass

    def create_index(self):
        path = Path(Config.pcap_path())
        files_list = list(path.glob("*.pcap"))
        pcapfile = PcapFile()
        pool = mp.Pool(Config.nbr_threads())
        start_time = datetime.now()
        flist = []
        for i in files_list:
            flist.append(i.stem)
        result = pool.map(pcapfile.create_index, flist)
        result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result, clean=True)
        ttl_time = datetime.now() - start_time
        log.info(f"---> Total Index Time: {ttl_time}")

    def search_pkt(self, file_id: Path, search_index: int, ip_list: dict[str, list[Tuple[int, int]]]):
        result = []
        conn = sqlite3.connect(str(file_id))
        c = conn.cursor()
        params = []
        params.append(search_index)
        params.append(search_index)

        sql = """
              select pkt_ptr
              from pkt_index
              where (pindex & ?) = ?

              """
        if len(ip_list["ip.src"]) > 0:
            sql += " and ip_src between ? and ? "
            net, brdcast = self.net_broadcast(
                ip_list["ip.src"][0][0], ip_list["ip.src"][0][1])
            params.append(net)
            params.append(brdcast)

        if len(ip_list["ip.dst"]) > 0:
            sql += " and ip_dst between ? and ? "
            net, brdcast = self.net_broadcast(
                ip_list["ip.dst"][0][0], ip_list["ip.dst"][0][1])
            params.append(net)
            params.append(brdcast)

        c.execute(sql, params)

        for r in c.fetchall():
            pkt = PktPtr(file_id=int(file_id.stem),
                         ptr=r[0], ip_dst=0, ip_src=0, pkt_hdr_size=0)
            result.append(pkt)

        return result

    def search(self, model: SelectStatement) -> Generator[Any, Any, Any]:

        log.debug(f"Search index started: {model.index_field}")

        # --- Check for interval
        interval_result = self.search_interval(model)
        if interval_result:
            log.info(f"{len(interval_result)} found in master index")
            files_list = interval_result
        else:
            path = Path(Config.pcap_index())
            files_list = list(path.glob("*.db"))
            files_list.sort(key=lambda a: int(a.stem))

        search_index = pkt_index.build_search_index(model.index_field)
        log.debug(f"Computed index: {search_index:x}")
        pool = mp.Pool()

        for index_chunk in self.chunks(files_list, Config.nbr_threads()):
            params = []
            for idx in index_chunk:
                params.append((idx, search_index, model.ip_list))

            result = pool.starmap(self.search_pkt, params)

            for r in result:
                yield (r)

    def search_interval(self, model: SelectStatement) -> None | list[Path]:
        if not model.has_interval:
            return None

        log.debug(f"Interval s: {model.start_interval}, e: {model.end_interval}")

        conn = sqlite3.connect(Config.pcap_master_index())
        c = conn.cursor()

        params = (model.start_interval, model.end_interval,
                  model.start_interval, model.end_interval)

        sql = """
                select * from master_index where start_ts >= ? and end_ts <= ? 
                union all 
                select * from master_index where ? >= start_ts and ? <= end_ts;

              """

        c.execute(sql, params)

        result = []
        for r in c.fetchall():
            filename = f"{Config.pcap_index()}/{r[0]}.db"
            result.append(Path(filename))

        return result

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def match_ip(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        if len(ip_list['ip.dst']) > 0 and len(ip_list['ip.src']) > 0:
            return self.match_ip_and(ip_src, ip_dst, ip_list)
        else:
            return self.match_ip_or(ip_src, ip_dst, ip_list)

    def match_ip_and(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        src_found = False
        dst_found = False

        if self.is_in_network(ip_src, ip_list['ip.src']):
            src_found = True

        if self.is_in_network(ip_dst, ip_list['ip.dst']):
            dst_found = True

        return src_found and dst_found

    def match_ip_or(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        src_found = False
        dst_found = False

        if len(ip_list['ip.src']) > 0:
            if self.is_in_network(ip_src, ip_list['ip.src']):
                src_found = True

        if len(ip_list['ip.dst']) > 0:
            if self.is_in_network(ip_dst, ip_list['ip.dst']):
                dst_found = True

        return src_found or dst_found

    def is_in_network(self, address: int, address_list: list[Tuple[int, int]]) -> bool:
        for ip, mask in address_list:
            net, broadcast = self.net_broadcast(ip, mask)
            if address >= net and address <= broadcast:
                return True

        return False

    def net_broadcast(self, ip: int, mask: int) -> Tuple[int, int]:
        host_bits = 32 - mask
        start = (ip >> host_bits) << host_bits  # clear the host bits
        end = start | ((1 << host_bits) - 1)
        return (start, end)

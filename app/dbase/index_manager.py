import logging
import multiprocessing as mp
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from struct import unpack
from typing import Any, Generator, Tuple

import pql.packet_index as pkt_index
from config.config import Config
from dbase.packet_ptr import PktPtr
from pql.model import SelectStatement
from pql.pcapfile import PcapFile
from dbase.proto_index import ProtoIndex
from dbase.file_manager import FileManager

log = logging.getLogger("packetdb")


class IndexManager:
    def __init__(self):
        pass

    def create_index_seq(self):
        path = Path(Config.pcap_path())
        files_list = list(path.glob("*.pcap"))
        pcapfile = PcapFile()
        start_time = datetime.now()
        # flist = []
        result = []
        for i in files_list:
            start_ts = time.time()
            r = pcapfile.create_index(i.stem)
            log.info(f"   ====> Index manager: {time.time() - start_ts:.3}")
            result.append(r)

        # result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result, clean=True)
        ttl_time = datetime.now() - start_time
        log.info(f"---> Total Index Time: {ttl_time}")

    def create_index(self):
        FileManager.clean_indexes()
        path = Path(Config.pcap_path())
        files_list = list(path.glob("*.pcap"))
        pcapfile = PcapFile()
        pool = mp.Pool(Config.nbr_threads())
        start_time = datetime.now()
        flist = []
        for i in files_list:
            flist.append(i.stem)
        result = pool.map(pcapfile.create_index, flist)
        # result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result, clean=True)
        ttl_time = datetime.now() - start_time
        log.info(f"---> Total Index Time: {ttl_time}")

    def chunk_size(self, proto: int) -> int:
        result = []
        db_filename = Config.dbase_path() + "/mindex/packetdb.db"
        log.error(f"FILENAME: {db_filename}")
        conn = sqlite3.connect(db_filename)
        c = conn.cursor()

        sql = """
            select cast (avg(count) as int)
            from proto_stats
            where (proto & ?) = ?;

        """

        c.execute(sql, [proto, proto])

        result = c.fetchone()

        return result

    def search_id(self, id_list: list[int]):
        result = []

        for id in id_list:
            file_id = id >> 32
            ptr = id & 0xffff
            log.debug(f"ID PCAPfile: {file_id}")

            pcapfile = PcapFile()
            pcapfile.open(file_id)

            pkt = pcapfile.get_packet_by_id(ptr)

            if pkt:
                result.append(pkt)

        return result

    def search_proto(self, file_id: int, proto_id: int, ip_list: dict[str, list[Tuple[int, int]]]):
        result = []
        proto_index = ProtoIndex(file_id, proto_id)
        index_list = proto_index.load(file_id, proto_id)

        for idx in index_list:
            # (ts, ptr, index, dst_ip, src_ip, hdr_len,
            #  dport, sport) = unpack(">IIIIIHHH", buffer)
            # log.debug(f"TS: {ts:x}, ptr: {ptr:x}, Index:{index:x} ")
            # log.debug(f"Search index: {search_index:x}:{index:x}")
            found = True

            if len(ip_list["ip.dst"]) > 0:
                ip_search = Ipv4Search(ip_list["ip.dst"])
                found = idx.ip_dst in ip_search

            if len(ip_list["ip.src"]) > 0:
                ip_search = Ipv4Search(ip_list["ip.src"])
                found = idx.ip_src in ip_search

            if found:
                pkt = PktPtr(file_id=file_id,
                             ptr=idx.ptr, ip_dst=0, ip_src=0, pkt_hdr_size=0)
                # log.debug(f"PTR index: {pkt.file_id}:{pkt.ptr}")
                result.append(pkt)

        return result

    def search_pkt(self, file_id: Path, search_index: int, ip_list: dict[str, list[Tuple[int, int]]]):
        result = []

        with open(str(file_id), "rb") as f:
            while True:
                buffer = f.read(26)

                if len(buffer) != 26:
                    break

                (ts, ptr, index, dst_ip, src_ip, hdr_len,
                 dport, sport) = unpack(">IIIIIHHH", buffer)
                # log.debug(f"TS: {ts:x}, ptr: {ptr:x}, Index:{index:x} ")
                found = False
                if (index & search_index) == search_index:
                    # log.debug(f"Search index: {search_index:x}:{index:x}")
                    found = True

                    if len(ip_list["ip.dst"]) > 0:
                        ip_search = Ipv4Search(ip_list["ip.dst"])
                        found = dst_ip in ip_search

                    if len(ip_list["ip.src"]) > 0:
                        ip_search = Ipv4Search(ip_list["ip.src"])
                        found = src_ip in ip_search

                    if len(ip_list['dport']) > 0:
                        found = dport in ip_list['dport']

                    if len(ip_list['sport']) > 0:
                        log.error(f"Found sport: {ip_list['sport'][0]}")
                        found = sport in ip_list['sport']

                if found:
                    pkt = PktPtr(file_id=int(file_id.stem),
                                 ptr=ptr, ip_dst=0, ip_src=0, pkt_hdr_size=0)
                    # log.debug(f"PTR index: {pkt.file_id}:{pkt.ptr}")
                    result.append(pkt)

        return result

    def proto_index_files(self, proto: str) -> list[int]:
        file_pattern = ""

        match proto:
            case "DHCP":
                log.debug(":::::::::::: DHCP SEARCH :::::::::::")
                file_pattern = "*_100.pidx"

            case "RDP":
                log.debug(":::::::::::: RDP SEARCH :::::::::::")
                file_pattern = "*_800.pidx"

            case "DNS":
                log.debug(":::::::::::: DNS SEARCH :::::::::::")
                file_pattern = "*_80.pidx"

            case "TELNET":
                log.debug(":::::::::::: TELNET SEARCH :::::::::::")
                file_pattern = "*_1000.pidx"

            case "SSH":
                log.debug(":::::::::::: SSH SEARCH :::::::::::")
                file_pattern = "*_400.pidx"

            case "ETH_PROTO_ARP":
                log.debug(":::::::::::: ARP SEARCH :::::::::::")
                file_pattern = "*_40.pidx"

            case "HTTP":
                log.debug(":::::::::::: HTTP SEARCH :::::::::::")
                file_pattern = "*_100000.pidx"

            case "HTTPS":
                log.debug(":::::::::::: HTTPS SEARCH :::::::::::")
                file_pattern = "*_200.pidx"

            case "NTP":
                log.debug(":::::::::::: NTP SEARCH :::::::::::")
                file_pattern = "*_200000.pidx"

            case "SMB":
                log.debug(":::::::::::: SMB SEARCH :::::::::::")
                file_pattern = "*_8000000.pidx"

        path = Path(Config.pcap_proto_index())
        files_list = list(path.glob(file_pattern))
        files_list.sort(key=lambda a: int(a.stem.split('_')[0]), reverse=True)

        log.debug(f">>> FOUND {len(files_list)} proto")
        return files_list

    def has_proto_index(self, proto_list: list[str]) -> str:
        proto_def = ["ETH_PROTO_ARP", "DHCP",
                     "RDP", "DNS", "TELNET", "SSH", "HTTP", "HTTPS", "NTP", "SMB"]

        for proto in proto_def:
            if proto in proto_list:
                return proto

        return None

    def search(self, model: SelectStatement) -> Generator[Any, Any, Any]:
        proto_search = False

        log.debug(f"Search index started: {model.index_field}")

        # --- Check for interval
        if model.has_interval:
            files_list = self.search_interval(model)
        elif proto := self.has_proto_index(model.index_field):
            proto_search = True
            log.debug(f"-----> PROTO SEARCH: {proto}")
            files_list = self.proto_index_files(proto)
        else:
            log.debug("======== SHOULD NOT BE HERE =========")
            path = Path(Config.pcap_index())
            files_list = list(path.glob("*.pidx"))
            files_list.sort(key=lambda a: int(a.stem), reverse=True)

        # # --- Check for interval
        # if model.has_interval:
        #     files_list = self.search_interval(model)
        # else:
        #     path = Path(Config.pcap_index())
        #     files_list = list(path.glob("*.pidx"))
        #     files_list.sort(key=lambda a: int(a.stem), reverse=True)

        search_index = pkt_index.build_search_index(model.index_field)

        log.info(f"Using {Config.nbr_threads()} threads for index search")
        result = []
        for index_file in files_list:
            if proto_search:
                # log.debug(":::::::::::: In proto search :::::::::::")
                (file_id, proto_id) = index_file.stem.split('_')
                # log.debug(
                #     f":::::::::::: {file_id}:{int(proto_id, 16):x}:::::::::::")
                result = self.search_proto(
                    int(file_id), int(proto_id, 16), model.ip_list)
            else:
                result = self.search_pkt(
                    index_file, search_index, model.ip_list)

            for r in result:
                yield (r)

    def search_interval(self, model: SelectStatement) -> None | list[Path]:
        if not model.has_interval:
            return None

        log.debug(
            f"Interval s: {model.start_interval}, e: {model.end_interval}")

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
            filename = f"{Config.pcap_index()}/{r[0]}.pidx"
            result.append(Path(filename))

        log.debug(f"Interval packets found: {len(result)}")
        return result

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]


class Ipv4Search:
    def __init__(self, address_list: list[Tuple[int, int]]):
        self.ip_list = address_list

    def __contains__(self, search_ip: int) -> bool:
        for addr in self.ip_list:
            if self.is_in_network(search_ip, addr[0], addr[1]):
                return True

        return False

    def is_in_network(self, address: int, searched_ip: int, mask: int) -> bool:
        net, broadcast = self.net_broadcast(searched_ip, mask)
        if address >= net and address <= broadcast:
            return True

        return False

    def net_broadcast(self, ip: int, mask: int) -> Tuple[int, int]:
        host_bits = 32 - mask
        start = (ip >> host_bits) << host_bits  # clear the host bits
        end = start | ((1 << host_bits) - 1)
        return (start, end)

    # def search_parallel(self, model: SelectStatement) -> Generator[Any, Any, Any]:

    #     log.debug(f"Search index started: {model.index_field}")

    #     # --- Check for interval
    #     interval_result = self.search_interval(model)
    #     if interval_result:
    #         log.info(f"{len(interval_result)} found in master index")
    #         files_list = interval_result
    #     else:
    #         path = Path(Config.pcap_index())
    #         files_list = list(path.glob("*.db"))
    #         files_list.sort(key=lambda a: int(a.stem))

    #     search_index = pkt_index.build_search_index(model.index_field)
    #     pool = mp.Pool()

    #     log.info(f"Using {Config.nbr_threads()} threads for index search")

    #     log.info(f"Using {Config.nbr_threads()} threads for index search")
    #     for index_chunk in self.chunks(files_list, Config.nbr_threads()):
    #         params = []
    #         for idx in index_chunk:
    #             params.append((idx, search_index, model.ip_list))

    #         result = pool.starmap(self.search_pkt, params)

    #         for r in result:
    #             yield (r)

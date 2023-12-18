import multiprocessing as mp
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from struct import unpack
from typing import Any, Generator, Optional, Tuple

import pql.packet_index as pkt_index
from config.config import Config
from pql.pcapfile import PcapFile


@dataclass
class PktPtr ():
    file_id: int
    ptr: int
    ip_dst: int
    ip_src: int
    pkt_hdr_size: int
    header: Optional[bytes] = None
    packet: Optional[bytes] = None

class IndexManager:
    def __init__(self):
        pass

    def create_index(self):
        path = Path(Config.pcap_path())
        files_list = list(path.glob("*.pcap"))
        pcapfile = PcapFile()
        pool = mp.Pool()
        start_time = datetime.now()
        flist = []
        for i in files_list:
            flist.append(i.stem)
        result = pool.map(pcapfile.create_index, flist)
        result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result)
        ttl_time = datetime.now() - start_time
        print(f"---> Total Index Time: {ttl_time}")

    def search_pkt(self, file_id: int, search_index: int, ip_list: dict[str, list[Tuple[int, int]]]):
        result = []
        with open(file_id, "rb") as f:
            buffer = []
            while True:
                buffer = f.read(26)

                if not buffer:
                    break

                _, offset, index, ip_dst, ip_src, pkt_hdr_size= unpack(
                    ">IIQIIH", buffer)
                if (search_index & index) == search_index and self.match_ip(ip_src, ip_dst, ip_list):
                    pkt = PktPtr(file_id=int(file_id.stem),
                                 ptr=offset, ip_dst=ip_dst, ip_src=ip_src, pkt_hdr_size=pkt_hdr_size)
                    result.append(pkt)
        return result

    def search(self, index_field: set[int], ip_list: dict[str, list[int]]) -> Generator[Any, Any, Any]:
        path = Path(Config.pcap_index())
        files_list = list(path.glob("*.pidx"))
        files_list.sort(key=lambda a: int(a.stem))

        search_index = pkt_index.build_search_index(index_field)
        print(f"Computed index: {search_index:x}")
        pool = mp.Pool()

        for index_chunk in self.chunks(files_list, mp.cpu_count()):
            params = []
            for idx in index_chunk:
                params.append((idx, search_index, ip_list))

            result = pool.starmap(self.search_pkt, params)

            for r in result:
                yield (r)

    def chunks(self, l: list[Any], n: int) -> Generator[Any, Any, Any]:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def match_ip(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        if len(ip_list['ip.dst']) > 0 and len(ip_list['ip.src']) > 0:
            return self.match_ip_and(ip_src, ip_dst, ip_list)
        else:
            return self.match_ip_or(ip_src, ip_dst, ip_list)

    def match_ip_and(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        src_found=False
        dst_found=False

        if self.is_in_network(ip_src, ip_list['ip.src']):
            src_found=True

        if self.is_in_network(ip_dst, ip_list['ip.dst']):
            dst_found=True

        return src_found and dst_found

    def match_ip_or(self, ip_src: int, ip_dst: int, ip_list: dict[str, list[Tuple[int, int]]]) -> bool:
        src_found=False
        dst_found=False

        if len(ip_list['ip.src']) > 0:
            if self.is_in_network(ip_src, ip_list['ip.src']):
                src_found=True

        if len(ip_list['ip.dst']) > 0:
            if self.is_in_network(ip_dst, ip_list['ip.dst']):
                dst_found=True

        return src_found or dst_found

    def is_in_network(self, address: int, address_list: list[Tuple[int, int]]) -> bool:
        for ip, mask in address_list:
            net, broadcast=self.net_broadcast(ip, mask)
            if address >= net and address <= broadcast:
                return True

        return False

    def net_broadcast(self, ip: int, mask: int) -> Tuple[int, int]:
        host_bits=32 - mask
        start=(ip >> host_bits) << host_bits  # clear the host bits
        end=start | ((1 << host_bits) - 1)
        return(start, end)

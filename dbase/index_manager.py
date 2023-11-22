from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from struct import unpack
from multiprocessing import Pool

from config.config import Config
from pql.pcapfile import PcapFile
from typing import Optional


@dataclass
class PktPtr:
    file_id: int
    ptr: int
    ip_dst: int
    ip_src: int
    header: Optional[bytes] = None
    packet: Optional[bytes] = None


class IndexManager:
    def __init__(self):
        pass

    def create_index(self):
        path = Path(Config.pcap_path())
        files_list = list(path.glob("*.pcap"))
        pcapfile = PcapFile()
        pool = Pool()
        start_time = datetime.now()
        flist = []
        for i in files_list:
            flist.append(i.stem)
        result = pool.map(pcapfile.create_index, flist)
        result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result)
        ttl_time = datetime.now() - start_time
        print(f"---> Total Index Time: {ttl_time}")

    def search(self, search_index, ip_list):
        path = Path(Config.pcap_index())
        files_list = list(path.glob("*.pidx"))
        files_list.sort(key=lambda a: int(a.stem))
        print(ip_list)
        for file_id in files_list:
            with open(f"{Config.pcap_index()}{file_id.stem}.pidx", "rb") as f:
                buffer = []
                while True:
                    buffer = f.read(20)

                    if not buffer:
                        break

                    _, offset, index, ip_dst, ip_src = unpack(
                        ">IIIII", buffer)
                    if (search_index & index) == search_index and self.match_ip(ip_src, ip_dst, ip_list):
                        pkt = PktPtr(file_id=int(file_id.stem),
                                     ptr=offset, ip_dst=ip_dst, ip_src=ip_src)
                        yield(pkt)

    def match_ip(self, ip_src, ip_dst, ip_list) -> bool:
        if len(ip_list['ip.dst']) > 0 and len(ip_list['ip.src']) > 0:
            return self.match_ip_and(ip_src, ip_dst, ip_list)
        else:
            return self.match_ip_or(ip_src, ip_dst, ip_list)

    def match_ip_and(self, ip_src, ip_dst, ip_list):
        src_found = False
        dst_found = False

        if self.is_in_network(ip_src, ip_list['ip.src']):
            src_found = True

        if self.is_in_network(ip_dst, ip_list['ip.dst']):
            dst_found = True

        return src_found and dst_found

    def match_ip_or(self, ip_src, ip_dst, ip_list):
        src_found = False
        dst_found = False

        if len(ip_list['ip.src']) > 0:
            if self.is_in_network(ip_src, ip_list['ip.src']):
                src_found = True

        if len(ip_list['ip.dst']) > 0:
            if self.is_in_network(ip_dst, ip_list['ip.dst']):
                dst_found = True

        return src_found or dst_found

    def is_in_network(self, address: int, address_list) -> bool:
        for ip, mask in address_list:
            net, broadcast = self.net_broadcast(ip, mask)
            if address >= net and address <= broadcast:
                return True

        return False

    def net_broadcast(self, ip, mask):
        host_bits = 32 - mask
        start = (ip >> host_bits) << host_bits  # clear the host bits
        end = start | ((1 << host_bits) - 1)
        return(start, end)

    def build_search_value(self, index_set):
        pindex = 0

        if 'ETH' in index_set:
            pindex = pindex + 0x01
        if 'ARP' in index_set:
            pindex = pindex + 0x02
        if 'IP' in index_set:
            pindex = pindex + 0x04
        if 'ICMP' in index_set:
            pindex = pindex + 0x08
        if 'UDP' in index_set:
            pindex = pindex + 0x10
        if 'TCP' in index_set:
            pindex = pindex + 0x20
        if 'DNS' in index_set:
            pindex = pindex + 0x40
        if 'DHCP' in index_set:
            pindex = pindex + 0x80
        if 'HTTPS' in index_set:
            pindex = pindex + 0x100

        print(f"Bit index: {pindex: x}")
        return pindex

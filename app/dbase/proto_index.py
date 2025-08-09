
from struct import pack, unpack
from config.config import Config

from dataclasses import dataclass
import logging
import time

log = logging.getLogger("packetdb")


@dataclass
class IndexLine:
    ptr: int
    ip_dst: int
    ip_src: int

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"Ptr: {self.ptr}, IP dst: {self.ip_dst:x}, IP src: {self.ip_src:x}"


class ProtoIndex:
    def __init__(self, file_id: int, proto_id: int):
        self.file_id = file_id
        self.proto_id = proto_id

    def save(self, index_list: list[IndexLine]):
        filename = f"{Config.pcap_proto_index()}/{self.file_id}_{self.proto_id:x}.pidx"

        start_time = time.time()
        with open(filename, "w+b") as f:
            f.write(pack(">I", 0xa1b2c3d4))
            f.write(pack(">H", 0x0001))
            f.write(pack(">H", 0x0000))
            f.write(pack(">I", len(index_list)))

            for ix in index_list:
                f.write(pack(">I", ix.ptr))
                f.write(pack(">I", ix.ip_dst))
                f.write(pack(">I", ix.ip_src))
        log.info(f"Proto index creation time: {time.time() - start_time}")

    def load(self, file_id: int, proto_id: int) -> list[IndexLine]:
        filename = f"{Config.pcap_proto_index()}/{file_id}_{proto_id:x}.pidx"
        result = []

        with open(filename, "rb") as f:
            magic_no = unpack(">I", f.read(4))[0]
            version = unpack(">H", f.read(2))[0]
            options = unpack(">H", f.read(2))[0]
            idx_len = unpack(">I", f.read(4))[0]

            for _ in range(idx_len):
                idx_line = unpack(">III", f.read(12))
                result.append(IndexLine(idx_line[0], idx_line[1], idx_line[2]))

            return result


class ProtoManager:
    def __init__(self, file_id: int):
        self.file_id = file_id
        self.proto_list = {}

    def add(self, proto_id: int, ptr: int):
        if self.proto_list.get(proto_id, None):
            self.proto_list[proto_id].append(ptr)
        else:
            self.proto_list[proto_id] = [ptr]

    def save(self):
        for k, v in self.proto_list.items():
            proto_index = ProtoIndex(self.file_id, k)
            proto_index.save(v)

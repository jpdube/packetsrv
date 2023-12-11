import sys

from packet.layers.packet_builder import PacketBuilder
from pql.model import SelectStatement


class QueryResult:
    def __init__(self, model: SelectStatement):
        self.count = 0
        self.searched = 0
        self.ts_start = sys.maxsize
        self.ts_end = 0
        self.model = model
        self.packet_list = []

    def add_packet(self, packet: PacketBuilder):
        self.packet_list.append(packet)
        ts = packet.get_field("frame.timestamp")

        self.count += 1

        if ts is None:
            return

        if ts < self.ts_start:
            self.ts_start = ts

        if ts > self.ts_end:
            self.ts_end = ts

    def result(self) -> list[dict[str, str | int]]:
        pass

    def process_pkt(self, pb: PacketBuilder):
        record = {}
        for f in self.model.select_expr:
            if f.value in ["ip.dst", "ip.src"]:
                field_value = f"{IPv4Address(pb.get_field(f.value))}"
            else:
                field_value = pb.get_field(f.value)
            record[f.value] = field_value
        self.result.append(record)

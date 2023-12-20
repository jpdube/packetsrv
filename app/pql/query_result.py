import sys

from packet.layers.fields import IPv4Address
from packet.layers.packet_builder import PacketBuilder
from pql.aggregate import Count
from pql.model import SelectStatement


class QueryResult:
    def __init__(self, model: SelectStatement):
        self.found = 0
        self.searched = 0
        self.ts_start = sys.maxsize
        self.ts_end = 0
        self.model = model
        self.packet_list = []
        self.result = []

    def add_packet(self, packet: PacketBuilder):
        self.packet_list.append(packet)
        ts = packet.get_field("frame.ts_sec")

        self.found += 1

        if ts is None:
            return

        if ts < self.ts_start:
            self.ts_start = ts

        if ts > self.ts_end:
            self.ts_end = ts

        self.process_pkt(packet)

    def get_result(self) -> list[dict[str, str | int]]:
        self.aggregate()
        return self.result

    def aggregate(self) -> None:
        record = {}
        for aggr in self.model.aggregate:
            record[aggr.as_of] = aggr.execute(self.packet_list)
        self.result.insert(0, record)

    def process_pkt(self, pb: PacketBuilder):
        if len(self.model.select_expr) == 0:
            return

        record = {}
        for f in self.model.select_expr:
            if f.value in ["ip.dst", "ip.src"]:
                field_value = f"{IPv4Address(pb.get_field(f.value))}"
            else:
                field_value = pb.get_field(f.value)
            record[f.value] = field_value

        if bool(record):
            self.result.append(record)

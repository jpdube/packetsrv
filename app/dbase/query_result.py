import logging
import sys
from collections import defaultdict
from itertools import groupby
from operator import itemgetter

from packet.layers.field_type import get_type
from packet.layers.fields import IPv4Address
from packet.layers.packet_builder import PacketBuilder
from pql.aggregate import Bandwidth
from pql.model import SelectStatement

log = logging.getLogger("packetdb")


class QueryResult:
    def __init__(self, model: SelectStatement):
        self.found = 0
        self.searched = 0
        self.ts_start = sys.maxsize
        self.ts_end = 0
        self.model = model
        self.packet_list = []
        self.distinct = []
        self.result = {
            "errors": ["No errors"],
            "columns": [],
            "result": [],
        }

    @property
    def count_reach(self) -> bool:
        # log.debug(f"Top reach: {len(self.result['result'])}")
        return len(self.result['result']) >= self.model.top_expr

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

    def get_columns(self):
        for field in self.model.select_expr:
            self.result["columns"].append({field: get_type(field)})

    def get_result(self) -> list[dict[str, str | str]]:
        self.distinct = []
        self.get_columns()
        if self.model.has_groupby:
            self.group_by()
            return self.result
            # return [{"group by": "True"}]
        self.aggregate()
        return self.result

    def group_by(self):
        grp_result = defaultdict(list)

        record = {}
        for idx, pkt in enumerate(self.packet_list):
            tmp_list = []
            for grp_field in self.model.groupby_fields:
                tmp_list.append(pkt.get_field(grp_field))

            key = (*tmp_list,)
            grp_result[key].append(idx)

        for key, aggr in grp_result.items():
            record = {}
            for i, k in enumerate(key):
                record[self.model.groupby_fields[i]] = f"{IPv4Address(k)}"
            record['aggr'] = len(aggr)
            log.debug(record)
            self.result["result"].append(record)
        # print(grp_result)

    def aggregate(self) -> None:
        if len(self.model.aggregate) == 0:
            return

        record = {}
        for aggr in self.model.aggregate:
            if isinstance(aggr, Bandwidth):
                aggr.time_range(self.ts_start, self.ts_end)

            record[aggr.as_of] = aggr.execute(self.packet_list)
        self.result["result"].insert(0, record)

    def process_pkt(self, pb: PacketBuilder):
        if len(self.model.select_expr) == 0:
            return

        tmp_hash = ""
        record = {}
        for f in self.model.select_expr:
            if f in ["ip.dst", "ip.src"]:
                field_value = f"{IPv4Address(pb.get_field(f))}"
            elif f in ["eth.src", "eth.dst"]:
                field_value = str(pb.get_field(f))
            else:
                field_value = pb.get_field(f)

            if self.model.is_distinct:
                tmp_hash += str(pb.get_field(f))

            record[f] = field_value

        # log.debug(f"HASH: {tmp_hash}")

        if bool(record) and (not self.model.is_distinct or tmp_hash not in self.distinct):
            self.result["result"].append(record)
            self.distinct.append(tmp_hash)

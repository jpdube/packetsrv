import logging
import sys
from collections import defaultdict
from itertools import groupby
from operator import itemgetter

from packet.layers.field_type import get_type
from packet.layers.fields import IPv4Address, MacAddress
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

        log.debug(self.model)
        self.groupby = GroupBy(self.model)

    @property
    def is_empty(self) -> bool:
        return len(self.result['result']) > 0

    @property
    def count_reach(self) -> bool:
        if self.model.has_groupby:
            return self.groupby.count >= self.model.top_expr
        else:
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

        if self.model.has_groupby:
            self.groupby.add(packet)
        else:
            self.process_pkt(packet)

    def get_columns(self):
        for field in self.model.select_expr:
            self.result["columns"].append({field: get_type(field)})

    def get_result(self) -> list:
        self.distinct = []
        self.get_columns()
        if self.model.has_groupby:
            # self.groupby.print()
            self.result['result'] = self.groupby.get_result()
        return self.result

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

            if self.model.has_distinct:
                tmp_hash += str(pb.get_field(f))

            record[f] = field_value

        if bool(record) and (not self.model.has_distinct or tmp_hash not in self.distinct):
            self.result["result"].append(record)
            self.distinct.append(tmp_hash)


class GroupBy:
    def __init__(self, model: SelectStatement):
        self.model = model
        self.grp_result = defaultdict(list)

    def add(self, packet: PacketBuilder):
        key = []
        for grp_field in self.model.groupby_fields:
            key.append(packet.get_field(grp_field))

        self.grp_result[(*key,)].append(packet)

    @property
    def count(self) -> int:
        return len(self.grp_result)

    def get_result(self) -> list:
        result = []
        field_value = None

        for key, pkt_list in self.grp_result.items():
            record = {}
            for index, k in enumerate(key):
                if self.model.groupby_fields[index] in ['ip.src', 'ip.dst']:
                    field_value = str(IPv4Address(k))
                elif self.model.groupby_fields[index] in ['eth.src', 'eth.dst']:
                    field_value = str(k)
                else:
                    field_value = k

                record[self.model.groupby_fields[index]] = field_value

            for aggr in self.model.aggregate:
                record[aggr.as_of] = aggr.execute(pkt_list)

            result.append(record)

        # log.debug(f"GroupBy Result: {result}")

        return result

    def print(self):
        for key, value in self.grp_result.items():
            log.debug(f"Group ADD: {
                key}->{len(value)}\n-----------------------------------")

        log.debug(f"Group by total: {len(self.grp_result)}")

import sys
from abc import ABC, abstractmethod
from typing import List

from packet.layers.packet_builder import PacketBuilder


class Aggregate(ABC):
    def __init__(self, fieldname: str, as_of: str):
        self.fieldname: str = fieldname
        self.as_of: str = as_of
        self.result: int = 0

    def __repr__(self) -> str:
        result = f"""OPCODE: {type(self).__name__}, fieldname: {
            self.fieldname}, as: {self.as_of}"""
        return result

    @abstractmethod
    def execute(self, packet_list: list[PacketBuilder]) -> int:
        pass


class Sum(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, packet_list: list[PacketBuilder]) -> int:
        result = 0
        for pkt in packet_list:
            pkt_value = pkt.get_field(self.fieldname)
            if pkt_value:
                result += pkt_value
        return result


class Average(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, packet_list: list[PacketBuilder]) -> int:
        result = 0
        for pkt in packet_list:
            pkt_value = pkt.get_field(self.fieldname)
            if pkt_value:
                result += pkt_value

        if len(packet_list) != 0:
            result = int(result / len(packet_list))
            return result
        else:
            return 0


class Count(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, packet_list: list[PacketBuilder]) -> int:
        return len(packet_list)


class Min(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, packet_list: list[PacketBuilder]) -> int:
        min_value: int = sys.maxsize
        for pkt in packet_list:
            test_value = pkt.get_field(self.fieldname)
            if test_value and (test_value < min_value):
                min_value = test_value

        return min_value


class Max(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, packet_list: List[PacketBuilder]) -> int:
        max_value: int = 0
        for pkt in packet_list:
            test_value = pkt.get_field(self.fieldname)
            if test_value and (int(test_value) > max_value):
                max_value = int(test_value)

        return max_value


class Bandwidth(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def time_range(self, start_ts: int, end_ts: int) -> None:
        self.start_ts = start_ts
        self.end_ts = end_ts

    def execute(self, packet_list: List[PacketBuilder]) -> int:
        ttl_bytes: int = 0
        for pkt in packet_list:
            bw_value = pkt.get_field(self.fieldname)
            if bw_value:
                ttl_bytes += bw_value

        return int(ttl_bytes / (self.end_ts - self.start_ts)) * 8

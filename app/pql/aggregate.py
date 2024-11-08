import sys
from abc import ABC, abstractmethod
from typing import List


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
    def execute(self, value_list: list[int]) -> int:
        pass


class Count(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, value_list: list[int]) -> int:
        return len(value_list)


class Min(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, value_list: list[int]) -> int:
        min_value: int = sys.maxsize
        for test_value in value_list:
            if test_value and (test_value < min_value):
                min_value = test_value

        return min_value


class Sum(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, value_list: list[int]) -> int:
        result = 0
        for pkt_value in value_list:
            if pkt_value:
                result += pkt_value
        return result


class Average(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, value_list: list[int]) -> int:
        result = 0
        for pkt_value in value_list:
            if pkt_value:
                result += pkt_value

        if len(value_list) != 0:
            result = int(result / len(value_list))
            return result
        else:
            return 0


class Max(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def execute(self, value_list: List[int]) -> int:
        max_value: int = 0
        for test_value in value_list:
            if test_value and (int(test_value) > max_value):
                max_value = int(test_value)

        return max_value


class Bandwidth(Aggregate):
    def __init__(self, fieldname: str, as_of: str):
        super().__init__(fieldname, as_of)

    def time_range(self, start_ts: int, end_ts: int) -> None:
        self.start_ts = start_ts
        self.end_ts = end_ts

    def execute(self, value_list: List[int]) -> int:
        ttl_bytes: int = 0
        for bw_value in value_list:
            if bw_value:
                ttl_bytes += bw_value

        return int(ttl_bytes / (self.end_ts - self.start_ts)) * 8

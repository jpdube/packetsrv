from datetime import datetime
from functools import lru_cache
from typing import List

from packet.layers.fields import IPv4Address, MacAddress
from packet.layers.layer_type import LayerID
from pql.aggregate import Aggregate
# from pql.pql_constant import const_value
# from pql.pql_constant import Constants


class Node:
    pass


class Statement(Node):
    pass


class Declaration(Statement):
    pass


class Expression(Node):
    pass


class Unary(Expression):
    def __init__(self, op, value):
        self.op = op
        self.value = value

    def __repr__(self):
        return f"Unary {self.op}:{self.value}"


class Load(Expression):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"Load {self.name}"


class Store(Statement):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return f"Store({self.name},{self.value})"


class ConstDecl(Expression):
    def __init__(self, name, type, value):
        self.name = name
        self.type = type
        self.value = value

    def __repr__(self):
        return f"ConstDecl {self.name}, {self.type}, {self.value}"


class VarDecl(Expression):
    def __init__(self, name, type, value):
        self.name = name
        self.type = type
        self.value = value

    def __repr__(self):
        return f"VarDecl {self.name},{self.type},{self.value}"


class Label(Expression):
    def __init__(self, value):
        self._value = value

    @property
    @lru_cache
    def value(self) -> str:
        return self._value

    def __repr__(self):
        return f"Label({self._value})"


class LabelByte(Expression):
    def __init__(self, value, offset, length):
        self._value = value
        self._offset = offset
        self._length = length

    @property
    @lru_cache
    def value(self) -> str:
        return self._value

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def length(self) -> int:
        return self._length

    def __repr__(self):
        return f"LabelByte({self._value}, {self._offset}, {self._length})"


class Array(Expression):
    def __init__(self, value):
        self._value = value

    @property
    def value(self) -> int:
        return self._value

    def __repr__(self):
        return f"Array ({self._value})"


class Date(Expression):
    def __init__(self, value):
        self.value = value

    @property
    def timestamp(self) -> int:
        return int(datetime.strptime(self.value, "%Y-%m-%d %H:%M:%S").timestamp())

    def __repr__(self):
        return f"Date ({self.value})"


class Now(Expression):
    def __init__(self, offset=0, modifier='h'):
        self.value = int(datetime.now().timestamp())
        self.offset = offset
        self.modifier = modifier

    def __repr__(self) -> str:
        return f"Now ({self.value}, {self.offset}, {self.modifier})"


class SelectStatement(Statement):
    def __init__(
        self,
        select_fields: list[str],
        distinct,
        from_fields,
        include_field,
        index_field,
        ip_list,
        where_expr,
        groupby_fields=None,
        orderby_fields=None,
        top_expr=0,
        offset_expr=0,
        # limit_expr=0,
        interval=(0, 0),
        aggregate: list[Aggregate] = [],
        id: list[int] = []
    ):
        self.select_expr = select_fields
        self.distinct = distinct
        self.from_fields = from_fields
        self.include = include_field
        self.index_field = index_field
        self.ip_list = ip_list
        self.where_expr = where_expr
        self.groupby_fields = groupby_fields
        self.orderby_fields = orderby_fields
        self.top_expr = int(top_expr)
        self.offset = int(offset_expr)
        # self.limit = None
        self.interval = interval
        self.aggregate: list[Aggregate] = aggregate
        self.id = id
        # if isinstance(limit_expr, List) and len(limit_expr) == 2:
        #     self.offset = limit_expr[0]
        #     self.limit = limit_expr[1]

    @property
    def has_top(self) -> bool:
        return self.top_expr != 0

    @property
    def has_aggregate(self) -> bool:
        return len(self.aggregate) > 0

    @property
    def packet_to_fetch(self) -> int:
        return self.offset + self.top_expr

    @property
    def has_distinct(self) -> bool:
        return self.distinct

    @property
    def has_groupby(self) -> bool:
        return self.groupby_fields is not None

    @property
    def has_interval(self) -> bool:
        return self.interval[0] != 0 and self.interval[1] != 0

    @property
    def has_orderby(self) -> bool:
        return self.orderby_fields is not None

    @property
    def has_id(self) -> bool:
        return len(self.id) > 0

    @property
    def start_interval(self) -> int:
        if self.has_interval:
            return self.interval[0]
        else:
            return 0

    @property
    def end_interval(self) -> int:
        if self.has_interval:
            return self.interval[1]
        else:
            return 0

    def __repr__(self) -> str:
        return f"""SelectStatement Select: {self.select_expr},
                   From: {repr(self.from_fields)},
                   Index: {self.index_field}, IP: {self.ip_list},
                   Include: {self.include},
                   Where: {repr(self.where_expr)},
                   Group By: {self.has_groupby}: {self.groupby_fields},
                   Order By: {self.has_orderby}: {self.orderby_fields},
                   Top: {self.has_top} value:{self.top_expr},
                   Offset: {self.offset},
                   Interval: {self.interval[0]} to {self.interval[1]},
                   Aggregate: {self.has_aggregate}: aggr list:{self.aggregate}
                   Distinct: {self.has_distinct}
                   ID: {self.id}
                   """


class AssertStatement(Statement):
    def __init__(self, pql: SelectStatement, message: str, every: str, notify: str):
        self.pql = pql
        self.message = message
        self.every = every
        self.notify = notify


class String(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"String({self.value})"


class Float(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Float({self.value})"


class IPv4(Expression):
    def __init__(self, value, mask):
        self.ipaddr = IPv4Address(value)
        self.mask = int(mask)
        self.min, self.max = self.ipaddr.network(self.mask)

    @property
    @lru_cache
    def to_int(self):
        return self.ipaddr.value

    # def to_network(self, mask):
    #     return self.ipaddr.network(mask)

    # @lru_cache
    def is_in_network(self, address) -> bool:
        return address >= self.min and address <= self.max

    def __repr__(self) -> str:
        return f"IPv4({(self.ipaddr)}, {self.mask})"


class Mac(Expression):
    def __init__(self, value):
        self.value = MacAddress(value)
        self.int_value = self.value.to_int()

    @property
    @lru_cache
    def to_int(self) -> int:
        return self.int_value

    def __repr__(self) -> str:
        return f"Mac({self.value})"


class Integer(Expression):
    def __init__(self, value):
        if isinstance(value, str):
            self._value = int(value)
        else:
            self._value = value

    @property
    @lru_cache
    def value(self) -> int:
        return self._value

    def __repr__(self):
        return f"Integer({self._value})"


class Boolean(Expression):
    def __init__(self, value):
        self.value = True if value == "true" else False

    def __repr__(self):
        return f"Boolean({self.value})"


class Grouping(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Grouping({self.value})"


class BinOp(Expression):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return f"BinOp({self.op}, {self.left}, {self.right})"

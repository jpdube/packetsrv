from datetime import datetime
from functools import lru_cache
from typing import List

from packet.layers.fields import IPv4Address, MacAddress
from pql.constant import const_value
from pql.tokens_list import human_tokens


class Node:
    pass
    # _next_id = 1

    # def __new__(cls, *args, **kwargs):
    #     self = super().__new__(cls)
    #     self.id = Node._next_id
    #     Node._next_id += 1
    #     return self


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
        self.value = const_value(value)

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
        value,
        from_fields,
        include_field,
        index_field,
        ip_list,
        where_expr,
        groupby_expr,
        top_expr=None,
        limit_expr=None,
        interval=(0, 0),
    ):
        self.select_expr = value
        self.from_fields = from_fields
        self.include = include_field
        self.index_field = index_field
        self.ip_list = ip_list
        self.where_expr = where_expr
        self.groupby_expr = groupby_expr
        self.top_expr = top_expr
        self.offset = None
        self.limit = None
        self.interval = interval
        if isinstance(limit_expr, List) and len(limit_expr) == 2:
            self.offset = limit_expr[0]
            self.limit = limit_expr[1]

    @property
    def has_interval(self) -> bool:
        return self.interval[0] != 0 and self.interval[1] != 0

    def __repr__(self) -> str:
        return f"""SelectStatement Select: {self.select_expr}, 
                   From: {repr(self.from_fields)}, 
                   Index: {self.index_field}, IP: {self.ip_list}, 
                   Include: {self.include}, 
                   Where: {repr(self.where_expr)}, 
                   Group By: {self.groupby_expr}, 
                   Top: {self.top_expr}, 
                   Limit: {self.offset},{self.limit}, 
                   Interval: {self.interval[0]} to {self.interval[1]}"""


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
        return f"BinOp({human_tokens(self.op)}, {self.left}, {self.right})"

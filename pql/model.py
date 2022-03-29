from datetime import datetime
from packet.layers.fields import IPv4Address, MacAddress
from typing import List
from pql import fields_list
from pql.fields_list import field_list, Field

from packet.layers.ip import IP


class Node:
    _next_id = 1

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls)
        self.id = Node._next_id
        Node._next_id += 1
        return self


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
        f = field_list.get(self._value, None)
        if f is not None:
            self.index = f.index

    @property
    def value(self) -> str:
        f = field_list.get(self._value, None)
        if f is not None:
            return f.field
        else:
            return f'Invalid field near {self._value}'

    def __repr__(self):
        return f"Label({self._value})"


class Date(Expression):
    def __init__(self, value):
        self.value = value

    @property
    def timestamp(self) -> int:
        return int(datetime.strptime(self.value, "%Y-%m-%d %H:%M:%S").timestamp())

    def __repr__(self):
        return f"Date ({self.value})"


class WithStatement(Statement):
    def __init__(
        self,
        with_fields,
        include_field,
        filter_expr,
        top_expr=None,
        limit_expr=None,
    ):
        self.with_field = with_fields
        self.include = include_field
        self.filter_expr = filter_expr
        self.top_expr = top_expr
        self.offset = None
        self.limit = None
        if isinstance(limit_expr, List) and len(limit_expr) == 2:
            self.offset = limit_expr[0]
            self.limit = limit_expr[1]

    def __repr__(self) -> str:
        return f"With: {repr(self.with_field)}, Include: {self.include}, Filter: {repr(self.filter_expr)}, Top: {self.top_expr}, Limit: {self.offset},{self.limit}"


class SelectStatement(Statement):
    def __init__(
        self,
        value,
        from_fields,
        include_field,
        where_expr,
        top_expr=None,
        limit_expr=None,
    ):
        self.value = value
        self.from_fields = from_fields
        self.include = include_field
        self.where_expr = where_expr
        self.top_expr = top_expr
        self.offset = None
        self.limit = None
        if isinstance(limit_expr, List) and len(limit_expr) == 2:
            self.offset = limit_expr[0]
            self.limit = limit_expr[1]

    def __repr__(self) -> str:
        return f"SelectStatement Select: {self.value}, From: {repr(self.from_fields)}, Include: {self.include}, Where: {repr(self.where_expr)}, Top: {self.top_expr}, Limit: {self.offset},{self.limit}"


# class InStatement(Expression):
#     def __init__(self, value):
#         self.value = value
#
#     def __repr__(self) -> str:
#         return f"In ({self.value})"


class PrintStatement(Statement):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"PrintStatement {repr(self.value)}"


class String(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"String({self.value})"


class Char(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Char({self.value})"


class Float(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Float({self.value})"


class IPv4(Expression):
    def __init__(self, value):
        self.ipaddr = IPv4Address(value)

    @property
    def to_int(self):
        return self.ipaddr.value

    def to_network(self, mask):
        return self.ipaddr.network(mask)

    def __repr__(self) -> str:
        return f"IPv4({(self.ipaddr)})"


class Mac(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self) -> str:
        return f"MacStatement({repr(self.value)})"


class Integer(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Integer({self.value})"


class Boolean(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"BooleanStatement({self.value})"


class Grouping(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Grouping({self.value})"


class IfStatement(Statement):
    def __init__(self, test, true_block, else_block):
        self.test = test
        self.true_block = true_block
        self.else_block = else_block

    def __repr__(self):
        return f"ifStatement {self.test} {{\n  {self.true_block} }}\n else {{ {self.else_block} }}\n"


class ContinueStatement(Statement):
    def __repr__(self):
        return f"ContinueStatement"


class BreakStatement(Statement):
    def __repr__(self):
        return f"BreakStatement"


class BinOp(Expression):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return f"BinOp({self.op}, {self.left}, {self.right})"


class WhileStatement(Statement):
    def __init__(self, test, code_block):
        self.test = test
        self.code_block = code_block

    def __repr__(self):
        return f"WhileStatement {self.test} {self.code_block}"


class Block:
    def __init__(self, code):
        self.code = code

    def __repr__(self):
        return f"Block: {self.code}"

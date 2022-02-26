from datetime import datetime
from packet.layers.fields import IPv4Address, MacAddress


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
        self.value = value

    def __repr__(self):
        return f"Label {self.value}"


class Date(Expression):
    def __init__(self, value):
        self.value = value

    @property
    def timestamp(self) -> int:
        return int(datetime.strptime(self.value, "%Y-%m-%d %H:%M:%S").timestamp())

    def __repr__(self):
        return f"Date ({self.value})"


class SelectStatement(Statement):
    def __init__(
        self,
        value,
        from_fields,
        where_expr,
        between_expr,
        top_expr=None,
        limit_expr=None,
    ):
        self.value = value
        self.from_fields = from_fields
        self.where_expr = where_expr
        self.between_expr = between_expr
        self.top_expr = top_expr
        self.limit_expr = limit_expr

    def __repr__(self) -> str:
        return f"SelectStatement {repr(self.value)}, From: {repr(self.from_fields)}, Where: {repr(self.where_expr)} Between: {self.between_expr}, Top: {self.top_expr}, Limit: {self.limit_expr}"


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
        print(f"IPV4 -> {value}, {self.ipaddr}")

    @property
    def to_int(self):
        return self.ipaddr.value

    def __repr__(self) -> str:
        return f"IPv4({(self.ipaddr)})"


class Mac(Expression):
    def __init__(self, value):
        self.value = value

    def __repr__(self) -> str:
        return f"MacStatement({repr(self.value)})"


class Integer(Expression):
    """
    Example: 42
    """

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
    """
    Example: left + right
    """

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


# ------ Debugging function to convert a model into source code (for easier viewing)


def to_source(node, indent=""):
    print(node)
    if isinstance(node, Integer):
        return repr(node.value)

    elif isinstance(node, Float):
        return repr(node.value)

    elif isinstance(node, Boolean):
        return repr(node.value)

    elif isinstance(node, Store):
        return f"{indent}{node.name} = {to_source(node.value, indent)};\n"

    elif isinstance(node, VarDecl):
        ty = node.type if node.type else ""
        val = f"= {to_source(node.value, indent)}" if node.value else ""
        return f"{indent}var {node.name} {ty} {val};\n"

    elif isinstance(node, Load):
        return f"{node.name}"

    elif isinstance(node, WhileStatement):
        return (
            f"while {to_source(node.test, indent)} "
            + "{\n"
            + "  "
            + to_source(node.code_block, indent + "  ")
            + "\n"
            + indent
            + "}\n"
        )

    elif isinstance(node, Unary):
        return f"{node.op}{to_source(node.value, indent)}"

    elif isinstance(node, Block):
        return f'{{  {to_source(node.code, indent + "  ")} }}'

    elif isinstance(node, IfStatement):
        if node.true_block and node.else_block:
            return (
                f"if {to_source(node.test, indent)} "
                + "{\n"
                + "  "
                + to_source(node.true_block, indent + "  ")
                + " } else {\n"
                + "  "
                + to_source(node.else_block, indent + "  ")
                + " }\n"
            )
        else:
            return (
                f"if {to_source(node.test, indent)} "
                + "{\n"
                + "  "
                + to_source(node.true_block, indent + "  ")
                + " }\n"
            )

    elif isinstance(node, Grouping):
        return f"({to_source(node.value, indent)})"

    elif isinstance(node, ConstDecl):
        ty = node.type if node.type else ""
        val = f"= {to_source(node.value, indent)}"
        return f"{indent}const {node.name} {ty} {val};\n"

    elif isinstance(node, BinOp):
        return (
            f"{to_source(node.left, indent)} {node.op} {to_source(node.right, indent)}"
        )

    elif isinstance(node, PrintStatement):
        return f"print {to_source(node.value, indent)};\n"

    elif isinstance(node, ContinueStatement):
        return f"{indent}continue;\n"

    elif isinstance(node, BreakStatement):
        return f"{indent}break;\n"

    elif isinstance(node, list):
        return "".join(to_source(n, indent) for n in node)

    else:
        raise RuntimeError(f"Can't convert {node} to source")

# interp.py

from pql.model import *


def interpret_program(model):
    env = {}
    return interpret(model, env)


def interpret(node, env):
    if isinstance(node, Integer):
        return int(node.value)

    elif isinstance(node, Float):
        return float(node.value)

    elif isinstance(node, String):
        return f'"{node.value}"'

    elif isinstance(node, Date):
        return node.timestamp

    elif isinstance(node, Label):
        return node.value

    elif isinstance(node, IPv4):
        return node.to_int

    elif isinstance(node, SelectStatement):
        value = interpret(node.value, env)
        print(value)
        return None

    elif isinstance(node, PrintStatement):
        value = interpret(node.value, env)
        print(value)
        return None

    elif isinstance(node, (VarDecl, ConstDecl)):
        if node.value:
            val = interpret(node.value, env)
        else:
            val = None
        env[node.name] = val
        return None

    elif isinstance(node, Load):
        return env[node.name]

    elif isinstance(node, Store):
        value = interpret(node.value, env)
        env[node.name] = value
        return None

    elif isinstance(node, Unary):
        value = interpret(node.value, env)
        if node.op == "-":
            return value * -1
        elif node.op == "+":
            return value
        elif node.op == "!":
            return not value

    elif isinstance(node, Grouping):
        return f"({interpret(node.value, env)})"

    elif isinstance(node, Boolean):
        return node.value

    elif isinstance(node, BinOp):
        leftval = interpret(node.left, env)
        rightval = interpret(node.right, env)

        if node.op == "/":
            return f"{IPv4(leftval).to_network(rightval)[0]} AND {IPv4(leftval).to_network(rightval)[1]}"
        elif node.op == "in":
            return f" {leftval} BETWEEN {rightval}"
        elif node.op == "*":
            return "*"
            # return leftval * rightval
        elif node.op == "+":
            return f"{leftval} + {rightval}"
        elif node.op == "-":
            return f"{leftval} - {rightval}"
        elif node.op == "<":
            return f"{leftval} < {rightval}"
        elif node.op == "<=":
            return f"{leftval} <= {rightval}"
        elif node.op == ">":
            return f"{leftval} > {rightval}"
        elif node.op == ">=":
            return f"{leftval} >= {rightval}"
        elif node.op == "==":
            return f"{leftval} == {rightval}"
        elif node.op == "and":
            return f"{leftval} AND {rightval}"
        elif node.op == "or":
            return f"{leftval} OR {rightval}"
        elif node.op == "!=":
            return f"{leftval} <> {rightval}"

    elif isinstance(node, IfStatement):
        testval = interpret(node.test, env)
        if testval:
            interpret(node.true_block, env)
        else:
            interpret(node.else_block, env)
        return None

    elif isinstance(node, WhileStatement):
        while interpret(node.test, env):
            try:
                interpret(node.code_block, env)
            except Break:
                break
            except Continue:
                continue
        return None

    elif isinstance(node, BreakStatement):
        print("In break")
        raise Break()

    elif isinstance(node, ContinueStatement):
        print("In continue")
        raise Continue()

    elif isinstance(node, list):
        result = None
        for n in node:
            result = interpret(n, env)
        return result

    raise RuntimeError(f"Can't interpret {node}")


class Break(Exception):
    pass


class Continue(Exception):
    pass

# interp.py

from datetime import datetime, timedelta

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

    elif isinstance(node, Now):
        time_result = datetime.fromtimestamp(node.value)
        match node.modifier:
            case "s":
                time_result -= timedelta(seconds=node.offset)
            case "m":
                time_result -= timedelta(minutes=node.offset)
            case "h":
                time_result -= timedelta(hours=node.offset)
            case "d":
                time_result -= timedelta(days=node.offset)
            case "w":
                time_result -= timedelta(weeks=node.offset)

        return int(round(time_result.timestamp()))

    elif isinstance(node, SelectStatement):
        value = interpret(node.value, env)
        print(value)
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
        elif node.op == "to":
            return f"(ip_src = {leftval} and ip_dst = {rightval}) or (ip_dst = {leftval} and ip_src = {rightval})"
        elif node.op == "in" or node.op == "between":
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
            return f"{leftval} = {rightval}"
        elif node.op == "and":
            return f"{leftval} AND {rightval}"
        elif node.op == "or":
            return f"{leftval} OR {rightval}"
        elif node.op == "!=":
            return f"{leftval} <> {rightval}"

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

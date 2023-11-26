# interp.py

from datetime import datetime, timedelta
from packet.layers.ipv4 import IPV4

from pql.model import *
from pql.pcapfile import PcapFile
from packet.layers.packet_builder import PacketBuilder
from packet.layers.packet_decode import PacketDecode
from pql.tokens_list import *
from dbase.index_manager import PktPtr

# ---------------------------------------------
# Process a pcap file to filter
# The pcapfile should be iterator based
# ---------------------------------------------


def exec_program(model, pkt_ref: PktPtr):
    pfile = PcapFile()
    pfile.open(f"{pkt_ref.file_id}")
    env = {}

    pd = PacketDecode()
    hdr, pkt = pfile.get(pkt_ref.ptr)
    pd.decode(hdr, pkt)
    if interpret(model, env, pd):
        pkt_ref.header = hdr
        pkt_ref.packet = pkt
        return pkt_ref
    else:
        return None


def interpret(node, env, packet: PacketDecode):
    if isinstance(node, Integer):
        return int(node.value)

    elif isinstance(node, Date):
        return node.timestamp

    elif isinstance(node, Label):
        value = packet.get_field(node.value)
        if isinstance(value, IPv4):
            return value.to_int
        else:
            return value

    elif isinstance(node, IPv4):
        return node

    elif isinstance(node, Mac):
        return node

    elif isinstance(node, ConstDecl):
        return node.value

    elif isinstance(node, Now):
        time_result = datetime.fromtimestamp(node.value)
        if node.modifier == "s":
            time_result -= timedelta(seconds=node.offset)
        elif node.modifier == "m":
            time_result -= timedelta(minutes=node.offset)
        elif node.modifier == "h":
            time_result -= timedelta(hours=node.offset)
        elif node.modifier == "d":
            time_result -= timedelta(days=node.offset)
        elif node.modifier == "w":
            time_result -= timedelta(weeks=node.offset)
        elif node.modifier == "M":
            time_result -= timedelta(days=node.offset)

        # print(f"In Now {int(round(time_result.timestamp()))}")
        return int(round(time_result.timestamp()))

    elif isinstance(node, SelectStatement):
        value = interpret(node.select_expr, env, packet)
        return None

    elif isinstance(node, Unary):
        value = interpret(node.value, env, packet)
        if node.op == "-":
            return value * -1
        elif node.op == "+":
            return value
        elif node.op == "!":
            return not value

    elif isinstance(node, Grouping):
        return interpret(node.value, env, packet)

    elif isinstance(node, Boolean):
        return node.value

    elif isinstance(node, BinOp):
        leftval = interpret(node.left, env, packet)
        rightval = interpret(node.right, env, packet)

        # if node.op == "/":
        #     return IPv4(leftval).to_network(rightval)[0] <= IPv4(leftval).to_network(rightval)[1]
        if node.op == "to":
            return f"(ip_src = {leftval} and ip_dst = {rightval}) or (ip_dst = {leftval} and ip_src = {rightval})"
        elif node.op == "in":
            return rightval.is_in_network(leftval)
        elif node.op == "*":
            return "*"
            # return leftval * rightval
        elif node.op == TOK_PLUS:
            return leftval + rightval
        elif node.op == TOK_MINUS:
            return leftval - rightval
        elif node.op == TOK_LT:
            return leftval < rightval
        elif node.op == TOK_LE:
            return leftval <= rightval
        elif node.op == TOK_GT:
            return leftval > rightval
        elif node.op == TOK_GE:
            # print(f"{leftval},{rightval}")
            return leftval >= rightval
        elif node.op == TOK_EQ:
            if isinstance(rightval, IPv4):
                return rightval.is_in_network(leftval)
            elif isinstance(rightval, Mac):
                return leftval == rightval.to_int
            else:
                return leftval == rightval
        elif node.op == TOK_LAND:
            return leftval and rightval
        elif node.op == TOK_LOR:
            return leftval or rightval
        elif node.op == TOK_NE:
            if isinstance(rightval, IPv4):
                return not rightval.is_in_network(leftval)
            elif isinstance(rightval, Mac):
                return leftval != rightval.to_int
            else:
                return leftval != rightval

    elif isinstance(node, list):
        result = None
        for n in node:
            result = interpret(n, env, packet)
        return result

    raise RuntimeError(f"Can't interpret {node}")


def int_ip(value):
    if isinstance(value, IPv4):
        return value.to_int
    else:
        return value


class Break(Exception):
    pass


class Continue(Exception):
    pass
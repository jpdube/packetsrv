# interp.py

from datetime import datetime, timedelta
from packet.layers.ipv4 import IPV4

from pql.model import *
from pql.pcapfile import PcapFile
from packet.layers.packet_builder import PacketBuilder
from packet.layers.packet_decode import PacketDecode
from pql.tokens_list import *


# ---------------------------------------------
# Process a pcap file to filter
# The pcapfile should be iterator based
# ---------------------------------------------
def interpret_program(model, pcapfile):
    env = {}
    pfile = PcapFile()
    pfile.open(pcapfile)
    packet_list = []
    total = 0
    for pkt in pfile.next():
        total += 1
        found = interpret(model, env, pkt)
        if found:
            packet_list.append(True)
            # pb = PacketBuilder()
            # pb.from_bytes(pkt.packet)
            # print(pb)

    print(f"Found {len(packet_list)} packets in {total}")


def interpret(node, env, packet: PacketDecode):
    if isinstance(node, Integer):
        return int(node.value)

    elif isinstance(node, Date):
        return node.timestamp

    elif isinstance(node, Label):
        value = packet.get_field(node.value)
        # print(f"In Label: {node.value}:{value}")
        if isinstance(value, IPv4):
            return value.to_int
        else:
            return value

    elif isinstance(node, IPv4):
        # print(node.to_int)
        return node

    elif isinstance(node, Mac):
        # print(node.to_int)
        return node

    elif isinstance(node, ConstDecl):
        return node.value

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
        value = interpret(node.value, env, packet)
        print(value)
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
            # print(f"IN {leftval}:{rightval}")
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

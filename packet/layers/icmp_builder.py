from struct import unpack
from packet.layers.icmp_echo import IcmpEcho
from packet.layers.icmp_dest_unreach import IcmpDestUnreach
from packet.layers.icmp_info_req import IcmpInfoReq
from packet.layers.icmp_param_problem import IcmpParamProblem
from packet.layers.icmp_redirect import IcmpRedirect
from packet.layers.icmp_src_quench import IcmpSrcQuench
from packet.layers.icmp_time_exceeded import IcmpTimeExceeded
from packet.layers.icmp_timestamp import IcmpTimestamp

ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11
ICMP_PARAM_PROBLEM = 12
ICMP_SRC_QUENCH = 4
ICMP_REDIRECT_MSG = 5
ICMP_ECHO_MSG = 8
ICMP_ECHO_REPLY = 0
ICMP_TIMESTAMP_MSG = 13
ICMP_TIMESTAMP_REPLY = 14
ICMP_INFO_REQ = 15
ICMP_INFO_REPLY = 16


def icmp_builder(packet):
    icmp_type = unpack("!B", packet[0:1])[0]
    if icmp_type == ICMP_ECHO_MSG or icmp_type == ICMP_ECHO_REPLY:
        return IcmpEcho(packet)
    elif icmp_type == ICMP_DEST_UNREACHABLE:
        return IcmpDestUnreach(packet)
    elif icmp_type == ICMP_TIME_EXCEEDED:
        return IcmpTimeExceeded(packet)
    elif icmp_type == ICMP_PARAM_PROBLEM:
        return IcmpParamProblem(packet)
    elif icmp_type == ICMP_SRC_QUENCH:
        return IcmpSrcQuench(packet)
    elif icmp_type == ICMP_REDIRECT_MSG:
        return IcmpRedirect(packet)
    elif icmp_type == ICMP_TIMESTAMP_MSG or icmp_type == ICMP_TIMESTAMP_REPLY:
        return IcmpTimestamp(packet)
    elif icmp_type == ICMP_INFO_REQ or icmp_type == ICMP_INFO_REPLY:
        return IcmpInfoReq(packet)

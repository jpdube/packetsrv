from struct import unpack

from packet.layers.fields import IPv4Address
from packet.layers.layer_type import LayerID
from packet.layers.packet import Packet

type_values = {
    1: "1: Type(A)",
    2: "2: Type(NS)",
    3: "3: Type(MD)",
    4: "4: Type(MF)",
    5: "5: Type(CNAME)",
    6: "6: Type(SOA)",
    7: "7: Type(MB)",
    8: "8: Type(MG)",
    9: "9: Type(MR)",
    10: "10: Type(NULL)",
    11: "11: Type(WKS)",
    12: "12: Type(PTR)",
    13: "13: Type(HINFO)",
    14: "14: Type(MINFO)",
    15: "15: Type(MX)",
    16: "16: Type(TXT)",
    33: "33: Type(SRV)",
}


class DnsHeader:
    def __init__(self, header: bytes):
        self.header = header

    @property
    def id(self) -> int:
        return unpack("!H", self.header[0:2])[0]

    @property
    def qr_flag(self) -> bool:
        return unpack("!B", self.header[2:3])[0] & 0x01

    @property
    def opcode(self) -> int:
        return self.flags & 0x78

    @property
    def recursion(self) -> bool:
        return (self.flags & 0x100) == 0x100

    @property
    def flags(self) -> bool:
        return unpack("!H", self.header[2:4])[0]

    @property
    def response(self) -> bool:
        return (self.flags & 0x8000) == 0x8000

    @property
    def questions(self) -> int:
        return unpack("!H", self.header[4:6])[0]

    @property
    def answer_rr(self) -> int:
        return unpack("!H", self.header[6:8])[0]

    @property
    def authority_rr(self) -> int:
        return unpack("!H", self.header[8:10])[0]

    @property
    def add_rr(self) -> int:
        return unpack("!H", self.header[10:12])[0]

    def __str__(self) -> str:
        return f"ID: {self.id:x}, Flags: {self.flags:04x}, QR: {self.qr_flag}, OpCode: {self.opcode:x}, Recur: {self.recursion}, Questions: {self.questions}"

    def export(self) -> dict[str, int | str]:
        return {
            "dns.id": self.id,
            "dns.flags": self.flags,
            "dns.qr_flag": self.qr_flag,
            "dns.opcode": self.opcode,
            "dns.recursion": self.recursion,
            "dns.response": self.response,
            "dns.questions": self.questions,
            "dns.answer_rr": self.answer_rr,
            "dns.add_rr": self.add_rr,
        }


class DnsQuery:
    def __init__(self, query):
        self.query = query
        # print_hex(self.query)
        self.label_list = []
        self.qtype = 0
        self.qclass = 0
        self.answer_pos = 0

        self.decode()

    def get_label(self, index, label_len):
        return self.query[index: index + label_len].decode("utf-8")

    def decode(self):
        index = 0

        while self.query[index] != 0:
            label_len = self.query[index]
            label = self.get_label(index + 1, label_len)
            self.label_list.append(label)
            index += label_len + 1

        index += 1
        self.qtype = unpack("!H", self.query[index: index + 2])[0]
        self.qclass = unpack("!H", self.query[index + 2: index + 4])[0]

        self.answer_pos = index + 4

    def __str__(self) -> str:
        return f'Labels: {self.label_list}, Type: {type_values.get(self.qtype, "Unknow")}, Class: {self.qclass}'

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}  Query ->\n'
        result += f'{" " *
                     offset}   Type.....: {type_values.get(self.qtype, "Undefined")}\n'
        result += f'{" " * offset}   Class....: {self.qclass}\n'

        for l in self.label_list:
            result += f'{" " * offset}   Label....: {l}\n'

        return result

    def export(self) -> dict[str, int | str]:
        result = {
            "dns.type": type_values.get(self.qtype, "Undefined"),
            "dns.class": self.qclass,
            "dns.answer": ".".join(self.label_list)
        }

        # for index, label in enumerate(self.label_list):
        # result[f"dns.label_{index}"] = label

        return result


class DnsAnswer:
    def __init__(self, qtype, qclass, ttl, data_len, result) -> None:
        self.qtype = qtype
        self.qclass = qclass
        self.ttl = ttl
        self.data_len = data_len
        self.result = result

    def __str__(self) -> str:
        return f'Answer -> Type: {type_values.get(self.qtype, "Unknow")}, Class: {self.qclass}, Ttl: {self.ttl}, Len: {self.data_len}, Data: {self.result}'

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}  Answer ->\n'
        result += f'{" " *
                     offset}   Type.....: {type_values.get(self.qtype, "Undefined")}\n'
        result += f'{" " * offset}   Class....: {self.qclass}\n'
        result += f'{" " * offset}   TTL......: {self.ttl}\n'
        result += f'{" " * offset}   Length...: {self.data_len}\n'
        result += f'{" " * offset}   Result...: {self.result}\n'

        return result

    def export(self) -> dict[str, int | str]:
        result = {
            "dns.qtype": type_values.get(self.qtype, "Undefined"),
            "dns.qclass": self.qclass,
            "dns.ttl": self.ttl,
            "dns.length": self.data_len,
            "dns.result": str(self.result)
        }

        return result


class Dns(Packet):
    name = LayerID.DNS

    __slots__ = ["packet"]

    def __init__(self, packet):
        self.packet = packet
        # print('*************************************')
        # print_hex(packet)
        # print('*************************************')
        self.header = DnsHeader(packet)
        self.queries = DnsQuery(self.packet[12:])
        self.answer_list = []

        if self.header.response:
            self.decode_answer(self.packet[self.queries.answer_pos + 12:])
        else:
            self.answer = None

    def decode_answer(self, answer):
        for a in range(self.header.answer_rr):
            result = "Type not implemented yet"
            start = unpack("!H", answer[0:2])[0]
            # print(f'******* Decode answer: {start:x}')
            if (start & 0xFF00) == 0xC000:
                qtype = unpack("!H", answer[2:4])[0]
                qclass = unpack("!H", answer[4:6])[0]
                ttl = unpack("!I", answer[6:10])[0]
                data_len = unpack("!H", answer[10:12])[0]
                # print(f'#### Data len label: {data_len}')
                if qtype == 1:
                    result = IPv4Address(
                        unpack("!I", answer[12: 12 + data_len])[0])
                elif qtype == 33:
                    result = self.get_srv(answer[12: 12 + data_len], data_len)
                elif qtype in [5, 6]:
                    result = self.get_labels(answer[12: 12 + data_len])  # -1

                dns_answer = DnsAnswer(qtype, qclass, ttl, data_len, result)
                self.answer_list.append(dns_answer)

                answer = answer[12 + data_len:]

    def get_srv(self, packet, data_len):
        priority = unpack("!H", packet[0:2])[0]
        weight = unpack("!H", packet[2:4])[0]
        port = unpack("!H", packet[4:6])[0]
        target = self.get_labels(packet[6: 6 + (data_len - 6)])
        # target = unpack(f'!{data_len - 6}s', packet[6: 6 + (data_len - 6)])

        return f"Priority: {priority}, Weight: {weight}, Port: {port}, Target: {target}"

    def get_labels(self, packet) -> str:
        result = ""
        label_list = []
        pos = 0

        # print(f'^^^^^^ {self.header.id:x} ^^^^^^^')
        while pos < len(packet) and packet[pos] not in [0x00, 0xC0, 0xC1]:
            # print(f'====== {pos}, ')
            # print_hex(packet)
            label_len = packet[pos]
            pos += 1
            label = unpack(f"!{label_len}s", packet[pos: pos + label_len])[0].decode(
                "ascii"
            )
            label_list.append(label)
            pos += label_len

        # print(f'+++++ {result}')
        for i, l in enumerate(label_list):
            result += l
            if i < len(label_list) - 1:
                result += "."

        return result

    def summary(self, offset: int) -> str:
        result = f'{" " * offset}DNS ->\n'

        result += self.queries.summary(offset)

        for answer in self.answer_list:
            result += answer.summary(offset)

        return result

    def __str__(self) -> str:
        result = (
            f"DNS ->{self.header} Option: {self.queries}\n"
            # f"DNS ->{self.header}\n{format_hex(self.packet)} Option: {self.queries}\n"
        )
        for i, a in enumerate(self.answer_list):
            result += f"{i}: {a}\n"

        return result

    def export(self) -> dict[str, int | str]:
        result = {
            "dns.id": self.header.id,
            "dns.flags": self.header.flags,
            "dns.qr_flag": self.header.qr_flag,
            "dns.opcode": self.header.opcode,
            "dns.recursion": self.header.recursion,
            "dns.questions": self.header.questions,
        }

        result.update(self.queries.export())

        if self.answer_list is not None:
            for answer in self.answer_list:
                result.update(answer.export())

        return result

    def get_field(self, fieldname: str) -> int | None:
        match fieldname:
            case "dns.opcode":
                return self.header.opcode
            case "dns.flags":
                return self.header.flags
            case "dns.recursion":
                return self.header.recursion
            case "dns.questions":
                return self.header.questions
            case _:
                return None

    def get_array(self, offset: int, length: int) -> bytes | None:
        if offset < len(self.packet) and (offset + length) < len(self.packet):
            return self.packet[offset: offset + length]
        else:
            return None

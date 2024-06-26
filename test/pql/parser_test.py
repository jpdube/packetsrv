import app.pql.parse as parser
from app.pql.lexer import tokenize
from app.pql.model import BinOp, Integer, Label
from app.pql.tokens_list import *
from datetime import datetime

def date_to_timestamp(str_datetime: str) -> int:
    element = datetime.strptime(str_datetime, "%Y-%m-%d %H:%M:%S")
    timestamp = datetime.timestamp(element)

    return int(timestamp)

def test_bit_shift_right():
    tokens = tokenize("ip.version >> 4")
    model = parser.parse_expression(parser.Tokenizer(tokens))
    assert (model.op == Tokens.TOK_BITSHIFT_RIGHT)
    assert (model.left.value == "ip.version")
    assert (model.right.value == 4)


def test_bit_shift_left():
    tokens = tokenize("ip.version << 4")
    model = parser.parse_expression(parser.Tokenizer(tokens))
    assert (model.op == Tokens.TOK_BITSHIFT_LEFT)
    assert (model.left.value == "ip.version")
    assert (model.right.value == 4)


def test_bit_shift_and():
    tokens = tokenize("ip.version & 0x0f")
    model = parser.parse_expression(parser.Tokenizer(tokens))
    assert (model.op == Tokens.TOK_BIT_AND)
    assert (model.left.value == "ip.version")
    assert (model.right.value == 0x0f)


def test_bit_shift_or():
    tokens = tokenize("ip.version | 0x0f")
    model = parser.parse_expression(parser.Tokenizer(tokens))
    assert (model.op == Tokens.TOK_BIT_OR)
    assert (model.left.value == "ip.version")
    assert (model.right.value == 0x0f)


def test_bit_shift_xor():
    tokens = tokenize("ip.version ^ 0x0f")
    model = parser.parse_expression(parser.Tokenizer(tokens))
    assert (model.op == Tokens.TOK_BIT_XOR)
    assert (model.left.value == "ip.version")
    assert (model.right.value == 0x0f)


def test_ipv4():
    tokens = tokenize("192.168.3.200/24")
    model = parser.parse_ipv4(parser.Tokenizer(tokens))
    assert (model.to_int == 0xc0a803c8)
    assert (model.mask == 24)


def test_mac():
    tokens = tokenize("00:01:02:03:04:05")
    model = parser.parse_mac(parser.Tokenizer(tokens))
    assert (model.to_int == 0x000102030405)


def test_integer():
    tokens = tokenize("123")
    model = parser.parse_integer(parser.Tokenizer(tokens))
    assert (int(model.value) == 123)


def test_date():
    tokens = tokenize("2023-11-29")
    model = parser.parse_date(parser.Tokenizer(tokens))
    assert (model.value == "2023-11-29")


def test_interval():
    tokens = tokenize("interval 2023-11-29 13:00:00 to 2023-11-29 14:00:00")
    model = parser.parse_interval(parser.Tokenizer(tokens))
    assert (model[0] == date_to_timestamp("2023-11-29 13:00:00"))
    assert (model[1] == date_to_timestamp("2023-11-29 14:00:00"))


def test_offset():
    tokens = tokenize("offset 22")
    model = parser.parse_offset(parser.Tokenizer(tokens))
    assert (model == 22)


def test_top():
    tokens = tokenize("top 100")
    model = parser.parse_top(parser.Tokenizer(tokens))
    assert (model == 100)


def test_group_by():
    tokens = tokenize("group by tcp.dport, ip.src")
    model = parser.parse_groupby(parser.Tokenizer(tokens))
    assert (model[0] == "tcp.dport")
    assert (model[1] == "ip.src")


def test_from_one_source():
    tokens = tokenize("from col_01_east")
    model = parser.parse_from(parser.Tokenizer(tokens))
    assert (model[0] == "col_01_east")


def test_from_multiple_source():
    tokens = tokenize("from col_01_east, col_01_west, col_02_south")
    model = parser.parse_from(parser.Tokenizer(tokens))
    assert (model[0] == "col_01_east")
    assert (model[1] == "col_01_west")
    assert (model[2] == "col_02_south")


def test_count():
    tokens = tokenize("count() as src_count")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "src_count")


def test_sum():
    tokens = tokenize("sum(frame.orig_len) as ttl_bytes")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "ttl_bytes")
    assert (model.fieldname == "frame.orig_len")


def test_average():
    tokens = tokenize("avg(frame.orig_len) as avg_bytes")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "avg_bytes")
    assert (model.fieldname == "frame.orig_len")


def test_min():
    tokens = tokenize("min(frame.orig_len) as min_bytes")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "min_bytes")
    assert (model.fieldname == "frame.orig_len")


def test_max():
    tokens = tokenize("max(frame.orig_len) as max_bytes")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "max_bytes")
    assert (model.fieldname == "frame.orig_len")


def test_bandwidth():
    tokens = tokenize("bandwidth(frame.orig_len) as bw_bytes")
    model = parser.parse_aggregate(parser.Tokenizer(tokens))
    print(model)
    assert (model.as_of == "bw_bytes")
    assert (model.fieldname == "frame.orig_len")

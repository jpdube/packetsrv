from app.pql.model import IPv4
import app.pql.parse as parser
from app.pql.tokens_list import *
from app.pql.lexer import tokenize
# import pytest


def test_ipv4():
    tokens = tokenize("192.168.3.200/24")
    model = parser.parse_ipv4(parser.Tokenizer(tokens))
    assert(model.to_int == 0xc0a803c8)
    assert(model.mask == 24)


def test_mac():
    tokens = tokenize("00:01:02:03:04:05")
    model = parser.parse_mac(parser.Tokenizer(tokens))
    assert(model.to_int == 0x000102030405)


def test_integer():
    tokens = tokenize("123")
    model = parser.parse_integer(parser.Tokenizer(tokens))
    assert(int(model.value) == 123)


def test_date():
    tokens = tokenize("2023-11-29")
    model = parser.parse_date(parser.Tokenizer(tokens))
    assert(model.value == "2023-11-29")

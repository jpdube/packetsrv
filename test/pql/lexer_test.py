from ipaddress import IPv4Address
from pql.lexer import Lexer
from pql.tokens_list import Tok
from packet.layers.fields import IPv4Address


def test_date():
    src = '2022-02-01 14:30:45'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = next(tokens)
    print(tok_date)
    if tok_date:
        assert(tok_date.type == Tok.DATE)
        assert(tok_date.value == src)
    else:
        assert(False)


def test_integer():
    src = '80'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = next(tokens)
    if tok_date:
        assert(tok_date.type == Tok.INTEGER)
        assert(tok_date.value == src)
    else:
        assert(False)


def test_float():
    src = '80.45'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = next(tokens)
    if tok_date:
        assert(tok_date.type == Tok.FLOAT)
        assert(tok_date.value == src)
    else:
        assert(False)


def test_ipv4():
    src = '192.168.3.124'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = next(tokens)
    assert(tok_date.type == Tok.IPV4)
    assert(tok_date.value == src)

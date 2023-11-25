# from ipaddress import IPv4Address
from app.pql.lexer import Lexer, tokenize
from app.pql.tokens_list import *
# from packet.layers.fields import IPv4Address
import pytest


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("select", TOK_SELECT),
        ("from", TOK_FROM),
        ("where", TOK_WHERE),
        ("interval", TOK_INTERVAL),
        ("top", TOK_TOP),
        ("to", TOK_TO),
        ("true", TOK_TRUE),
        ("false", TOK_FALSE),
        ("now", TOK_NOW),
        ("and", TOK_LAND),
        ("or", TOK_LOR),
    )
)
def test_keywords(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    print(tok_keyword)
    assert(tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("/", TOK_MASK),
        ("*", TOK_WILDCARD),
        (";", TOK_SEMI),
        (",", TOK_DELIMITER),
        (">", TOK_GT),
        ("<", TOK_LT),
        ("{", TOK_LBRACE),
        ("}", TOK_RBRACE),
        ("+", TOK_PLUS),
        ("-", TOK_MINUS),
        ("(", TOK_LPAREN),
        (")", TOK_RPAREN),
        ("[", TOK_INDEX_START),
        ("]", TOK_INDEX_END),
        (":", TOK_COLON),
        ("'", TOK_SINGLE_QUOTE),
        (".", TOK_PERIOD),
    )
)
def test_token1(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    print(tok_keyword)
    assert(tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("==", TOK_EQ),
        ("<=", TOK_LE),
        (">=", TOK_GE),
        ("!=", TOK_NE),
    )
)
def test_token2(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    print(tok_keyword)
    assert(tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("192.168.3.10", TOK_IPV4),
        ("2023-10-15", TOK_DATE),
        ("21:23:45", TOK_TIME),
        ("2023-10-12 14:30:50", TOK_TIMESTAMP),
        ("tcp.sport", TOK_NAME),
    )
)
def test_preparse_token(keyword, expected):
    token = tokenize(keyword)
    tok_keyword = next(token)
    print(tok_keyword)
    assert(tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("select * from a", [TOK_SELECT,
         TOK_WILDCARD, TOK_FROM, TOK_NAME, TOK_EOF]),
        ("select * from a where tcp.sport == 53", [TOK_SELECT,
         TOK_WILDCARD, TOK_FROM, TOK_NAME, TOK_WHERE, TOK_NAME, TOK_EQ, TOK_INTEGER, TOK_EOF]),
    )
)
def test_preparse_pql(keyword, expected):
    token = tokenize(keyword)
    for (i, tok) in enumerate(token):
        assert(tok.type == expected[i])


def test_integer():
    src = '80'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = tokens[0]
    if tok_date:
        assert(tok_date.type == TOK_INTEGER)
        assert(tok_date.value == src)
    else:
        assert(False)


# def test_ipv4():
#     src = '192.168.3.124'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_date = next(tokens)
#     assert(tok_date.type == Tok.IPV4)
#     assert(tok_date.value == src)

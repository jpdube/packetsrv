import pytest

from app.pql.lexer import Lexer, tokenize
from app.pql.tokens_list import *


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
        ("avg", TOK_AVERAGE),
    )
)
def test_keywords(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
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
    assert(tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("select * from a", [TOK_SELECT,
         TOK_WILDCARD, TOK_FROM, TOK_NAME, TOK_EOF]),
        ("select * from a where tcp.sport == 53", [TOK_SELECT,
         TOK_WILDCARD, TOK_FROM, TOK_NAME, TOK_WHERE, TOK_NAME, TOK_EQ, TOK_INTEGER, TOK_EOF]),
        ("select count() as PKT_TOTAL from a where tcp.dport == HTTPS", [
         TOK_SELECT, TOK_COUNT, TOK_AS, TOK_FROM, TOK_NAME, TOK_WHERE, TOK_NAME, TOK_EQ, TOK_CONST, TOK_EOF]),
        ("select sum(frame.inc_len) as PKT_TOTAL from a where tcp.dport == HTTPS", [
         TOK_SELECT, TOK_SUM, TOK_AS, TOK_FROM, TOK_NAME, TOK_WHERE, TOK_NAME, TOK_EQ, TOK_CONST, TOK_EOF])
    )
)
def test_preparse_pql(keyword, expected):
    token = tokenize(keyword)
    print(list(token))
    token = tokenize(keyword)
    for (i, tok) in enumerate(token):
        assert(tok.type == expected[i])


def test_count():
    pql = "count () as PKT_TEST"
    token = tokenize(pql)
    tok_count = next(token)
    assert(tok_count.type == TOK_COUNT)
    tok_as = next(token)
    assert(tok_as.type == TOK_AS)
    assert(tok_as.value == "PKT_TEST")


def test_sum():
    pql = "sum (frame.inclen) as PKT_SUM"
    token = tokenize(pql)
    tok_count = next(token)
    assert(tok_count.type == TOK_SUM)
    assert(tok_count.value == "frame.inclen")
    tok_as = next(token)
    assert(tok_as.type == TOK_AS)
    assert(tok_as.value == "PKT_SUM")


def test_average():
    pql = "avg (frame.inclen) as PKT_AVG"
    token = tokenize(pql)
    tok_count = next(token)
    assert(tok_count.type == TOK_AVERAGE)
    assert(tok_count.value == "frame.inclen")
    tok_as = next(token)
    assert(tok_as.type == TOK_AS)
    assert(tok_as.value == "PKT_AVG")


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

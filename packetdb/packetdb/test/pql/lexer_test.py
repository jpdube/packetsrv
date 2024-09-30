import pytest

from app.pql.lexer import Lexer, tokenize
from app.pql.tokens_list import Tokens


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("select", Tokens.TOK_SELECT),
        ("from", Tokens.TOK_FROM),
        ("where", Tokens.TOK_WHERE),
        ("interval", Tokens.TOK_INTERVAL),
        ("top", Tokens.TOK_TOP),
        ("to", Tokens.TOK_TO),
        ("true", Tokens.TOK_TRUE),
        ("false", Tokens.TOK_FALSE),
        ("now", Tokens.TOK_NOW),
        ("and", Tokens.TOK_LAND),
        ("or", Tokens.TOK_LOR),
        ("avg", Tokens.TOK_AVERAGE),
    )
)
def test_keywords(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    assert (tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("/", Tokens.TOK_MASK),
        ("*", Tokens.TOK_WILDCARD),
        (";", Tokens.TOK_SEMI),
        (",", Tokens.TOK_DELIMITER),
        (">", Tokens.TOK_GT),
        ("<", Tokens.TOK_LT),
        ("{", Tokens.TOK_LBRACE),
        ("}", Tokens.TOK_RBRACE),
        ("+", Tokens.TOK_PLUS),
        ("-", Tokens.TOK_MINUS),
        ("(", Tokens.TOK_LPAREN),
        (")", Tokens.TOK_RPAREN),
        ("[", Tokens.TOK_INDEX_START),
        ("]", Tokens.TOK_INDEX_END),
        (":", Tokens.TOK_COLON),
        ("'", Tokens.TOK_SINGLE_QUOTE),
        (".", Tokens.TOK_PERIOD),
    )
)
def test_token1(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    assert (tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("==", Tokens.TOK_EQ),
        ("<=", Tokens.TOK_LE),
        (">=", Tokens.TOK_GE),
        ("!=", Tokens.TOK_NE),
    )
)
def test_token2(keyword, expected):
    lexer = Lexer(keyword)
    tokens = lexer.tokenize()
    tok_keyword = tokens[0]
    assert (tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("192.168.3.10", Tokens.TOK_IPV4),
        ("2023-10-15", Tokens.TOK_DATE),
        ("21:23:45", Tokens.TOK_TIME),
        ("2023-10-12 14:30:50", Tokens.TOK_TIMESTAMP),
        ("tcp.sport", Tokens.TOK_NAME),
    )
)
def test_preparse_token(keyword, expected):
    token = tokenize(keyword)
    tok_keyword = next(token)
    assert (tok_keyword.type == expected)


@pytest.mark.parametrize(

    ('keyword', 'expected'),
    (
        ("select * from a", [Tokens.TOK_SELECT,
         Tokens.TOK_WILDCARD, Tokens.TOK_FROM, Tokens.TOK_NAME, Tokens.TOK_EOF]),
        ("select * from a where tcp.sport == 53", [Tokens.TOK_SELECT,
         Tokens.TOK_WILDCARD, Tokens.TOK_FROM, Tokens.TOK_NAME, Tokens.TOK_WHERE, Tokens.TOK_NAME, Tokens.TOK_EQ, Tokens.TOK_INTEGER, Tokens.TOK_EOF]),
        ("select count() as PKT_TOTAL from a where tcp.dport == HTTPS", [
         Tokens.TOK_SELECT, Tokens.TOK_COUNT, Tokens.TOK_AS, Tokens.TOK_FROM, Tokens.TOK_NAME, Tokens.TOK_WHERE, Tokens.TOK_NAME, Tokens.TOK_EQ, Tokens.TOK_CONST, Tokens.TOK_EOF]),
        ("select sum(frame.inc_len) as PKT_TOTAL from a where tcp.dport == HTTPS", [
         Tokens.TOK_SELECT, Tokens.TOK_SUM, Tokens.TOK_AS, Tokens.TOK_FROM, Tokens.TOK_NAME, Tokens.TOK_WHERE, Tokens.TOK_NAME, Tokens.TOK_EQ, Tokens.TOK_CONST, Tokens.TOK_EOF])
    )
)
def test_preparse_pql(keyword, expected):
    token = tokenize(keyword)
    token = tokenize(keyword)
    for (i, tok) in enumerate(token):
        assert (tok.type == expected[i])


def test_count():
    pql = "count () as PKT_TEST"
    token = tokenize(pql)
    tok_count = next(token)
    assert (tok_count.type == Tokens.TOK_COUNT)
    tok_as = next(token)
    assert (tok_as.type == Tokens.TOK_AS)
    assert (tok_as.value == "PKT_TEST")


def test_sum():
    pql = "sum (frame.inclen) as PKT_SUM"
    token = tokenize(pql)
    tok_count = next(token)
    assert (tok_count.type == Tokens.TOK_SUM)
    assert (tok_count.value == "frame.inclen")
    tok_as = next(token)
    assert (tok_as.type == Tokens.TOK_AS)
    assert (tok_as.value == "PKT_SUM")


def test_average():
    pql = "avg (frame.inclen) as PKT_AVG"
    token = tokenize(pql)
    tok_count = next(token)
    assert (tok_count.type == Tokens.TOK_AVERAGE)
    assert (tok_count.value == "frame.inclen")
    tok_as = next(token)
    assert (tok_as.type == Tokens.TOK_AS)
    assert (tok_as.value == "PKT_AVG")


def test_integer():
    src = '80'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_date = tokens[0]
    if tok_date:
        assert (tok_date.type == Tokens.TOK_INTEGER)
        assert (tok_date.value == src)
    else:
        assert (False)

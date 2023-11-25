# from ipaddress import IPv4Address
from pql.lexer import Lexer
from pql.tokens_list import *
# from packet.layers.fields import IPv4Address


# def test_comment():
#     src = '#'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_keyword = next(tokens)
#     print(tok_keyword)
#     if tok_keyword:
#         assert(tok_keyword.type == TOK_EOF)
#     else:
#         assert(False)


def test_start_index():
    src = "["
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_keyword = next(tokens)
    print(tok_keyword)
    if tok_keyword:
        assert(tok_keyword.type == TOK_INDEX_START)
        assert(tok_keyword.value == src)
    else:
        assert(False)


def test_end_index():
    src = ']'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_keyword = next(tokens)
    print(tok_keyword)
    if tok_keyword:
        assert(tok_keyword.type == TOK_INDEX_END)
        assert(tok_keyword.value == src)
    else:
        assert(False)

# def test_colon():
#     src = ':'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_keyword = next(tokens)
#     print(tok_keyword)
#     if tok_keyword:
#         assert(tok_keyword.type == TOK_COLON)
#         assert(tok_keyword.value == src)
#     else:
#         assert(False)


def test_gt():
    src = '>'
    lexer = Lexer(src)
    tokens = lexer.tokenize()
    tok_keyword = next(tokens)
    print(tok_keyword)
    if tok_keyword:
        assert(tok_keyword.type == TOK_GT)
        assert(tok_keyword.value == src)
    else:
        assert(False)


# def test_where():
#     src = 'where'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_keyword = next(tokens)
#     print(tok_keyword)
#     if tok_keyword:
#         assert(tok_keyword.type == Tok.WHERE)
#         assert(tok_keyword.value == src)
#     else:
#         assert(False)


# def test_from():
#     src = 'from'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_keyword = next(tokens)
#     print(tok_keyword)
#     if tok_keyword:
#         assert(tok_keyword.type == Tok.FROM)
#         assert(tok_keyword.value == src)
#     else:
#         assert(False)


# def test_select():
#     src = 'select'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_select = next(tokens)
#     print(tok_select)
#     if tok_select:
#         assert(tok_select.type == Tok.SELECT)
#         assert(tok_select.value == src)
#     else:
#         assert(False)


# def test_integer():
#     src = '80'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_date = next(tokens)
#     if tok_date:
#         assert(tok_date.type == Tok.INTEGER)
#         assert(tok_date.value == src)
#     else:
#         assert(False)


# def test_float():
#     src = '80.45'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_date = next(tokens)
#     if tok_date:
#         assert(tok_date.type == Tok.FLOAT)
#         assert(tok_date.value == src)
#     else:
#         assert(False)


# def test_ipv4():
#     src = '192.168.3.124'
#     lexer = Lexer(src)
#     tokens = lexer.tokenize()
#     tok_date = next(tokens)
#     assert(tok_date.type == Tok.IPV4)
#     assert(tok_date.value == src)

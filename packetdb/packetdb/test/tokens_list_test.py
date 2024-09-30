import pytest
from app.pql.tokens_list import Tokens


def test_equal():
    t0 = Tokens.TOK_ARRAY
    t1 = Tokens.TOK_ARRAY
    assert (t0 == t1)


def test_equal_str():
    t0 = Tokens.TOK_ARRAY
    t1 = "Array"
    assert (t0 != t1)


def test_str():
    t0 = Tokens.TOK_SELECT
    assert (str(t0) == "TOK_SELECT")

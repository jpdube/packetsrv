import pytest

from app.dbase.query_result import QueryResult


def test_found_with_empty_result():
    qr = QueryResult(None)
    assert not qr.is_empty

def test_found_with_result():
    qr = QueryResult(None)
    qr.result['result'].append(1)
    assert qr.is_empty
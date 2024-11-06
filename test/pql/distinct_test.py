
import pytest

from app.pql.lexer import Lexer, tokenize
from app.pql.tokens_list import Tokens
import datetime


def test_distinct_int():
    field_list = set()

    field_list.add(1)
    field_list.add(2)
    field_list.add(3)
    field_list.add(1)
 
    result = set()
    result.add(1)
    result.add(2)
    result.add(3)

    assert(field_list == result)

def test_distinct_dict():

    test_list = [{'gfg': 1, 'is': 2}, {'best': 1, 'for': 3}, {'CS': 2}]
 
    # printing original list
    print("The original list : " + str(test_list))
    
    # Using set() + values() + dictionary comprehension
    # Get Unique values from list of dictionary
    res = list(set(val for dic in test_list for val in dic.values()))
    
    # printing result
    print("The unique values in list are : " + str(res))


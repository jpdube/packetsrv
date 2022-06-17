from dbase.read_packet import query

from pql.interp import *
from pql.model import *
from pql.parse import *


def exec_query(pql: str):
    model = parse_source(pql)
    return build_sql(model)


def exec_from_file(filename: str):
    model = parse_file(filename)
    for m in model:
        print(m)

    build_sql(model)


def build_sql(model):
    sql = "SELECT "
    include = 'packet'

    for m in model:
        if isinstance(m, SelectStatement):
            sql += '*'
            sql += " FROM "
            sql += f" packet"

            if m.where_expr is not None:
                sql += " WHERE "
                # print(f'WHERE EXPR -> {m.where_expr}')
                sql += interpret_program(m.where_expr)

            if m.top_expr is not None:
                sql += " LIMIT "
                sql += m.top_expr.value
            else:
                if m.top_expr is not None:
                    sql += " LIMIT "
                    # print(f'BETWEEN EXPR -> {m.between_expr}')
                    sql += str(interpret_program(m.top_expr))

                if m.limit is not None and m.offset is not None:
                    sql += f" LIMIT {m.offset.value}, {m.limit.value}"

            sql += ";"

    print(f"SQL -> {sql}")
    return query(sql)
# def build_sql(model):
#     sql = "SELECT "
#     include = 'packet'

#     for m in model:
#         if isinstance(m, WithStatement):
#             sql += '*'
#             sql += " FROM "
#             sql += f" packet"

#             if m.filter_expr is not None:
#                 sql += " WHERE "
#                 # print(f'WHERE EXPR -> {m.where_expr}')
#                 sql += interpret_program(m.filter_expr)

#             if m.top_expr is not None:
#                 sql += " LIMIT "
#                 sql += m.top_expr.value
#             else:
#                 if m.top_expr is not None:
#                     sql += " LIMIT "
#                     # print(f'BETWEEN EXPR -> {m.between_expr}')
#                     sql += str(interpret_program(m.top_expr))

#                 if m.limit is not None and m.offset is not None:
#                     sql += f" LIMIT {m.offset.value}, {m.limit.value}"

#             sql += ";"

#     print(f"SQL -> {sql}")
#     return query(sql)

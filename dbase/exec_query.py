from dbase.read_packet import query
from dbase.sql_statement import SqlStatement
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
    sql_stmt = SqlStatement()
    sql_stmt.add_select("*")

    for m in model:
        if isinstance(m, SelectStatement):
            sql += '*'
            sql += " FROM "
            sql += f" packet"
            sql_stmt.add_from("packet")

            if m.where_expr is not None:
                sql += " WHERE "
                # print(f'WHERE EXPR -> {m.where_expr}')
                sql += interpret_program(m.where_expr)
                sql_stmt.add_where(interpret_program(m.where_expr))

            if m.top_expr is not None:
                sql += " LIMIT "
                sql += m.top_expr.value
                sql_stmt.add_limit(m.top_expr.value)
            else:
                if m.top_expr is not None:
                    sql += " LIMIT "
                    # print(f'BETWEEN EXPR -> {m.between_expr}')
                    sql += str(interpret_program(m.top_expr))
                    sql_stmt.add_limit(str(interpret_program(m.top_expr)))

                if m.limit is not None and m.offset is not None:
                    sql += f" LIMIT {m.offset.value}, {m.limit.value}"
                    sql_stmt.add_limit(f"{m.offset.value}, {m.limit.value}")

            sql += ";"

    print(f"SQL -> {sql}")
    print(f"Builder: {sql_stmt.build()}")
    return query(sql_stmt)
    # return query(sql)

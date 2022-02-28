from pql.parse import *
from pql.model import *
from pql.interp import *
from dbase.read_packet import query


def exec_query(filename: str):
    model = parse_file(filename)
    for m in model:
        print(m)

    build_sql(model)


def build_sql(model):
    sql = "SELECT "

    for m in model:
        if isinstance(m, SelectStatement):
            for i, f in enumerate(m.value):
                sql += f"{f.value} "

                if i < len(m.value) - 1:
                    sql += ", "

            if not sql.find("*"):
                sql += "file_ptr, file_id"

            sql += " FROM "
            for s in m.from_fields:
                sql += f" {s.value}"

            sql += " WHERE "
            if m.where_expr is not None:
                # print(f'WHERE EXPR -> {m.where_expr}')
                sql += interpret_program(m.where_expr)

            if m.between_expr is not None:
                if m.where_expr is not None:
                    sql += " AND "
                sql += " timestamp BETWEEN "
                # print(f'BETWEEN EXPR -> {m.between_expr}')
                sql += interpret_program(m.between_expr)

            if m.top_expr is not None:
                sql += " LIMIT "
                # print(f'BETWEEN EXPR -> {m.between_expr}')
                sql += str(interpret_program(m.top_expr))

            if m.limit and m.offset:
                sql += f" LIMIT {m.offset.value}, {m.limit.value}"

            sql += ";"

    print(f"SQL -> {sql}")

    query(sql)

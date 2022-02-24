from datetime import datetime


class QueryProcessor:
    def __init__(self, sql=None):
        self.sql = sql

    def get(self, start_ts=datetime.now(), end_ts=datetime.now(), **kwargs):
        # mac_src=None,
        # mac_dst=None,
        # ip_src=None,
        # ip_dst=None,
        # sport=None,
        # dport=None,
        # start_ts=datetime.now(),
        # end_ts=datetime.now()):

        select_fields = {}

        for k, v in kwargs.items():
            # print(f'K:{k}, V:{v}')
            if v is not None:
                select_fields[k] = v

        print("-----------------")
        print(select_fields)
        print("-----------------")

        sql = "SELECT "
        for i, f in enumerate(select_fields.keys()):
            sql += f

            if i < len(select_fields) - 1:
                sql += ", "

        sql += " FROM packet "

        sql += f" WHERE timestamp between {int(start_ts.timestamp())} and {int(end_ts.timestamp())} "

        print(sql)

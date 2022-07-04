

class SqlStatement:

    def __init__(self):
        self.select = ""
        self.sfrom = ""
        self.where = ""
        self.limit = ""
        self.order = "ORDER BY"
        self.group_by = "GROUP BY"

    def build(self) -> str:
        return f"SELECT {self.select} FROM {self.sfrom} WHERE {self.where} LIMIT {self.limit};"

    def add_select(self, select):
        self.select += f" {select}"

    def add_from(self, sfrom):
        self.sfrom += f" {sfrom}"

    def add_where(self, where):
        self.where += f" {where}"

    def add_limit(self, limit):
        self.limit += f" {limit}"

    def __str__(self) -> str:
        return self.build()


if __name__ == "__main__":
    sql = SqlStatement()
    sql.add_select("*")
    sql.add_from("packet")
    sql.add_where("ip.dst == 3214566 AND ether.vlan == 91")
    sql.add_limit("10")
    print(sql.build())

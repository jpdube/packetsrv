from api.server2 import start
from pql.interp import interpret_program
from pql.pcapfile import PcapFile
from pql.parse import parse_source
from pql.interp_raw import interpret_program
from datetime import datetime


def search():
    model = parse_source(
        "select * from a where ip.src == 192.168.3.0/24 and tcp.syn == true;")
    # "select * from ip.src where (ip.src == 8.8.8.8 and ip.dst == 192.168.3.230) or (ip.src == 192.168.3.230 and ip.dst == 8.8.8.8);")
    print(model)

    start_time = datetime.now()
    for m in model:
        if m.where_expr is not None:
            interpret_program(m.where_expr, pcapfile="0")

    print(f"Time:{(datetime.now() - start_time).total_seconds()}")


if __name__ == "__main__":
    # pc = PcapFile()
    # pc.open(f"0")

    # count = 0
    # for p in pc.next():
    #     count += 1
    #     print(p)
    #     # print(p.print_hex())

    # print(count)
    # start()
    search()

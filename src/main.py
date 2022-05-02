from dbase.exec_query import exec_from_file
from dbase.read_packet import query
import sys

from dbase.exec_query import *
from dbase.packet_search import *
from datetime import datetime


if __name__ == "__main__":
    start_time = datetime.now()
    # for i in range(20):
    #     loop_time = datetime.now()
    #     pkt_list = packet_search(f"/Users/jpdube/hull-voip/db/pcap/{i}.pcap")
    #     print(f"Len: {len(pkt_list)}")
    #     print(f"File: {i}, Len: {len(pkt_list)} time: {datetime.now() - loop_time}")

    search_parallel()

    print(f"Execution time: {datetime.now() - start_time}")


    # exec_from_file("./pql_test/pql-new.pql")
    # query(sys.argv[1], sys.argv[2])

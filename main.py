from dbase.exec_query import exec_from_file
from dbase.read_packet import query
import sys

from dbase.exec_query import *


if __name__ == "__main__":
    exec_from_file("./pql_test/pql-02.pql")
    # query(sys.argv[1], sys.argv[2])

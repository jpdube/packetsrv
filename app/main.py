# from api.server import app
# import uvicorn
from config.config import Config
from dbase.dbengine import DBEngine
from pql.lexer import tokenize


def search():
    engine = DBEngine()
    # engine.index_db()
    for _ in range(1):
        _ = engine.run(
            """
                    select udp.sport,ip.dst, ip.src, udp.dport, pkt.timestamp, pkt.origlen
        from s1
         where udp.dport == 53 and (ip.dst == 192.168.2.230 and ip.src == 192.168.3.0/24)
        top 6000;
                    """)

    # lexer = Lexer(
    #     "0xa2:0xc3")
    # tokens = lexer.tokenize()
    # for t in tokens:
    #     print(t)
    # parse = Preparser(tokens)
    # parse.parse()
    # print(parse.token_list)

    # result = tokenize(
    #     """
    #                 select udp.sport,ip.dst, ip.src, udp.dport, frame.timestamp, frame.origlen
    #     from s1
    #      where udp.dport == 53 and (ip.dst == 192.168.2.230 and ip.src == 192.168.3.0/24)
    #     top 6000;
    #                 """)
    # # "2023-11-24 13:45:30 2024-12-10 23:45:35 192.168.3.128")
    # for r in result:
    #     print(r)


if __name__ == "__main__":
    Config.load()
    search()

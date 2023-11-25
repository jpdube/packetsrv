import psycopg2
import sqlite3

def convert():
    conn = psycopg2.connect(host='localhost', database='pcapdb', user='postgres', password='stileto99')

    cur = conn.cursor()
    cur.execute('select version()')
    db_version = cur.fetchone()
    print(db_version)

    sql_conn = sqlite3.connect('/Users/jpdube/hull-voip/db/index.db')
    cursor = sql_conn.cursor()

    cursor.execute('select * from packet;')
    # rows = cursor.fetchall()

    count = 0
    batch = 0
    sql = ""
    for r in cursor:
        sql += f"insert into packet (ip_src, ip_dst, mac_src, mac_dst, ether_type, ip_proto, vlan_id, sport, dport, file_ptr, file_id, timestamp) values ({r[1]},{r[2]},{r[3]},{r[4]},{r[5]},{r[6]},{r[7]},{r[8]},{r[9]},{r[10]},{r[11]},{r[12]});"
        if batch % 100 == 0:
            # print(sql)
            cur.execute(sql)
            count += 1
            sql = ""
            if count % 100 == 0:
                print('.', end='', flush=True)
                conn.commit()

    cur.close()
    conn.commit()


def create_pg_table():

    conn = psycopg2.connect(host='localhost', database='pcapdb', user='postgres', password='stileto99')

    cur = conn.cursor()
    cur.execute(
    """
    CREATE TABLE packet (
                id serial not null primary key,
                ip_src int8,
                ip_dst int8,
                mac_src int8,
                mac_dst int8,
                ether_type int4,
                ip_proto int4,
                vlan_id integer,
                sport integer,
                dport integer,
                file_ptr bigint,
                file_id bigint,
                timestamp int8);
    """
    )
    cur.close()
    conn.commit()

if __name__ == '__main__':
    create_pg_table()
    convert()

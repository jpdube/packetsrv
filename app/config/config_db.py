import sqlite3

from config.config import Config

import logging

log = logging.getLogger("packetdb")


class ConfigDB:

    def __init__(self):
        log.debug(f"Opening config database: {Config.config_dbase()}")
        self.conn = sqlite3.connect(Config.config_dbase())
        self.cursor = self.conn.cursor()
        # self.cursor.execute("SET ISOLATION TO SERIALIZABLE;")

    def drop_tables(self):
        self.cursor.execute("drop table if exists config;")
        self.cursor.execute("drop table if exists capture;")
        self.cursor.execute("drop table if exists user;")

    def check_tables(self):
        self.cursor.execute("""
                  create table if not exists config (
                      id integer primary key autoincrement,
                      name text, 
                      location text,
                      nbr_threads integer default 2,
                      database_path text,
                      packet_seq_no integer                   
                      );
                  """)
        self.cursor.execute("""
                  create table if not exists capture (
                      id integer primary key autoincrement,
                      name char(150) not null,
                      description text, 
                      iface char(40) not null,
                      state integer default 0 not null,
                      date_created datetime default current_timestamp,
                      folder text not null,            
                      filter text,
                      pcap_file_size integer default 2,
                      username text not null,
                      rotation integer default 7 not null,
                      created_by integer not null
                            
                      );
                  """)
        self.cursor.execute("""
                  create table if not exists user (
                      id integer primary key autoincrement,
                      username text,
                      description text, 
                      password text,
                      active boolean,
                      date_created datetime default current_timestamp,
                      created_by integer
                            
                      );
                  """)

    @property
    def node_name(self) -> str:
        name = ""
        self.cursor.execute("select name from config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            name = row[0][0]

        return name

    @property
    def node_location(self) -> str:
        location = ""
        self.cursor.execute("select location from config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            location = row[0][0]

        return location

    @property
    def node_info(self) -> dict[str, str | int]:
        node_info = {}
        self.cursor.execute(
            "select name, location, nbr_threads, database_path, packet_seq_no from config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            node_info["name"] = row[0][0]
            node_info["location"] = row[0][1]
            node_info["nbr_threads"] = row[0][2]
            node_info["database_path"] = row[0][3]
            node_info["packet_seq_no"] = row[0][4]

        return node_info

    @property
    def next_id(self) -> int:
        self.conn = sqlite3.connect(Config.config_dbase())
        self.cursor = self.conn.cursor()
        id = 0
        self.cursor.execute("select packet_seq_no from config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            log.warn(f"Got next id: {row[0][0]}")
            id = row[0][0]
            self.cursor.execute("begin transaction;")

            self.cursor.execute(
                "update config set packet_seq_no = ? where id = 1;", (id + 1,))
            self.cursor.execute("commit transaction;")
            self.conn.commit()

        return id

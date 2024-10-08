import logging
import sqlite3
from dataclasses import dataclass
from typing import Dict, Optional

from config.config import Config

log = logging.getLogger("packetdb")


class User:
    def __init__(self):
        self.conn = sqlite3.connect(Config.config_dbase())
        self.cursor = self.conn.cursor()
        self.username = ""
        self.password = ""
        self.active = False
        self.id = 0

    def create(self, username: str, password: str, description: str):
        sql = f"""
            insert into User (username, password, created_by, description, active) values ({username}, {password}, 1, {description}, True);
        """
        self.cursor.execute(sql)

    def get(self, username: str) -> bool:
        sql = f"select username, password, active, id from user where username = ?"
        row = self.cursor.execute(sql, (username, )).fetchone()
        if row:
            self.username = row[0]
            self.password = row[1]
            self.active = row[2]
            self.id = row[3]

            return True
        else:
            return False

    def check_user(self, username: str, password: str) -> bool:
        return True

    def __str__(self) -> str:
        return f"User: {self.username}, Active: {self.active}"


@dataclass
class CaptureProfile:
    id: int
    name: str
    description: str
    iface: str
    state: int
    date_created: int
    folder: str
    filter: str
    pcap_file_size: int
    username: str
    rotation: int
    created_by: int
    sequence_no: int


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
                      database_path text
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
                      created_by integer not null,
                      sequence_no integer not null
                            
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
            "select name, location, nbr_threads, database_path from config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            node_info["name"] = row[0][0]
            node_info["location"] = row[0][1]
            node_info["nbr_threads"] = row[0][2]
            node_info["database_path"] = row[0][3]

        return node_info

    # @property
    # def next_id(self) -> int:
    #     self.conn = sqlite3.connect(Config.config_dbase())
    #     self.cursor = self.conn.cursor()
    #     id = 0
    #     self.cursor.execute("select packet_seq_no from config limit 1;")
    #     row = self.cursor.fetchall()
    #     if len(row) == 1:
    #         log.warn(f"Got next id: {row[0][0]}")
    #         id = row[0][0]
    #         self.cursor.execute("begin transaction;")

    #         self.cursor.execute(
    #             "update config set packet_seq_no = ? where id = 1;", (id + 1,))
    #         self.cursor.execute("commit transaction;")
    #         self.conn.commit()

    #     return id

    def capture_profile(self, profile_id: int) -> CaptureProfile:
        self.cursor.execute("""
                            select
                            id,
                            name,
                            description, 
                            iface,
                            state,
                            date_create,
                            folder,            
                            filter,
                            pcap_file_size,
                            username,
                            rotation,
                            created_by,
                            sequence_no,
                            from capture where id = ?;
                            """, profile_id)

        row = self.cursor.fetchone()
        if len(row) == 1:
            log.warn(f"Got next id: {row[0][0]}")
            record = row[0]
            capture_profile = CaptureProfile(id=record[0],
                                             name=record[1],
                                             description=record[2],
                                             iface=record[3],
                                             state=record[4],
                                             date_created=record[5],
                                             folder=record[6],
                                             filter=record[7],
                                             pcap_file_size=record[8],
                                             username=record[9],
                                             rotation=record[10],
                                             created_by=record[11],
                                             sequence_no=record[12])

        return capture_profile

    def capture_next_id(self, profile_id) -> int:
        self.conn = sqlite3.connect(Config.config_dbase())
        self.cursor = self.conn.cursor()
        id = 0
        self.cursor.execute(
            "select sequence_no from capture where id = ?;", (profile_id, ))
        row = self.cursor.fetchall()
        if len(row) == 1:
            log.debug(f"Got next id: {row[0][0]} for profile: {profile_id}")
            id = row[0][0]
            self.cursor.execute("begin transaction;")

            self.cursor.execute(
                "update capture set sequence_no = ? where id = ?;", (id + 1, profile_id,))
            self.cursor.execute("commit transaction;")
            self.conn.commit()

        return id

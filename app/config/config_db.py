import sqlite3

from config.config import Config

import logging

log = logging.getLogger("packetdb")


class ConfigDB:

    def __init__(self):
        log.debug(f"Opening config database: {Config.config_dbase()}")
        self.conn = sqlite3.connect(Config.config_dbase())
        self.cursor = self.conn.cursor()

    def check_tables(self):
        self.cursor.execute("""
                  create table if not exists node_config (
                      id integer primary key autoincrement,
                      name text, 
                      location text 
                      );
                  """)
        self.cursor.execute("""
                  create table if not exists capture (
                      id integer primary key autoincrement,
                      name text,
                      description text, 
                      iface text,
                      state integer default 0,
                      date_created datetime default current_timestamp,
                      folder text,            
                      filter text,
                      created_by integer
                            
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
        self.cursor.execute("select name from node_config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            name = row[0][0]

        return name

    @property
    def node_location(self) -> str:
        location = ""
        self.cursor.execute("select location from node_config limit 1;")
        row = self.cursor.fetchall()
        if len(row) == 1:
            location = row[0][0]

        return location

    @property
    def node_info(self) -> dict[str, str | int]:
        node_info = {}
        node_info["name"] = self.node_name
        node_info["location"] = self.node_location

        return node_info

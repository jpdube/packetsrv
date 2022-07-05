import pprint

import tomllib


class Config:

    def __init__(self):
        import os
        print(os.getcwd())
        self.filename = "./config-jpd/server.toml"
        self.config = {}
        self.load(self.filename)

    def load(self, filename):
        self.filename = filename

        with open(filename, "rb") as f:
            self.config = tomllib.load(f)

        self.__set_fields()

        print("*** Config file ***")
        pprint.pprint(self.config)
        print("*** End of config file ***")

    def __set_fields(self):
        self.db_filename = self.config.get("db_filename", None)
        self.pcap_path = self.config.get("pcap_path", None)


config = Config()

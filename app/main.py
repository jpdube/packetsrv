import logging
import logging.config
import logging.handlers
import os
import platform
from signal import SIGINT, signal
from threading import Thread

from api.server import start
from config.config import Config
from config.config_db import ConfigDB
from rich.logging import RichHandler

from server.file_monitor import start_db_watcher

log_format = '%(threadName)s %(message)s'
logging.basicConfig(format=log_format, handlers=[RichHandler()])
log = logging.getLogger('packetdb')
log.setLevel(logging.DEBUG)


fh = logging.handlers.TimedRotatingFileHandler(
    'logs/packetdb.log', backupCount=10)

fh.setLevel(logging.INFO)
file_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

fh.setFormatter(file_format)
log.addHandler(fh)


def handler(signal_recv, frame):
    print("\n\n")
    log.info("Terminating program")
    os._exit(1)


if __name__ == "__main__":
    signal(SIGINT, handler)
    log.info(f"PCAP DB starting on plateform {platform.system()}")
    Config.load()
    configdb = ConfigDB()
    # configdb.drop_tables()
    configdb.check_tables()
    log.info(f"Node: {configdb.node_info} is online at {
             configdb.node_location}")

    start_db_watcher(Config.pcap_path(), 1)
    from dbase.dbengine import DBEngine

    api_thread = Thread(target=start, daemon=True)
    api_thread.start()
    api_thread.join()

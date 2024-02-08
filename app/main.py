from api.server import start
from config.config import Config
import logging
import logging.config
import logging.handlers
from rich.logging import RichHandler
from threading import Thread
import os
from signal import signal, SIGINT
from config.config_db import ConfigDB

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
    log.info("PCAP DB starting...")
    Config.load()
    configdb = ConfigDB()
    configdb.check_tables()
    log.info(f"Node: {configdb.node_name} is online at {
             configdb.node_location}")

    api_thread = Thread(target=start, daemon=True)
    api_thread.start()
    api_thread.join()

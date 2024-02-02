from api.server import start
from config.config import Config
from dbase.dbengine import DBEngine
import logging
import logging.config
import logging.handlers
from rich.logging import RichHandler
from threading import Thread


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

if __name__ == "__main__":
    log.info("PCAP DB starting...")
    Config.load()
    # db = DBEngine()

    api_thread = Thread(target=start, daemon=True)
    api_thread.start()
    api_thread.join()
    # start()

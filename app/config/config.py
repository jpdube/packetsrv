import os
from dotenv import load_dotenv
import multiprocessing as mp

import logging

log = logging.getLogger("packetdb")


class Config:
    config = None

    @classmethod
    def load(cls):
        load_dotenv()

    @classmethod
    def dbase_path(cls) -> str:
        return os.getenv('DBASE_PATH', '')

    @classmethod
    def config_path(cls) -> str:
        return os.getenv('CONFIG_PATH', '')

    @classmethod
    def config_dbase(cls) -> str:
        return f"{cls.config_path()}/config.db"

    @classmethod
    def pcap_path(cls) -> str:
        return os.getenv('PCAP_PATH', '')

    @classmethod
    def pcap_index(cls) -> str:
        return os.getenv('PCAP_INDEX', '')

    @classmethod
    def pcap_master_index(cls) -> str:
        return os.getenv('PCAP_MASTER_INDEX', '')

    @classmethod
    def nbr_threads(cls) -> int:
        nbr_threads = os.getenv('NBR_THREADS', mp.cpu_count())
        try:
            cpu_threads = int(nbr_threads)
        except ValueError:
            log.info(f"Invalid value for NBR_THREADS: {
                     nbr_threads} using default core count")
            cpu_threads = mp.cpu_count()

        if cpu_threads > mp.cpu_count():
            cpu_threads = mp.cpu_count()

        log.debug(f"Config nbr_cores: {cpu_threads}")
        return cpu_threads

    @classmethod
    def nbr_files_to_process(cls) -> int:
        nbr_files = os.getenv('NBR_FILES_TO_PROCESS')
        if nbr_files is not None:
            return int(nbr_files)
        else:
            return 2

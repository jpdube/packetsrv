import os
from dotenv import load_dotenv


class Config:
    config = None

    @classmethod
    def load(cls):
        load_dotenv()

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
    def nbr_files_to_process(cls) -> int:
        nbr_files = os.getenv('NBR_FILES_TO_PROCESS')
        if nbr_files is not None:
            return int(nbr_files)
        else:
            return 2

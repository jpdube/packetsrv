from config.config import Config
import io
import os


class FileManager:

    @classmethod
    def clean_indexes(cls):
        cls.__clean_folder(Config.pcap_index())
        cls.__clean_folder(Config.pcap_proto_index())

    @classmethod
    def __clean_folder(cls, folder_name):
        for filename in os.listdir(folder_name):
            file_path = os.path.join(folder_name, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(filename, "is removed")

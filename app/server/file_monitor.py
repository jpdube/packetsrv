import logging
import multiprocessing as mp
import os
import time

from config.config import Config
from config.config_db import ConfigDB
from pql.pcapfile import PcapFile
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("packetdb")

capture_queue = mp.Queue()


class _Handler(FileSystemEventHandler):

    def __init__(self, capture_queue):
        self.capture_queue = capture_queue

    def on_created(self, event):
        log.debug(f"on_created {event.src_path}")
        self.capture_queue.put(event.src_path)


class PacketDbWatch:
    def __init__(self, packet_dir: str):
        self.watchDirectory = packet_dir
        self.observer = Observer()

    def run(self, capture_queue: mp.Queue, watch_dir: str):
        event_handler = _Handler(capture_queue)
        self.observer.schedule(
            event_handler, watch_dir, recursive=False)
        self.observer.start()
        try:
            while True:
                time.sleep(0.5)
        except:
            self.observer.stop()
            log.info("Observer Stopped")

        self.observer.join()


def capture_thread(in_queue: mp.Queue, profile_id: int):
    configdb = ConfigDB()
    pool = mp.Pool()
    while True:
        flist = []
        new_file = in_queue.get()

        file_id = configdb.capture_next_id(profile_id)
        os.rename(new_file, f"{Config.pcap_path()}/{file_id}.pcap")
        flist.append(file_id)
        file_count = in_queue.qsize()

        for _ in range(file_count):
            new_file = in_queue.get()
            file_id = configdb.capture_next_id(profile_id)
            os.rename(new_file, f"{Config.pcap_path()}/{file_id}.pcap")
            flist.append(file_id)

        log.debug(f"File list: {flist}")
        pcapfile = PcapFile()
        result = pool.map(pcapfile.create_index, flist)
        result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result)


def start_db_watcher(watch_dir: str, profile_id: int):
    log.info(f"Database watcher started with folder: {watch_dir}")
    dbwatch = PacketDbWatch(watch_dir)
    mp.Process(target=capture_thread, args=(capture_queue, profile_id)).start()
    mp.Process(target=dbwatch.run, args=(
        capture_queue, watch_dir,), daemon=True).start()

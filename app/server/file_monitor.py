from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
from threading import Thread
from queue import Queue
from config.config_db import ConfigDB
from pql.pcapfile import PcapFile
import logging

log = logging.getLogger("packetdb")

capture_queue = Queue()


class _Handler(FileSystemEventHandler):

    def on_created(self, event):
        log.debug(f"on_created {event.src_path}")
        on_new_pcap(event.src_path)

    def on_deleted(self, event):
        log.debug(f"on_deleted {event.src_path}")

    # def on_modified(self, event):
    #     log.debug(f"on_modified {event.src_path}")

    def on_moved(self, event):
        log.debug(f"on_moved {event.src_path}")


class PacketDbWatch:

    def __init__(self, packet_dir: str):
        self.watchDirectory = packet_dir
        self.observer = Observer()

    def run(self):
        event_handler = _Handler()
        self.observer.schedule(
            event_handler, self.watchDirectory, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1.5)
        except:
            self.observer.stop()
            log.info("Observer Stopped")

        self.observer.join()


def capture_thread():
    configdb = ConfigDB()
    while True:
        pcap_file = capture_queue.get()
        file_id = configdb.next_id
        log.debug(f"Next file id: {file_id} -- Capture file: {pcap_file}")
        os.rename(pcap_file, f"/Users/jpdube/pcapdb/db/pcap/{file_id}.pcap")
        pcap = PcapFile()
        mx_idx = pcap.create_index(file_id)
        master_idx = []
        master_idx.append(mx_idx)
        pcap.build_master_index(master_idx)


def on_new_pcap(src_filename: str):
    capture_queue.put(src_filename)
    # os.rename()


def start_db_watcher(watch_dir: str):
    log.info(f"Database watcher started with folder: {watch_dir}")
    dbwatch = PacketDbWatch(watch_dir)
    Thread(target=capture_thread, daemon=True).start()
    Thread(target=dbwatch.run, daemon=True).start()


if __name__ == '__main__':
    watch = PacketDbWatch()
    watch.run()

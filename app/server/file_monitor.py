from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
from threading import Thread
import multiprocessing as mp
import glob

from config.config_db import ConfigDB
from pql.pcapfile import PcapFile
import logging


log = logging.getLogger("packetdb")

capture_queue = mp.Queue()


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
                time.sleep(0.5)
        except:
            self.observer.stop()
            log.info("Observer Stopped")

        self.observer.join()


def capture_thread(in_queue: mp.Queue):
    configdb = ConfigDB()
    pool = mp.Pool()
    while True:
        flist = []
        new_file = in_queue.get()
        file_id = configdb.next_id
        log.debug(f"Next file id: {file_id} -- Capture file: {new_file}")
        os.rename(new_file, f"/opt3/capture/pcap/{file_id}.pcap")
        flist.append(file_id)
        file_count = in_queue.qsize()
        for f in range(file_count):
            new_file = in_queue.get()
            file_id = configdb.next_id
            log.debug(f"Next file id: {file_id} -- Capture file: {new_file}")
            os.rename(new_file, f"/opt3/capture/pcap/{file_id}.pcap")
            flist.append(file_id)

        log.debug(f"File list: {flist}")
        pcapfile = PcapFile()
        result = pool.map(pcapfile.create_index, flist)
        result.sort(key=lambda a: a[0])
        pcapfile.build_master_index(result)


def on_new_pcap(src_filename: str):
    capture_queue.put(src_filename)


def start_db_watcher(watch_dir: str):
    log.info(f"Database watcher started with folder: {watch_dir}")
    dbwatch = PacketDbWatch(watch_dir)
    mp.Process(target=capture_thread, args=(capture_queue,)).start()
    Thread(target=dbwatch.run, daemon=True).start()


if __name__ == '__main__':
    watch = PacketDbWatch()
    watch.run()

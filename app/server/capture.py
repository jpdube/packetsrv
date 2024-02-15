
import os
import stat
from config.config_db import ConfigDB
from queue import Queue

import logging

log = logging.getLogger("packetdb")

"""
Create capture

Here are the steps needed to create a capture session

    Need to create:
        1- The capture folder
        2- Folder needed inside:
            pcap, index, mindex, capture
        3- Create the move script in capture folder
        4- Add info to database in the capture table
        5- Start the tcpdump command
        6- Save the PID if we need to stop the capture

"""


def create_capture(capture_path: str):
    create_folder(capture_path)
    create_move_script(f"{capture_path}/capture")


def create_folder(capture_path: str):
    path = os.path.join(capture_path, "pcap")
    os.mkdir(path, 0o700)
    log.info(f"Path created: {path}")

    path = os.path.join(capture_path, "index")
    os.mkdir(path, 0o700)
    log.info(f"Path created: {path}")

    path = os.path.join(capture_path, "mindex")
    os.mkdir(path, 0o700)
    log.info(f"Path created: {path}")

    path = os.path.join(capture_path, "capture")
    os.mkdir(path, 0o700)
    log.info(f"Path created: {path}")


def create_move_script(capture_path: str):
    script = """
    #!/bin/sh
    mv ./${1}"""

    script += f" {capture_path}\n"

    with open(f"{capture_path}/move.sh", "w") as f:
        f.write(script)

    os.chmod(f"{capture_path}/move.sh", stat.S_IXUSR |
             stat.S_IWUSR | stat.S_IRUSR)


if __name__ == "__main__":
    create_move_script("/Users/jpdube/packetdb_test")

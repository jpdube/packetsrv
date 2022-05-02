import subprocess
import os
import time
import signal
import psutil

class Sniffer:
    def __init__(self):
        ...

    def start(self, name: str, iface: str, username: str):
        output_dir = f"/home/jpdube/hull-voip/sniffer/{name}/"
        cmd = f"tcpdump -i {iface} -C 2 -W 5 -w {output_dir} -Z {username} -z {output_dir}move.sh"
        print(f"CMD: {cmd}")
        p = subprocess.Popen(cmd, shell=True)
        print(f"Sniffer {name} PID: {p.pid}")
        time.sleep(1)
        print(self.status(p.pid))

    def stop(self, name):
        pass

    def status(self, pid: int):
        process_status = [ proc for proc in psutil.process_iter() if proc.pid == pid ]
        if process_status:
            for current_process in process_status:
                return current_process.status()
        else:
           return None 


if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.start("trunk", "wlp0s20f3", "jpdube")

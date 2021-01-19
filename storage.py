from threading import Thread
from queue import Empty
from time import sleep


class Storage(Thread):
    def __init__(self, packets_queue):
        super().__init__()
        self.packets_queue = packets_queue
        self.connections = {}
        self._stop = False

    def run(self):
        self.package_extractor()

    def package_extractor(self):
        while not self._stop:
            try:
                packet = self.packets_queue.get()
                self.analyse_packet(packet)
            except Empty:
                sleep(0.01)

    def analyse_packet(self, packet):
        src_ip = packet["IP"].src
        if src_ip not in self.connections:
            self.connections[src_ip] = []

        self.connections[src_ip].append({
            "sport": packet["TCP"].sport,
            "dport": packet["TCP"].dport,
            "flags": str(packet["TCP"].flags)
        })

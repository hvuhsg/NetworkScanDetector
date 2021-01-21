from threading import Thread, Lock
from queue import Empty
from time import sleep
from tinydb import TinyDB
from loguru import logger

from utils import pkg_to_json


class Storage(Thread):
    def __init__(self, packets_queue):
        super().__init__()
        self.packets_queue = packets_queue
        self._stop = False
        self.db = TinyDB("data/db.json")
        self.packets = self.db.table("packets")
        self.db_lock = Lock()

    def run(self):
        self.package_extractor()

    def package_extractor(self):
        while not self._stop:
            try:
                packet = self.packets_queue.get()
                json_packet = pkg_to_json(packet)
                try:
                    with self.db_lock:
                        self.packets.insert(json_packet)
                except TypeError:
                    logger.debug(f"Can't insert json format {json_packet}")
            except Empty:
                sleep(0.01)

    def stop(self):
        logger.debug("Stoping storage manager.")
        self.db.close()
        self._stop = True

from threading import Thread, RLock
from queue import Empty
from time import sleep
from loguru import logger

from utils import pkg_to_json, get_db


class Storage(Thread):
    def __init__(self, packets_queue, **kwargs):
        super().__init__(**kwargs)
        self.packets_queue = packets_queue
        self.__stop = False
        self.db = get_db()
        self.packets = self.db.table("packets")
        self.db_lock = RLock()

    def run(self):
        self.package_extractor()

    def package_extractor(self):
        while not self.__stop:
            try:
                packet = self.packets_queue.get(timeout=5)
                json_packet = pkg_to_json(packet)
                try:
                    with self.db_lock:
                        self.packets.insert(json_packet)
                except TypeError:
                    logger.debug(f"Can't insert json format {json_packet}")
                except ValueError:
                    logger.debug("DB file is closed")
            except Empty:
                sleep(0.01)

    def stop(self):
        logger.debug("Stoping storage manager.")
        self.db.close()
        self.__stop = True

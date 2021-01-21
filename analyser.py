from time import sleep
from tinydb import Query
from loguru import logger

from storage import Storage


class Analyser:
    def __init__(self, storage: Storage):
        self.storage = storage
        self.__stop = False
        self.reported = []

    def analyse(self):
        logger.debug("Analysing traffic...")
        Packet = Query()
        with self.storage.db_lock:
            packets = self.storage.packets.search(Packet.TCP.flags == "S")

        ips = {}

        for packet in packets:
            src_ip = packet["IP"]["src"]
            if src_ip not in ips:
                ips[src_ip] = {}
                ips[src_ip]["ports"] = set()
            if packet["TCP"]["dport"] not in ips[src_ip]["ports"]:
                ips[src_ip]["ports"].add(packet["TCP"]["dport"])

        for ip, info in ips.items():
            if len(info["ports"]) >= 3:
                logger.success(f"PORT SCAN FROM {ip} {len(info['ports'])} PORTS SCANED")

    def run(self):
        logger.debug("Start analyser.")
        while not self.__stop:
            self.analyse()
            try:
                sleep(10)
            except KeyboardInterrupt:
                break

    def stop(self):
        logger.debug("Stoping analyser...")
        self.__stop = True

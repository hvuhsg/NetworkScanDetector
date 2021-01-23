from time import sleep, time
from tinydb import Query
from loguru import logger
from threading import Thread

from storage import Storage
from utils import get_db


class Analyser(Thread):
    def __init__(self, storage: Storage):
        super().__init__()
        self.storage = storage
        self.__stop = False
        self.reported = []
        self.ips = get_db().table("ips")

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
            if self.its_scanner(info):
                logger.success(f"PORT SCAN FROM {ip} {len(info['ports'])} PORTS SCANED")
                IP = Query()
                ip_info = self.ips.search(IP.ip == ip)
                if not ip_info:
                    self.ips.insert({"ip": ip, "scanner": True, "ports": info["ports"], "time": time()})
                elif ip_info["scanner"] is False:
                    self.ips.update({"scanner": True}, IP.ip == ip)

    def its_scanner(self, info):
        return len(info["ports"]) >= 3

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

from time import sleep

from storage import Storage
from tinydb import Query


class Analyser:
    def __init__(self, storage: Storage):
        self.storage = storage
        self._stop = False
        self.reported = []

    def analyse(self):
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
            if len(info["ports"]) >= 5:
                print("PORT SCAN FROM", ip, len(info["ports"]), "PORTS SCANED")

        # for client, packets in self.storage.connections.copy().items():
        #     port_syn = set()
        #     if client in self.reported:
        #         continue
        #     for packet in packets.copy():
        #         if ("S" in packet["flags"] and "A" not in packet["flags"]) and packet["dport"] not in port_syn:
        #             port_syn.add(packet["dport"])
        #     if len(port_syn) >= 5:
        #         print("PORT SCAN FROM", client, len(port_syn), "PORTS SCANED")
        #         self.reported.append(client)

    def run(self):
        while not self._stop:
            self.analyse()
            try:
                sleep(10)
            except KeyboardInterrupt:
                break

    def stop(self):
        self._stop = True

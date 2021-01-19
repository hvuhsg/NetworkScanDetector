from time import sleep

from storage import Storage


class Analyser:
    def __init__(self, storage: Storage):
        self.storage = storage
        self._stop = False
        self.reported = []

    def analyse(self):
        for client, packets in self.storage.connections.copy().items():
            port_syn = set()
            if client in self.reported:
                continue
            for packet in packets.copy():
                if "S" in packet["flags"] and packet["dport"] not in port_syn:
                    port_syn.add(packet["dport"])
            if len(port_syn) >= 5:
                print("PORT SCAN FROM", client, len(port_syn), "PORTS SCANED")
                self.reported.append(client)

    def run(self):
        while not self._stop:
            self.analyse()
            sleep(2)

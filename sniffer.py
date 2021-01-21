from queue import Queue
from threading import Thread
from loguru import logger
from scapy.all import sniff


class Sniffer(Thread):
    def __init__(self, packets_queue: Queue):
        super().__init__()
        self.packets = []
        self.packets_queue = packets_queue
        self.my_ip = None
        self._stop = False

    def setup(self):
        self.my_ip = self.find_my_ip()

    def find_my_ip(self):
        logger.debug("Finding local ip...")
        src = set()
        dst = set()
        while True:
            packets = sniff(count=10, filter="tcp")
            for packet in packets:
                if packet["IP"].src in dst:
                    return packet["IP"].src
                else:
                    src.add(packet["IP"].src)
                if packet["IP"].dst in src:
                    return packet["IP"].dst
                else:
                    dst.add(packet["IP"].dst)
            logger.debug("Round of finding ip do not work starting a new one")

    def run(self):
        self.setup()
        sniff(
            filter="tcp",
            prn=self.add_packet_to_queue,
            store=False,
            lfilter=self.is_incoming,
            stop_filter=lambda x: self._stop
        )

    def is_incoming(self, packet):
        return packet["IP"].dst == self.my_ip

    def add_packet_to_queue(self, packet):
        self.packets_queue.put(packet)

    def stop(self):
        logger.debug("Stoping sniffer...")
        self._stop = True


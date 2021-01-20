from queue import Queue
from threading import Thread
from scapy.all import sniff


class Sniffer(Thread):
    def __init__(self, packets_queue: Queue):
        super().__init__()
        self.packets = []
        self.packets_queue = packets_queue
        self._stop = False

    def run(self):
        sniff(
            filter="tcp",
            prn=self.add_packet_to_queue,
            store=False,
            lfilter=self.is_incoming,
            stop_filter=lambda x: self._stop
        )

    def is_incoming(self, packet):
        return packet["IP"].dst in ("10.128.0.3", "192.168.1.101")

    def add_packet_to_queue(self, packet):
        self.packets_queue.put(packet)

    def stop(self):
        self._stop = True


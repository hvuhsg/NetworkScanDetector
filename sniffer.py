from queue import Queue
from threading import Thread
from scapy.all import sniff


class Sniffer(Thread):
    def __init__(self, packets_queue: Queue):
        super().__init__()
        self.packets = []
        self.packets_queue = packets_queue

    def run(self):
        sniff(filter="tcp", prn=self.add_packet_to_queue, store=False, lfilter=self.is_incoming)

    def is_incoming(self, packet):
        return packet["IP"].dst in ("10.128.0.3", )

    def add_packet_to_queue(self, packet):
        # print(packet.summary())
        # print(packet["IP"].src, "-->", packet["IP"].dst)
        self.packets_queue.put(packet)


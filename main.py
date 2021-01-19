from queue import Queue

from analyser import Analyser
from storage import Storage
from sniffer import Sniffer


def main():
    q = Queue()
    sniffer = Sniffer(q)
    storage = Storage(q)
    analyser = Analyser(storage)

    sniffer.start()
    storage.start()
    analyser.run()

main()
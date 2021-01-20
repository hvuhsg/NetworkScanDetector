from queue import Queue
from threading import enumerate, current_thread

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

    analyser.stop()
    storage.stop()
    sniffer.stop()

    for thread in enumerate():
        if thread is not current_thread():
            thread.join()
    print("Closing...")

main()

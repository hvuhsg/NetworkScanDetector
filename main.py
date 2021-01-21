from queue import Queue
from threading import enumerate, current_thread
from loguru import logger

from analyser import Analyser
from storage import Storage
from sniffer import Sniffer


def main():
    q = Queue()
    sniffer = Sniffer(q)
    storage = Storage(q)
    analyser = Analyser(storage)

    logger.info("Starting sniffer")
    sniffer.start()
    logger.info("Starting storage")
    storage.start()
    logger.info("Starting analyser")
    analyser.run()

    analyser.stop()
    storage.stop()
    sniffer.stop()

    for thread in enumerate():
        if thread is not current_thread():
            thread.join()
    logger.info("Closing completed")

main()

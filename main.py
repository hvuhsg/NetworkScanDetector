from threading import enumerate, current_thread
from queue import Queue

from api import app
from storage import Storage
from sniffer import Sniffer
from analyser import Analyser
from loguru import logger


@app.on_event("shutdown")
async def shutdown_event():
    for thread in enumerate():
        if thread is not current_thread():
            thread.stop()  # I added stop function to every thread in the code (Custom thread class)
            thread.join()


@app.on_event("startup")
async def startup_event():
    q = Queue()
    sniffer = Sniffer(q, name="sniffer")
    storage = Storage(q, name="storage")
    analyser = Analyser(storage, name="analyser")

    logger.info("Starting sniffer")
    sniffer.start()
    logger.info("Starting storage")
    storage.start()
    logger.info("Starting analyser")
    analyser.start()

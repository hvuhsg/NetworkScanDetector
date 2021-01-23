from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from tinydb import TinyDB

from utils import get_db

app = FastAPI()


origins = [
    "*" # TODO - change to real origins
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_LIMIT = 50


@app.get("/scanners")
async def get_scanners(limit: int = 10, offset: int = 0, db: TinyDB=Depends(get_db)):
    limit = min(MAX_LIMIT, limit)
    all_scanners = db.table("ips").all()
    try:
        return all_scanners[offset:offset+limit]
    except IndexError:
        return all_scanners

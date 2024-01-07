from api.server import start
from config.config import Config
from dbase.dbengine import DBEngine

if __name__ == "__main__":
    Config.load()
    db = DBEngine()
    # db.index_db()
    start()

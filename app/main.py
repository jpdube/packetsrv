from api.server import start
from config.config import Config

if __name__ == "__main__":
    Config.load()
    start()

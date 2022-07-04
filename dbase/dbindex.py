
from dbengine import Index


class DbIndex:
    index = Index()

    @classmethod
    def init(cls):
        cls.index.init()

    @classmethod
    def save(cls, sql):
        cls.index.save(sql)

    @classmethod
    def count(cls) -> int:
        return cls.index.count()

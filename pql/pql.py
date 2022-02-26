from pql.parse import *


class Result:
    ...


class Pql:
    def __init__(self) -> None:
        pass

    def load(self, filename: str) -> bool:
        return False

    def execute(self) -> Result | None:
        return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: wabbit.parse filename")
    model = parse_file(sys.argv[1])
    print(model)

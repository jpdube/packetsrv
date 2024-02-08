from enum import Enum, auto


class Tokens(Enum):

    def __eq__(self, other) -> bool:
        try:
            return self.value == other.value
        except AttributeError:
            return False

    def __str__(self) -> str:
        return self.name

    TOK_SELECT = auto()
    TOK_FROM = auto()
    TOK_INCLUDE = auto()
    TOK_WHERE = auto()
    TOK_ORDER_BY = auto()
    TOK_GROUP_BY = auto()
    TOK_BY = auto()
    TOK_ASC = auto()
    TOK_DESC = auto()
    TOK_BETWEEN = auto()
    TOK_TOP = auto()
    TOK_OFFSET = auto()
    TOK_LIMIT = auto()
    TOK_IN = auto()
    TOK_LAND = auto()
    TOK_LOR = auto()
    TOK_NOW = auto()
    TOK_VAR = auto()
    TOK_CONST = auto()
    TOK_EOL = auto()
    TOK_EOF = auto()
    TOK_FILTER = auto()
    TOK_OUTPUT = auto()
    TOK_TO = auto()
    TOK_INTERVAL = auto()
    TOK_TIMESTAMP = auto()
    TOK_TIME = auto()
    TOK_AVERAGE = auto()
    TOK_SUM = auto()
    TOK_MAX = auto()
    TOK_MIN = auto()
    TOK_COUNT = auto()
    TOK_AS = auto()
    TOK_BANDWIDTH = auto()

    # --- Types
    TOK_INTEGER = auto()
    TOK_FLOAT = auto()
    TOK_IPV4 = auto()
    TOK_MAC = auto()
    TOK_DATE = auto()
    TOK_STRING = auto()
    TOK_CHAR = auto()
    TOK_NAME = auto()
    TOK_LABEL = auto()
    TOK_TRUE = auto()
    TOK_FALSE = auto()
    TOK_ARRAY = auto()

    # --- One character keywords
    TOK_ASSIGN = auto()
    TOK_MASK = auto()
    TOK_WILDCARD = auto()
    TOK_TIMES = auto()
    TOK_SEMI = auto()
    TOK_DELIMITER = auto()
    TOK_GT = auto()
    TOK_LT = auto()
    TOK_LBRACE = auto()
    TOK_RBRACE = auto()
    TOK_PLUS = auto()
    TOK_MINUS = auto()
    TOK_LPAREN = auto()
    TOK_RPAREN = auto()
    TOK_LNOT = auto()
    TOK_INDEX_START = auto()
    TOK_INDEX_END = auto()
    TOK_SINGLE_QUOTE = auto()
    TOK_COLON = auto()
    TOK_PERIOD = auto()

    # --- Two character keywords
    TOK_EQ = auto()
    TOK_LE = auto()
    TOK_GE = auto()
    TOK_NE = auto()

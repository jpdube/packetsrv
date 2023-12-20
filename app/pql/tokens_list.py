from tools.itoa import itoa

TOK_SELECT = itoa(reset=True)
TOK_FROM = itoa()
TOK_INCLUDE = itoa()
TOK_WHERE = itoa()
TOK_ORDER_BY = itoa()
TOK_GROUP_BY = itoa()
TOK_ASC = itoa()
TOK_DESC = itoa()
TOK_BETWEEN = itoa()
TOK_TOP = itoa()
TOK_LIMIT = itoa()
TOK_IN = itoa()
TOK_LAND = itoa()
TOK_LOR = itoa()
TOK_NOW = itoa()
TOK_VAR = itoa()
TOK_CONST = itoa()
TOK_EOL = itoa()
TOK_EOF = itoa()
TOK_FILTER = itoa()
TOK_OUTPUT = itoa()
TOK_TO = itoa()
TOK_INTERVAL = itoa()
TOK_TIMESTAMP = itoa()
TOK_TIME = itoa()
TOK_AVERAGE = itoa()
TOK_SUM = itoa()
TOK_MAX = itoa()
TOK_MIN = itoa()
TOK_COUNT = itoa()
TOK_AS = itoa()


#--- Types
TOK_INTEGER = itoa()
TOK_FLOAT = itoa()
TOK_IPV4 = itoa()
TOK_MAC = itoa()
TOK_DATE = itoa()
TOK_STRING = itoa()
TOK_CHAR = itoa()
TOK_NAME = itoa()
TOK_LABEL = itoa()
TOK_TRUE = itoa()
TOK_FALSE = itoa()
TOK_ARRAY = itoa()

# --- One character keywords
TOK_ASSIGN = itoa()
TOK_MASK = itoa()
TOK_WILDCARD = itoa()
TOK_TIMES = itoa()
TOK_SEMI = itoa()
TOK_DELIMITER = itoa()
TOK_GT = itoa()
TOK_LT = itoa()
TOK_LBRACE = itoa()
TOK_RBRACE = itoa()
TOK_PLUS = itoa()
TOK_MINUS = itoa()
TOK_LPAREN = itoa()
TOK_RPAREN = itoa()
TOK_LNOT = itoa()
TOK_INDEX_START = itoa()
TOK_INDEX_END = itoa()
TOK_SINGLE_QUOTE = itoa()
TOK_COLON = itoa()
TOK_PERIOD = itoa()

# --- Two character keywords
TOK_EQ = itoa()
TOK_LE = itoa()
TOK_GE = itoa()
TOK_NE = itoa()


text_token = {
    TOK_SELECT: "SELECT",
    TOK_FROM: "FROM",
    TOK_WHERE: "WHERE",
    TOK_ORDER_BY: "ORDER BY",
    TOK_GROUP_BY: "GROUP BY",
    TOK_ASC: "ASC",
    TOK_DESC: "DESC",
    TOK_BETWEEN: "BETWEEN",
    TOK_TOP: "TOP",
    TOK_LAND: "LAND",
    TOK_LOR: "LOR",
    TOK_NOW: "NOW",
    TOK_CONST: "CONST",
    TOK_EOL: "EOL",
    TOK_EOF: "EOF",
    TOK_OUTPUT: "OUTPUT",
    TOK_TO: "TO",
    TOK_INTEGER: "INTEGER",
    TOK_FLOAT: "FLOAT",
    TOK_IPV4: "IPV4",
    TOK_MASK: "MASK",
    TOK_MAC: "MAC",
    TOK_DATE: "DATE",
    TOK_STRING: "STRING",
    TOK_CHAR: "CHAR",
    TOK_LABEL: "LABEL",
    TOK_NAME: "NAME",
    TOK_TRUE: "TRUE",
    TOK_FALSE: "FALSE",
    TOK_TIMES: "MUL",
    TOK_WILDCARD: "WILDCARD",
    TOK_SEMI: "SEMI",
    TOK_DELIMITER: "DELIM",
    TOK_GT: "GT",
    TOK_LT: "LT",
    TOK_PLUS: "PLUS",
    TOK_MINUS: "MINUS",
    TOK_LPAREN: "LPAREN",
    TOK_RPAREN: "RPAREN",
    TOK_LNOT: "LNOT",
    TOK_EQ: "EQ",
    TOK_LE: "LE",
    TOK_GE: "GE",
    TOK_NE: "NE",
    TOK_INDEX_START: "INDEX START",
    TOK_INDEX_END: "INDEX END",
    TOK_COLON: "COLON",
    TOK_PERIOD: "PERIOD",
    TOK_TIMESTAMP: "TIMESTAMP",
    TOK_TIME: "TIME",
    TOK_ARRAY: "ARRAY",
    TOK_AVERAGE: "AVERAGE",
    TOK_SUM: "SUM",
    TOK_MIN: "MIN",
    TOK_MAX: "MAX",
    TOK_COUNT: "COUNT",
    TOK_AS: "AS",
}


def human_tokens(token: int) -> str:
    return text_token.get(token, "UNDEFINED")

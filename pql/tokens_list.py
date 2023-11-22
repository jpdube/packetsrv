TOK_SELECT = 0x00
TOK_FROM = 0x01
TOK_INCLUDE = 0x02
TOK_WHERE = 0x03
TOK_ORDER_BY = 0x04
TOK_GROUP_BY = 0x05
TOK_ASC = 0x06
TOK_DESC = 0x07
TOK_BETWEEN = 0x08
TOK_TOP = 0x09
TOK_LIMIT = 0x0a
TOK_IN = 0x0b
TOK_LAND = 0x0c
TOK_LOR = 0x0d
TOK_NOW = 0x0e
TOK_VAR = 0x0f
TOK_CONST = 0x10
TOK_EOL = 0x11
TOK_EOF = 0x12
TOK_FILTER = 0x13
TOK_OUTPUT = 0x14
TOK_TO = 0x15
TOK_INTERVAL = 0x16

#--- Types
TOK_INTEGER = 0x100
TOK_FLOAT = 0x101
TOK_IPV4 = 0x102
TOK_MAC = 0x103
TOK_DATE = 0x104
TOK_STRING = 0x105
TOK_CHAR = 0x106
TOK_NAME = 0x107
TOK_LABEL = 0x108
TOK_TRUE = 0x109
TOK_FALSE = 0x10a

# --- One character keywords
TOK_ASSIGN = 0x200
TOK_MASK = 0x201
TOK_WILDCARD = 0x203
TOK_TIMES = 0x204
TOK_SEMI = 0x205
TOK_DELIMITER = 0x026
TOK_GT = 0x207
TOK_LT = 0x208
TOK_LBRACE = 0x209
TOK_RBRACE = 0x20a
TOK_PLUS = 0x20b
TOK_MINUS = 0x20c
TOK_LPAREN = 0x20d
TOK_RPAREN = 0x20e
TOK_LNOT = 0x20f

# --- Two character keywords
TOK_EQ = 0x300
TOK_LE = 0x301
TOK_GE = 0x302
TOK_NE = 0x303


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
}


def human_tokens(token: int) -> str:
    return text_token.get(token, "UNDEFINED")

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

CONST_IP_TOS_NET_CTRL = 0b111
CONST_IP_TOS_INTNET_CTRL = 0b110
CONST_IP_TOS_CRITIC_ECP = 0b101
CONST_IP_TOS_FLASH_OVERRIDE = 0b100
CONST_IP_TOS_FLASH = 0b011
CONST_IP_TOS_IMMEDIATE = 0b010
CONST_IP_TOS_PRIORITY = 0b001
CONST_IP_TOS_ROUTINE = 0b000

CONST_IP_TOS_MIN_DELAY = 0b00010000
CONST_IP_TOS_MAX_THROUGHPUT = 0b00001000
CONST_IP_TOS_MAX_RELIABILITY = 0b00000100
CONST_IP_TOS_MIN_COST = 0b00000010
CONST_IP_TOS_NORMAL = 0b00000000
CONST_IP_TOS_EF = 0xb8


def const_value(const: str) -> int:
    if const == "IP_TOS_NET_CTRL":
        return CONST_IP_TOS_NET_CTRL
    elif const == "IP_TOS_INTNET_CTRL":
        return CONST_IP_TOS_INTNET_CTRL
    elif const == "IP_TOS_CRITIC_ECP":
        return CONST_IP_TOS_CRITIC_ECP
    elif const == "IP_TOS_FLASH_OVERRIDE":
        return CONST_IP_TOS_FLASH_OVERRIDE
    elif const == "IP_TOS_FLASH":
        return CONST_IP_TOS_FLASH
    elif const == "IP_TOS_IMMEDIATE":
        return CONST_IP_TOS_IMMEDIATE
    elif const == "IP_TOS_PRIORITY":
        return CONST_IP_TOS_PRIORITY
    elif const == "IP_TOS_ROUTINE":
        return CONST_IP_TOS_ROUTINE
    elif const == "IP_TOS_MIN_DELAY":
        return CONST_IP_TOS_MIN_DELAY
    elif const == "IP_TOS_MAX_THROUGHPUT":
        return CONST_IP_TOS_MAX_THROUGHPUT
    elif const == "IP_TOS_MAX_RELIABILITY":
        return CONST_IP_TOS_MAX_RELIABILITY
    elif const == "IP_TOS_MIN_COST":
        return CONST_IP_TOS_MIN_COST
    elif const == "IP_TOS_MIN_NORMAL":
        return CONST_IP_TOS_NORMAL
    elif const == "IP_TOS_EF":
        return CONST_IP_TOS_EF
    else:
        return 0


def human_tokens(token: int) -> str:
    if token == TOK_SELECT:
        return "SELECT"
    elif token == TOK_FROM:
        return "FROM"
    elif token == TOK_WHERE:
        return "WHERE"
    elif token == TOK_ORDER_BY:
        return "ORDER BY"
    elif token == TOK_GROUP_BY:
        return "GROUP BY"
    elif token == TOK_ASC:
        return "ASC"
    elif token == TOK_DESC:
        return "DESC"
    elif token == TOK_BETWEEN:
        return "BETWEEN"
    elif token == TOK_TOP:
        return "TOP"
    elif token == TOK_LAND:
        return "LAND"
    elif token == TOK_LOR:
        return "LOR"
    elif token == TOK_NOW:
        return "NOW"
    elif token == TOK_CONST:
        return "CONST"
    elif token == TOK_EOL:
        return "EOL"
    elif token == TOK_EOF:
        return "EOF"
    elif token == TOK_OUTPUT:
        return "OUTPUT"
    elif token == TOK_TO:
        return "TO"
    elif token == TOK_INTEGER:
        return "INTEGER"
    elif token == TOK_FLOAT:
        return "FLOAT"
    elif token == TOK_IPV4:
        return "IPV4"
    elif token == TOK_MASK:
        return "MASK"
    elif token == TOK_MAC:
        return "MAC"
    elif token == TOK_DATE:
        return "DATE"
    elif token == TOK_STRING:
        return "STRING"
    elif token == TOK_CHAR:
        return "CHAR"
    elif token == TOK_LABEL:
        return "LABEL"
    elif token == TOK_NAME:
        return "NAME"
    elif token == TOK_TRUE:
        return "TRUE"
    elif token == TOK_FALSE:
        return "FALSE"
    elif token == TOK_TIMES:
        return "MUL"
    elif token == TOK_WILDCARD:
        return "WILDCARD"
    elif token == TOK_SEMI:
        return "SEMI"
    elif token == TOK_DELIMITER:
        return "DELIM"
    elif token == TOK_GT:
        return "GT"
    elif token == TOK_LT:
        return "LT"
    elif token == TOK_PLUS:
        return "PLUS"
    elif token == TOK_MINUS:
        return "MINUS"
    elif token == TOK_LPAREN:
        return "LPAREN"
    elif token == TOK_RPAREN:
        return "RPAREN"
    elif token == TOK_LNOT:
        return "LNOT"
    elif token == TOK_EQ:
        return "EQ"
    elif token == TOK_LE:
        return "LE"
    elif token == TOK_GE:
        return "GE"
    elif token == TOK_NE:
        return "NE"
    elif token == CONST_IP_TOS_NET_CTRL:
        return "IP_TOS_NET_CTRL"
    elif token == CONST_IP_TOS_INTNET_CTRL:
        return "IP_TOS_INNET_CTRL"
    elif token == CONST_IP_TOS_CRITIC_ECP:
        return "IP_TOS_CRITIC_ECP"
    elif token == CONST_IP_TOS_FLASH_OVERRIDE:
        return "IP_TOS_FLASH_OVERRIDE"
    elif token == CONST_IP_TOS_FLASH:
        return "IP_TOS_FLASH"
    elif token == CONST_IP_TOS_IMMEDIATE:
        return "IP_TOS_IMMEDIATE"
    elif token == CONST_IP_TOS_PRIORITY:
        return "IP_TOS_PRIORITY"
    elif token == CONST_IP_TOS_ROUTINE:
        return "IP_TOS_ROUTINE"
    else:
        return "UNDEFINED"

import re

from pql.constant import *
from pql.tokens_list import *

# from pql.tokens_list import Tok

_keywords = {
    "select": TOK_SELECT,
    "from": TOK_FROM,
    "include": TOK_INCLUDE,
    "where": TOK_WHERE,
    "order by": TOK_ORDER_BY,
    "asc": TOK_ASC,
    "desc": TOK_DESC,
    "between": TOK_BETWEEN,
    "groupby": TOK_GROUP_BY,
    "top": TOK_TOP,
    "limit": TOK_LIMIT,
    "in": TOK_IN,
    "and": TOK_LAND,
    "or": TOK_LOR,
    "now": TOK_NOW,
    "filter": TOK_FILTER,
    "output": TOK_OUTPUT,
    "to": TOK_TO,
    "true": TOK_TRUE,
    "false": TOK_FALSE,
    "interval": TOK_INTERVAL,
}

constants = {
    "IP_TOS_NET_CTRL": CONST_IP_TOS_NET_CTRL,
    "IP_TOS_INTNET_CTRL": CONST_IP_TOS_INTNET_CTRL,
    "IP_TOS_CRITIC_ECP": CONST_IP_TOS_CRITIC_ECP,
    "IP_TOS_FLASH_OVERRIDE": CONST_IP_TOS_FLASH_OVERRIDE,
    "IP_TOS_FLASH": CONST_IP_TOS_FLASH,
    "IP_TOS_IMMEDIATE": CONST_IP_TOS_IMMEDIATE,
    "IP_TOS_PRIORITY": CONST_IP_TOS_PRIORITY,
    "IP_TOS_ROUTINE": CONST_IP_TOS_ROUTINE,
    "IP_TOS_EF": CONST_IP_TOS_EF,
    "IP_PROTO_ICMP": 0x01,
    "IP_PROTO_TCP": 0x06,
    "IP_PROTO_UDP": 0x11,
    "ETH_PROTO_IPV4": 0x0800,
    "ETH_PROTO_IPV6": 0x86dd,
    "ETH_PROTO_ARP": 0x0806,
    "HTTPS": 443,
    "DNS": 53
}

_token1 = {
    "/": TOK_MASK,
    "*": TOK_WILDCARD,
    ";": TOK_SEMI,
    ",": TOK_DELIMITER,
    ">": TOK_GT,
    "<": TOK_LT,
    "{": TOK_LBRACE,
    "}": TOK_RBRACE,
    "+": TOK_PLUS,
    "-": TOK_MINUS,
    "(": TOK_LPAREN,
    ")": TOK_RPAREN,
}

_token2 = {
    "==": TOK_EQ,
    "<=": TOK_LE,
    ">=": TOK_GE,
    "!=": TOK_NE,
}

_token_comment = {"//", "/*", "*/"}


class Token:
    def __init__(self, type: int, value: str, line: int, col: int):
        # def __init__(self, type: Tok, value: str, line: int, col: int):
        self.type = type
        # self.type: Tok = type
        self.value: str = value
        self.line: int = line
        self.col: int = col

    def __repr__(self):
        return f"({self.type:x}:{human_tokens(self.type)}, {self.value}, {self.line}, {self.col})"


class Lexer:
    def __init__(self, text):
        assert len(text) > 0
        self.text = text
        self.text_len = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1

    def tokenize(self):
        self.pos = 0
        token = None

        while self.pos < self.text_len:
            if self.text[self.pos].isspace():
                if self.text[self.pos] == "\n":
                    self.line += 1
                    self.col = 0

                self.pos += 1
                self.col += 1
                continue

            # --- Comments
            elif self.text[self.pos: self.pos + 1] == "#":
                eol = self.text.find("\n", self.pos + 1)
                if eol > 0:
                    self.pos = eol + 1
                else:
                    self.pos = len(self.text)
                continue

            # --- Timespan
            elif self.is_timespan():
                print(f'TIMESPAN FOUND')

            # --- String
            elif self.is_string():
                token = self.read_string()

            # --- Token 2 characters
            elif self.text[self.pos: self.pos + 2] in _token2:
                token = Token(
                    _token2[self.text[self.pos: self.pos + 2]],
                    self.text[self.pos: self.pos + 2],
                    self.line,
                    self.col,
                )
                self.pos += 2
                self.col += 2

            # --- Date
            elif self.is_date():
                token = self.read_date()

            # --- Token 1 characters
            elif self.text[self.pos] in _token1:
                token = Token(
                    _token1[self.text[self.pos]],
                    self.text[self.pos],
                    self.line,
                    self.col,
                )
                self.pos += 1
                self.col += 1

            # --- Mac
            elif self.is_mac_addr():
                token = self.read_mac()

            # --- Int, float, ipv4
            elif self.is_digit(self.text[self.pos]):
                token = self.read_digit()

            # --- Alpha numeric
            elif self.is_alpha(self.text[self.pos]):
                token = self.read_alpha()
            else:
                self.pos += 1
                self.col += 1

            yield (token)

        # --- End of file parsing
        yield (Token(TOK_EOF, "EOF", self.line, self.col))

    def is_digit(self, c: str) -> bool:
        return c.isdigit() or c == '.' or c == ':'

    def read_digit(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_digit(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start: self.pos]
        if value.count(".") == 3:
            token = Token(TOK_IPV4, value, self.line, self.col)
        elif "." in value:
            token = Token(TOK_FLOAT, value, self.line, self.col)
        else:
            token = Token(TOK_INTEGER, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_alpha(self, c: str) -> bool:
        return c.isalnum() or c == "_" or c == "."

    def read_alpha(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_alpha(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start: self.pos]
        if value in _keywords:
            token = Token(_keywords[value], value, self.line, self.col)
        elif value in constants:
            token = Token(TOK_CONST, value, self.line, self.col)
        else:
            token = Token(TOK_NAME, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_mac_addr(self) -> bool:
        return (self.pos + 16) < self.text_len and self.text[self.pos:self.pos + 16].count(":") == 5

    def read_mac(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and (self.text[self.pos].isalnum() or self.text[self.pos] == ":"):
            self.pos += 1

        value = self.text[tok_start: self.pos]
        self.col += self.pos - (self.pos - len(value))
        return Token(TOK_MAC, value, self.line, self.col)

    def is_string(self) -> bool:
        return self.text[self.pos] == "'"

    def read_string(self) -> Token:
        tok_start = self.pos
        self.pos += 1
        while self.pos < self.text_len and self.text[self.pos] != "'":
            self.pos += 1
        value = self.text[tok_start + 1: self.pos]
        token = Token(TOK_STRING, value, self.line, self.col)
        self.pos += 1
        self.col += self.pos - (self.pos - len(value))

        return token

    def is_date(self) -> bool:
        if (self.pos + 19) <= self.text_len:
            result = re.search(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d",
                               self.text[self.pos: self.pos + 19])
            if result:
                return True
        return False

    def read_date(self) -> Token:
        value = self.text[self.pos: self.pos + 19]
        token = Token(TOK_DATE, value, self.line, self.col)
        self.pos += 19
        self.col += self.pos - (self.pos - len(value))
        return token

    def is_timespan(self) -> bool:
        return False

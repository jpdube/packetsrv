import pql.constant as const
import pql.tokens_list as tl

_keywords = {
    "select": tl.TOK_SELECT,
    "from": tl.TOK_FROM,
    "include": tl.TOK_INCLUDE,
    "where": tl.TOK_WHERE,
    "order by": tl.TOK_ORDER_BY,
    "asc": tl.TOK_ASC,
    "desc": tl.TOK_DESC,
    "between": tl.TOK_BETWEEN,
    "groupby": tl.TOK_GROUP_BY,
    "top": tl.TOK_TOP,
    "limit": tl.TOK_LIMIT,
    "in": tl.TOK_IN,
    "and": tl.TOK_LAND,
    "or": tl.TOK_LOR,
    "now": tl.TOK_NOW,
    "filter": tl.TOK_FILTER,
    "output": tl.TOK_OUTPUT,
    "to": tl.TOK_TO,
    "true": tl.TOK_TRUE,
    "false": tl.TOK_FALSE,
    "interval": tl.TOK_INTERVAL,
    "avg": tl.TOK_AVERAGE,
    "sum": tl.TOK_SUM,
    "min": tl.TOK_MIN,
    "max": tl.TOK_MAX,
    "count": tl.TOK_COUNT,
}


constants = {
    "IP_TOS_NET_CTRL": const.CONST_IP_TOS_NET_CTRL,
    "IP_TOS_INTNET_CTRL": const.CONST_IP_TOS_INTNET_CTRL,
    "IP_TOS_CRITIC_ECP": const.CONST_IP_TOS_CRITIC_ECP,
    "IP_TOS_FLASH_OVERRIDE": const.CONST_IP_TOS_FLASH_OVERRIDE,
    "IP_TOS_FLASH": const.CONST_IP_TOS_FLASH,
    "IP_TOS_IMMEDIATE": const.CONST_IP_TOS_IMMEDIATE,
    "IP_TOS_PRIORITY": const.CONST_IP_TOS_PRIORITY,
    "IP_TOS_ROUTINE": const.CONST_IP_TOS_ROUTINE,
    "IP_TOS_EF": const.CONST_IP_TOS_EF,
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
    "/": tl.TOK_MASK,
    "*": tl.TOK_WILDCARD,
    ";": tl.TOK_SEMI,
    ",": tl.TOK_DELIMITER,
    ">": tl.TOK_GT,
    "<": tl.TOK_LT,
    "{": tl.TOK_LBRACE,
    "}": tl.TOK_RBRACE,
    "+": tl.TOK_PLUS,
    "-": tl.TOK_MINUS,
    "(": tl.TOK_LPAREN,
    ")": tl.TOK_RPAREN,
    "[": tl.TOK_INDEX_START,
    "]": tl.TOK_INDEX_END,
    ":": tl.TOK_COLON,
    "'": tl.TOK_SINGLE_QUOTE,
    ".": tl.TOK_PERIOD,
}

_token2 = {
    "==": tl.TOK_EQ,
    "<=": tl.TOK_LE,
    ">=": tl.TOK_GE,
    "!=": tl.TOK_NE,
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
        return f"({self.type:x}:{tl.human_tokens(self.type)}, {self.value}, {self.line}, {self.col})"


class Lexer:
    def __init__(self, text):
        assert len(text) > 0
        self.text = text
        self.text_len = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1
        self.token_list = []
        self.hex_digits = ['a', 'b', 'c', 'd', 'e', 'f', 'x']

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
            # elif self.is_timespan():
            #     print(f'TIMESPAN FOUND')

            # --- String
            # elif self.is_string():
            #     token = self.read_string()

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

            elif self.is_hex_digit(self.text[self.pos]):
                token = self.read_hex_digit()

            # --- Int, float, ipv4
            elif self.is_digit(self.text[self.pos]):
                token = self.read_digit()

            # --- Alpha numeric
            elif self.is_alpha(self.text[self.pos]):
                token = self.read_alpha()
            else:
                self.pos += 1
                self.col += 1

            self.token_list.append(token)
            # yield (token)

        # --- End of file parsing
        self.token_list.append(
            Token(tl.TOK_EOF, "EOF", self.line, self.col))
        return self.token_list
        # yield (Token(TOK_EOF, "EOF", self.line, self.col))

    def is_hex_digit(self, c: str) -> bool:
        return c.isdigit() and self.text[self.pos + 1] == 'x'
        # return c.isdigit() or c == '.'

    def read_hex_digit(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and (self.is_digit(self.text[self.pos]) or self.text[self.pos] in self.hex_digits):
            self.pos += 1

        value = self.text[tok_start + 2: self.pos]
        int_value = int(value, 16)
        token = Token(tl.TOK_INTEGER, str(int_value), self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_digit(self, c: str) -> bool:
        return c.isdigit()
        # return c.isdigit() or c == '.'

    def read_digit(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_digit(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start: self.pos]
        if value.count(".") == 1:
            token = Token(tl.TOK_FLOAT, value, self.line, self.col)
        else:
            token = Token(tl.TOK_INTEGER, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_alpha(self, c: str) -> bool:
        return c.isalnum() or c == "_"
        # return c.isalnum() or c == "_" or c == "."

    def read_alpha(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_alpha(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start: self.pos]
        if value in _keywords:
            token = Token(_keywords[value], value, self.line, self.col)
        elif value in constants:
            token = Token(tl.TOK_CONST, value, self.line, self.col)
        else:
            token = Token(tl.TOK_NAME, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token


class Preparser:
    def __init__(self, pql):
        self.pql = pql
        self.token_list = []
        self.index = 0
        self.len = len(pql)

    def peek(self) -> None | Token:
        if self.at_end():
            return None

        return self.pql[self.index]

    def peek_at(self, offset: int, search_tok) -> None | Token:
        if self.index + offset < self.len:
            if self.pql[self.index + offset].type == search_tok:
                return self.pql[self.index + offset]

        return None

    def advance(self) -> None | Token:
        if self.at_end():
            return None

        result = self.pql[self.index]
        self.index += 1

        return result

    def at_end(self) -> bool:
        return self.index >= self.len

    def parse(self):
        while not self.at_end():
            self.get_label()
            self.get_ip_address()
            self.get_mac_address()
            self.get_timestamp()
            self.get_date()
            self.get_time()
            self.token_list.append(self.advance())

        return self.token_list

    def get_label(self):
        label: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_NAME) \
                and self.peek_at(1, tl.TOK_PERIOD)  \
                and self.peek_at(2, tl.TOK_NAME):

            for i in range(0, 3):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    label += tok.value

            token = Token(tl.TOK_NAME, label, line, column)

            self.token_list.append(token)

    def get_ip_address(self):
        ip_address: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_INTEGER) \
                and self.peek_at(1, tl.TOK_PERIOD)  \
                and self.peek_at(2, tl.TOK_INTEGER) \
                and self.peek_at(3, tl.TOK_PERIOD)  \
                and self.peek_at(4, tl.TOK_INTEGER) \
                and self.peek_at(5, tl.TOK_PERIOD)  \
                and self.peek_at(6, tl.TOK_INTEGER):

            for i in range(0, 7):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    ip_address += tok.value

            token = Token(tl.TOK_IPV4, ip_address, line, column)

            self.token_list.append(token)

    def get_mac_address(self):
        mac_address: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_INTEGER) \
                and self.peek_at(1, tl.TOK_COLON)  \
                and self.peek_at(2, tl.TOK_INTEGER) \
                and self.peek_at(3, tl.TOK_COLON)  \
                and self.peek_at(4, tl.TOK_INTEGER) \
                and self.peek_at(5, tl.TOK_COLON)  \
                and self.peek_at(6, tl.TOK_INTEGER) \
                and self.peek_at(7, tl.TOK_COLON)  \
                and self.peek_at(8, tl.TOK_INTEGER) \
                and self.peek_at(9, tl.TOK_COLON)  \
                and self.peek_at(10, tl.TOK_INTEGER):

            for i in range(0, 11):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    mac_address += tok.value

            token = Token(tl.TOK_MAC, mac_address, line, column)

            self.token_list.append(token)

    def get_timestamp(self):
        timestamp: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_INTEGER) \
                and self.peek_at(1, tl.TOK_MINUS)  \
                and self.peek_at(2, tl.TOK_INTEGER) \
                and self.peek_at(3, tl.TOK_MINUS)  \
                and self.peek_at(4, tl.TOK_INTEGER) \
                and self.peek_at(5, tl.TOK_INTEGER) \
                and self.peek_at(6, tl.TOK_COLON)  \
                and self.peek_at(7, tl.TOK_INTEGER) \
                and self.peek_at(8, tl.TOK_COLON)  \
                and self.peek_at(9, tl.TOK_INTEGER):

            for i in range(0, 10):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    if i == 5:
                        timestamp += " "
                    timestamp += tok.value

            token = Token(tl.TOK_TIMESTAMP, timestamp, line, column)

            self.token_list.append(token)

    def get_date(self):
        date_value: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_INTEGER) \
                and self.peek_at(1, tl.TOK_MINUS)  \
                and self.peek_at(2, tl.TOK_INTEGER) \
                and self.peek_at(3, tl.TOK_MINUS)  \
                and self.peek_at(4, tl.TOK_INTEGER):

            for i in range(0, 5):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    date_value += tok.value

            token = Token(tl.TOK_DATE, date_value, line, column)

            self.token_list.append(token)

    def get_time(self):
        timestamp: str = ""
        column = 0
        line = 0

        if self.peek_at(0, tl.TOK_INTEGER) \
                and self.peek_at(1, tl.TOK_COLON)  \
                and self.peek_at(2, tl.TOK_INTEGER) \
                and self.peek_at(3, tl.TOK_COLON)  \
                and self.peek_at(4, tl.TOK_INTEGER):

            for i in range(0, 5):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    timestamp += tok.value

            token = Token(tl.TOK_TIME, timestamp, line, column)

            self.token_list.append(token)


def tokenize(pql: str):
    lexer = Lexer(pql)
    token_list = lexer.tokenize()
    preparser = Preparser(token_list)
    token_list = preparser.parse()
    for t in token_list:
        yield (t)

import pql.pql_constant as const
from pql.tokens_list import Tokens

_keywords = {
    "select": Tokens.TOK_SELECT,
    "from": Tokens.TOK_FROM,
    "include": Tokens.TOK_INCLUDE,
    "where": Tokens.TOK_WHERE,
    "order": Tokens.TOK_ORDER_BY,
    "by": Tokens.TOK_BY,
    "group": Tokens.TOK_GROUP_BY,
    "asc": Tokens.TOK_ASC,
    "desc": Tokens.TOK_DESC,
    "between": Tokens.TOK_BETWEEN,
    "top": Tokens.TOK_TOP,
    "offset": Tokens.TOK_OFFSET,
    "limit": Tokens.TOK_LIMIT,
    "in": Tokens.TOK_IN,
    "and": Tokens.TOK_LAND,
    "or": Tokens.TOK_LOR,
    "now": Tokens.TOK_NOW,
    "filter": Tokens.TOK_FILTER,
    "output": Tokens.TOK_OUTPUT,
    "to": Tokens.TOK_TO,
    "true": Tokens.TOK_TRUE,
    "false": Tokens.TOK_FALSE,
    "interval": Tokens.TOK_INTERVAL,
    "avg": Tokens.TOK_AVERAGE,
    "sum": Tokens.TOK_SUM,
    "min": Tokens.TOK_MIN,
    "max": Tokens.TOK_MAX,
    "count": Tokens.TOK_COUNT,
    "as": Tokens.TOK_AS,
    "bandwidth": Tokens.TOK_BANDWIDTH,
}


_token1 = {
    "/": Tokens.TOK_MASK,
    "*": Tokens.TOK_WILDCARD,
    ";": Tokens.TOK_SEMI,
    ",": Tokens.TOK_DELIMITER,
    ">": Tokens.TOK_GT,
    "<": Tokens.TOK_LT,
    "{": Tokens.TOK_LBRACE,
    "}": Tokens.TOK_RBRACE,
    "+": Tokens.TOK_PLUS,
    "-": Tokens.TOK_MINUS,
    "(": Tokens.TOK_LPAREN,
    ")": Tokens.TOK_RPAREN,
    "[": Tokens.TOK_INDEX_START,
    "]": Tokens.TOK_INDEX_END,
    ":": Tokens.TOK_COLON,
    "'": Tokens.TOK_SINGLE_QUOTE,
    ".": Tokens.TOK_PERIOD,
}

_token2 = {
    "==": Tokens.TOK_EQ,
    "<=": Tokens.TOK_LE,
    ">=": Tokens.TOK_GE,
    "!=": Tokens.TOK_NE,
}
# _keywords = {
#     "select": Tokens.TOK_SELECT,
#     "from": Tokens.TOK_FROM,
#     "include": Tokens.TOK_INCLUDE,
#     "where": Tokens.TOK_WHERE,
#     "order": Tokens.TOK_ORDER_BY,
#     "by": Tokens.TOK_BY,
#     "group": Tokens.TOK_GROUP_BY,
#     "asc": Tokens.TOK_ASC,
#     "desc": Tokens.TOK_DESC,
#     "between": Tokens.TOK_BETWEEN,
#     "top": Tokens.TOK_TOP,
#     "offset": Tokens.TOK_OFFSET,
#     "limit": Tokens.TOK_LIMIT,
#     "in": Tokens.TOK_IN,
#     "and": Tokens.TOK_LAND,
#     "or": Tokens.TOK_LOR,
#     "now": Tokens.TOK_NOW,
#     "filter": Tokens.TOK_FILTER,
#     "output": Tokens.TOK_OUTPUT,
#     "to": Tokens.TOK_TO,
#     "true": Tokens.TOK_TRUE,
#     "false": Tokens.TOK_FALSE,
#     "interval": Tokens.TOK_INTERVAL,
#     "avg": Tokens.TOK_AVERAGE,
#     "sum": Tokens.TOK_SUM,
#     "min": Tokens.TOK_MIN,
#     "max": Tokens.TOK_MAX,
#     "count": Tokens.TOK_COUNT,
#     "as": Tokens.TOK_AS,
#     "bandwidth": Tokens.TOK_BANDWIDTH,
# }


# _token1 = {
#     "/": Tokens.TOK_MASK,
#     "*": Tokens.TOK_WILDCARD,
#     ";": Tokens.TOK_SEMI,
#     ",": Tokens.TOK_DELIMITER,
#     ">": Tokens.TOK_GT,
#     "<": Tokens.TOK_LT,
#     "{": Tokens.TOK_LBRACE,
#     "}": Tokens.TOK_RBRACE,
#     "+": Tokens.TOK_PLUS,
#     "-": Tokens.TOK_MINUS,
#     "(": Tokens.TOK_LPAREN,
#     ")": Tokens.TOK_RPAREN,
#     "[": Tokens.TOK_INDEX_START,
#     "]": Tokens.TOK_INDEX_END,
#     ":": Tokens.TOK_COLON,
#     "'": Tokens.TOK_SINGLE_QUOTE,
#     ".": Tokens.TOK_PERIOD,
# }

# _token2 = {
#     "==": Tokens.TOK_EQ,
#     "<=": Tokens.TOK_LE,
#     ">=": Tokens.TOK_GE,
#     "!=": Tokens.TOK_NE,
# }

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
        return f"({self.type:x}:{Tokens.human_tokens(self.type)}, {self.value}, {self.line}, {self.col})"


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
            Token(Tokens.TOK_EOF, "EOF", self.line, self.col))
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
        token = Token(Tokens.TOK_INTEGER, str(int_value), self.line, self.col)

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
            token = Token(Tokens.TOK_FLOAT, value, self.line, self.col)
        else:
            token = Token(Tokens.TOK_INTEGER, value, self.line, self.col)

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
        elif value in const.const_list:
            token = Token(Tokens.TOK_CONST, value, self.line, self.col)
        else:
            token = Token(Tokens.TOK_NAME, value, self.line, self.col)

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
            self.get_ip_address()
            self.get_mac_address()
            self.get_timestamp()
            self.get_date()
            self.get_time()
            self.get_count()
            self.get_sum()
            self.get_average()
            self.get_min()
            self.get_max()
            self.get_bandwidth()
            self.get_as()
            self.order_by()
            self.group_by()
            self.get_label()
            self.token_list.append(self.advance())

        return self.token_list

    def group_by(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_GROUP_BY) \
                and self.peek_at(1, Tokens.TOK_BY):

            tok = self.advance()  # group
            if tok:
                column = tok.col
                line = tok.line

            _ = self.advance()  # by
            token = Token(Tokens.TOK_GROUP_BY, field, line, column)

            self.token_list.append(token)

    def order_by(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_ORDER_BY) \
                and self.peek_at(1, Tokens.TOK_BY):

            tok = self.advance()  # group
            if tok:
                column = tok.col
                line = tok.line

            _ = self.advance()  # by
            token = Token(Tokens.TOK_ORDER_BY, field, line, column)

            self.token_list.append(token)

    def get_as(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_AS) \
                and self.peek_at(1, Tokens.TOK_NAME):

            tok = self.advance()  # as
            if tok:
                column = tok.col
                line = tok.line

            fieldname = self.advance()
            if fieldname:
                field = fieldname.value

            token = Token(Tokens.TOK_AS, field, line, column)

            self.token_list.append(token)

    def get_count(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_COUNT) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_RPAREN):

            tok = self.advance()  # count
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_COUNT, field, line, column)

            self.token_list.append(token)

    def get_bandwidth(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_BANDWIDTH) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_NAME) \
                and self.peek_at(3, Tokens.TOK_PERIOD) \
                and self.peek_at(4, Tokens.TOK_NAME) \
                and self.peek_at(5, Tokens.TOK_RPAREN):

            tok = self.advance()  # sum
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                name_part1 = self.advance()
                self.advance()  # period
                name_part2 = self.advance()

                if name_part1 and name_part2:
                    field = f"{name_part1.value}.{name_part2.value}"
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_BANDWIDTH, field, line, column)

            self.token_list.append(token)

    def get_min(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_MIN) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_NAME) \
                and self.peek_at(3, Tokens.TOK_PERIOD) \
                and self.peek_at(4, Tokens.TOK_NAME) \
                and self.peek_at(5, Tokens.TOK_RPAREN):

            tok = self.advance()  # sum
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                name_part1 = self.advance()
                self.advance()  # period
                name_part2 = self.advance()

                if name_part1 and name_part2:
                    field = f"{name_part1.value}.{name_part2.value}"
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_MIN, field, line, column)

            self.token_list.append(token)

    def get_max(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_MAX) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_NAME) \
                and self.peek_at(3, Tokens.TOK_PERIOD) \
                and self.peek_at(4, Tokens.TOK_NAME) \
                and self.peek_at(5, Tokens.TOK_RPAREN):

            tok = self.advance()  # sum
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                name_part1 = self.advance()
                self.advance()  # period
                name_part2 = self.advance()

                if name_part1 and name_part2:
                    field = f"{name_part1.value}.{name_part2.value}"
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_MAX, field, line, column)

            self.token_list.append(token)

    def get_sum(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_SUM) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_NAME) \
                and self.peek_at(3, Tokens.TOK_PERIOD) \
                and self.peek_at(4, Tokens.TOK_NAME) \
                and self.peek_at(5, Tokens.TOK_RPAREN):

            tok = self.advance()  # sum
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                name_part1 = self.advance()
                self.advance()  # period
                name_part2 = self.advance()

                if name_part1 and name_part2:
                    field = f"{name_part1.value}.{name_part2.value}"
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_SUM, field, line, column)

            self.token_list.append(token)

    def get_average(self):
        field: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_AVERAGE) \
                and self.peek_at(1, Tokens.TOK_LPAREN)  \
                and self.peek_at(2, Tokens.TOK_NAME) \
                and self.peek_at(3, Tokens.TOK_PERIOD) \
                and self.peek_at(4, Tokens.TOK_NAME) \
                and self.peek_at(5, Tokens.TOK_RPAREN):

            tok = self.advance()  # sum
            if tok:
                column = tok.col
                line = tok.line

                self.advance()  # skip lparen
                name_part1 = self.advance()
                self.advance()  # period
                name_part2 = self.advance()

                if name_part1 and name_part2:
                    field = f"{name_part1.value}.{name_part2.value}"
                self.advance()  # skip rparen

            token = Token(Tokens.TOK_AVERAGE, field, line, column)

            self.token_list.append(token)

    def get_label(self):
        label: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_NAME) \
                and self.peek_at(1, Tokens.TOK_PERIOD)  \
                and self.peek_at(2, Tokens.TOK_NAME):

            for i in range(0, 3):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    label += tok.value

            token = Token(Tokens.TOK_NAME, label, line, column)

            self.token_list.append(token)

    def get_ip_address(self):
        ip_address: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_INTEGER) \
                and self.peek_at(1, Tokens.TOK_PERIOD)  \
                and self.peek_at(2, Tokens.TOK_INTEGER) \
                and self.peek_at(3, Tokens.TOK_PERIOD)  \
                and self.peek_at(4, Tokens.TOK_INTEGER) \
                and self.peek_at(5, Tokens.TOK_PERIOD)  \
                and self.peek_at(6, Tokens.TOK_INTEGER):

            for i in range(0, 7):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    ip_address += tok.value

            token = Token(Tokens.TOK_IPV4, ip_address, line, column)

            self.token_list.append(token)

    def get_mac_address(self):
        mac_address: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_INTEGER) \
                and self.peek_at(1, Tokens.TOK_COLON)  \
                and self.peek_at(2, Tokens.TOK_INTEGER) \
                and self.peek_at(3, Tokens.TOK_COLON)  \
                and self.peek_at(4, Tokens.TOK_INTEGER) \
                and self.peek_at(5, Tokens.TOK_COLON)  \
                and self.peek_at(6, Tokens.TOK_INTEGER) \
                and self.peek_at(7, Tokens.TOK_COLON)  \
                and self.peek_at(8, Tokens.TOK_INTEGER) \
                and self.peek_at(9, Tokens.TOK_COLON)  \
                and self.peek_at(10, Tokens.TOK_INTEGER):

            for i in range(0, 11):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    mac_address += tok.value

            token = Token(Tokens.TOK_MAC, mac_address, line, column)

            self.token_list.append(token)

    def get_timestamp(self):
        timestamp: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_INTEGER) \
                and self.peek_at(1, Tokens.TOK_MINUS)  \
                and self.peek_at(2, Tokens.TOK_INTEGER) \
                and self.peek_at(3, Tokens.TOK_MINUS)  \
                and self.peek_at(4, Tokens.TOK_INTEGER) \
                and self.peek_at(5, Tokens.TOK_INTEGER) \
                and self.peek_at(6, Tokens.TOK_COLON)  \
                and self.peek_at(7, Tokens.TOK_INTEGER) \
                and self.peek_at(8, Tokens.TOK_COLON)  \
                and self.peek_at(9, Tokens.TOK_INTEGER):

            for i in range(0, 10):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    if i == 5:
                        timestamp += " "
                    timestamp += tok.value

            token = Token(Tokens.TOK_TIMESTAMP, timestamp, line, column)

            self.token_list.append(token)

    def get_date(self):
        date_value: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_INTEGER) \
                and self.peek_at(1, Tokens.TOK_MINUS)  \
                and self.peek_at(2, Tokens.TOK_INTEGER) \
                and self.peek_at(3, Tokens.TOK_MINUS)  \
                and self.peek_at(4, Tokens.TOK_INTEGER):

            for i in range(0, 5):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    date_value += tok.value

            token = Token(Tokens.TOK_DATE, date_value, line, column)

            self.token_list.append(token)

    def get_time(self):
        timestamp: str = ""
        column = 0
        line = 0

        if self.peek_at(0, Tokens.TOK_INTEGER) \
                and self.peek_at(1, Tokens.TOK_COLON)  \
                and self.peek_at(2, Tokens.TOK_INTEGER) \
                and self.peek_at(3, Tokens.TOK_COLON)  \
                and self.peek_at(4, Tokens.TOK_INTEGER):

            for i in range(0, 5):
                tok = self.advance()
                if tok:
                    if i == 0:
                        column = tok.col
                        line = tok.line

                    timestamp += tok.value

            token = Token(Tokens.TOK_TIME, timestamp, line, column)

            self.token_list.append(token)


def tokenize(pql: str):
    lexer = Lexer(pql)
    token_list = lexer.tokenize()
    preparser = Preparser(token_list)
    token_list = preparser.parse()
    for t in token_list:
        yield (t)

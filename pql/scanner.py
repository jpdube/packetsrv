from enum import Enum, auto

itoa_counter = 0


def itoa(reset=False):
    global itoa_counter
    if reset:
        itoa_counter = 0
    result = itoa_counter
    itoa_counter += 1

    return result


class Keywords(Enum):
    SELECT = auto()
    FROM = auto()


_keywords = {
    "select": "SELECT",
    "from": "FROM",
    "where": "WHERE",
    "order by": "ORDER BY",
    "asc": "ASC",
    "desc": "DESC",
    "between": "BETWEEN",
    "top": "TOP",
    "limit": "LIMIT",
    "in": "IN",
    "and": "LAND",
    "or": "LOR",
    "now": "NOW",
    "var": "VAR",
    "print": "PRINT",
    "if": "IF",
    "else": "ELSE",
}

_token1 = {
    "=": "ASSIGN",
    "/": "MASK",
    "*": "WILDCARD",
    ";": "SEMI",
    ",": "DELIMITER",
    ">": "GT",
    "<": "LT",
    "{": "LBRACE",
    "}": "RBRACE",
    "+": "PLUS",
    "-": "MINUS",
    "(": "LPAREN",
    ")": "RPAREN",
}

_token2 = {
    "==": "EQ",
    "<=": "LE",
    ">=": "GE",
    "!=": "NE",
}  # , "&&": "LAND", "||": "LOR"}

_token_comment = {"//", "/*", "*/"}


class Token:
    def __init__(self, type, value, line, col):
        self.type = type
        self.value = value
        self.line = line
        self.col = col

    def __repr__(self):
        return f"({self.type}, {self.value}, {self.line}, {self.col})"


class Scanner:
    def __init__(self, text):
        assert len(text) > 0
        self.text = text
        self.text_len = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1

    def tokenize(self):
        self.pos = 0

        while self.pos < self.text_len:
            if self.text[self.pos].isspace():
                if self.text[self.pos] == "\n":
                    self.line += 1
                    self.col = 0

                self.pos += 1
                self.col += 1
                continue

            elif self.text[self.pos : self.pos + 2] == "//":
                eol = self.text.find(";", self.pos + 2)
                # print(f'Text pos: {pos}, EOL: {eol}')
                if eol > 0:
                    self.pos = eol + 1
                else:
                    self.pos = len(self.text)
                continue

            elif self.text[self.pos] == "'":
                tok_start = self.pos
                self.pos += 1
                while self.pos < self.text_len and self.text[self.pos] != "'":
                    self.pos += 1
                value = self.text[tok_start + 1 : self.pos]
                token = Token("STRING", value, self.line, self.col)
                self.col += self.pos - tok_start
                self.pos += 1

            elif self.text[self.pos : self.pos + 2] in _token2:
                token = Token(
                    _token2[self.text[self.pos : self.pos + 2]],
                    self.text[self.pos : self.pos + 2],
                    self.line,
                    self.col,
                )
                self.pos += 2
                self.col += 2

            elif (
                (self.pos + 18) < self.text_len
                and self.text[self.pos : self.pos + 19].count("-") == 2
                and self.text[self.pos : self.pos + 19].count(":") == 2
            ):
                value = self.text[self.pos : self.pos + 19]
                token = Token("DATE", value, self.line, self.col)
                self.pos += 19
                self.col += 19

            elif self.text[self.pos] in _token1:
                token = Token(
                    _token1[self.text[self.pos]],
                    self.text[self.pos],
                    self.line,
                    self.col,
                )
                self.pos += 1
                self.col += 1

            elif (self.pos + 16) < self.text_len and self.text[
                self.pos : self.pos + 16
            ].count(":") == 5:
                tok_start = self.pos
                while self.pos < self.text_len and (
                    self.text[self.pos].isalnum() or self.text[self.pos] == ":"
                ):
                    self.pos += 1

                value = self.text[tok_start : self.pos]
                token = Token("MAC", value, self.line, self.col)
                self.col += self.pos - tok_start

            elif self.text[self.pos].isdigit():
                tok_start = self.pos
                while self.pos < self.text_len and (
                    self.text[self.pos].isdigit() or self.text[self.pos] == "."
                ):
                    self.pos += 1

                value = self.text[tok_start : self.pos]
                if value.count(".") == 3:
                    token = Token("IPV4", value, self.line, self.col)
                elif "." in value:
                    token = Token("FLOAT", value, self.line, self.col)
                else:
                    token = Token("INTEGER", value, self.line, self.col)
                self.col += self.pos - tok_start

            elif self.text[self.pos].isalpha() or self.text[self.pos] == "_":
                tok_start = self.pos
                while self.pos < self.text_len and (
                    self.text[self.pos].isalnum() or self.text[self.pos] == "_"
                ):
                    self.pos += 1

                value = self.text[tok_start : self.pos]
                if value in _keywords:
                    token = Token(_keywords[value], value, self.line, self.col)
                    # token = Token(value.upper(), value)
                else:
                    token = Token("NAME", value, self.line, self.col)
                self.col += self.pos - tok_start
            else:
                self.pos += 1
                self.col += 1

            # print(f"YIELD: {token}")
            yield (token)

        # --- End of file parsing
        yield (Token("EOF", "EOF", self.line, self.col))

    def is_ipv4(self):
        if (
            (self.pos + 14) < self.text_len
            and self.text[self.pos : self.pos + 14].count(".") == 3
        ) or ():
            tok_start = self.pos
            while self.pos < self.text_len and (
                self.text[self.pos].isalnum() or self.text[self.pos] == "."
            ):
                self.pos += 1

            value = self.text[tok_start : self.pos]
            token = Token("IPV4", value)


# if __name__ == '__main__':
#     with open('../script/test1.fw') as file:
#         text = file.read()
#
#     source = "show version\nshow interface eth0\n"
#     tokenizer = Tokenizer(text)
#     tokens = tokenizer.tokenize()
#     for t in tokens:
#         print(f'Token: {t}')

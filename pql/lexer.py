from pql.tokens_list import Tok

_keywords = {
    "select": Tok.SELECT,
    "from": Tok.FROM,
    "include": Tok.INCLUDE,
    "where": Tok.WHERE,
    "order by": Tok.ORDER_BY,
    "asc": Tok.ASC,
    "desc": Tok.DESC,
    "between": Tok.BETWEEN,
    "top": Tok.TOP,
    "limit": Tok.LIMIT,
    "in": Tok.IN,
    "and": Tok.LAND,
    "or": Tok.LOR,
    "now": Tok.NOW,
    "var": Tok.VAR,
    "print": Tok.PRINT,
    "if": Tok.IF,
    "else": Tok.ELSE,
    "with": Tok.WITH,
    "filter": Tok.FILTER,
    "output": Tok.OUTPUT,
}

_token1 = {
    "=": Tok.ASSIGN,
    "/": Tok.MASK,
    "*": Tok.WILDCARD,
    ";": Tok.SEMI,
    ",": Tok.DELIMITER,
    ">": Tok.GT,
    "<": Tok.LT,
    "{": Tok.LBRACE,
    "}": Tok.RBRACE,
    "+": Tok.PLUS,
    "-": Tok.MINUS,
    "(": Tok.LPAREN,
    ")": Tok.RPAREN,
}

_token2 = {
    "==": Tok.EQ,
    "<=": Tok.LE,
    ">=": Tok.GE,
    "!=": Tok.NE,
}

_token_comment = {"//", "/*", "*/"}


class Token:
    def __init__(self, type: Tok, value: str, line: int, col: int):
        self.type: Tok = type
        self.value: str = value
        self.line: int = line
        self.col: int = col

    def __repr__(self):
        return f"({self.type}, {self.value}, {self.line}, {self.col})"


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
            elif self.text[self.pos : self.pos + 1] == "#":
                eol = self.text.find("\n", self.pos + 1)
                if eol > 0:
                    self.pos = eol + 1
                else:
                    self.pos = len(self.text)
                continue

            # --- String
            elif self.is_string():
                token = self.read_string()

            # --- Token 2 characters
            elif self.text[self.pos : self.pos + 2] in _token2:
                token = Token(
                    _token2[self.text[self.pos : self.pos + 2]],
                    self.text[self.pos : self.pos + 2],
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

            #--- Alpha numeric
            elif self.is_alpha(self.text[self.pos]):
                token = self.read_alpha()
            else:
                self.pos += 1
                self.col += 1

            yield (token)

        # --- End of file parsing
        yield (Token(Tok.EOF, "EOF", self.line, self.col))

    def is_digit(self, c: str) -> bool:
        return c.isdigit() or c == '.' or c == ':'

    def read_digit(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_digit(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start : self.pos]
        if value.count(".") == 3:
            token = Token(Tok.IPV4, value, self.line, self.col)
        elif "." in value:
            token = Token(Tok.FLOAT, value, self.line, self.col)
        else:
            token = Token(Tok.INTEGER, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_alpha(self, c: str) -> bool:
        return c.isalnum() or c == "_" or c == "."

    def read_alpha(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and self.is_alpha(self.text[self.pos]):
            self.pos += 1

        value = self.text[tok_start : self.pos]
        if value in _keywords:
            token = Token(_keywords[value], value, self.line, self.col)
        else:
            token = Token(Tok.NAME, value, self.line, self.col)

        self.col += self.pos - (self.pos - len(value))
        return token

    def is_mac_addr(self) -> bool:
        return (self.pos + 16) < self.text_len and self.text[self.pos:self.pos + 16].count(":") == 5
        
    def read_mac(self) -> Token:
        tok_start = self.pos
        while self.pos < self.text_len and (self.text[self.pos].isalnum() or self.text[self.pos] == ":"):
            self.pos += 1

        value = self.text[tok_start : self.pos]
        self.col += self.pos - (self.pos - len(value))
        return Token(Tok.MAC, value, self.line, self.col)

    def is_string(self) -> bool:
        return self.text[self.pos] == "'"

    def read_string(self) -> Token:
        tok_start = self.pos
        self.pos += 1
        while self.pos < self.text_len and self.text[self.pos] != "'":
            self.pos += 1
        value = self.text[tok_start + 1 : self.pos]
        token = Token(Tok.STRING, value, self.line, self.col)
        self.pos += 1
        self.col += self.pos - (self.pos - len(value))

        return token

    def is_date(self) -> bool:
        return (self.pos + 18) < self.text_len and self.text[self.pos : self.pos + 19].count("-") == 2 and self.text[self.pos : self.pos + 19].count(":") == 2

    def read_date(self) -> Token:
        value = self.text[self.pos : self.pos + 19]
        token = Token(Tok.DATE, value, self.line, self.col)
        self.pos += 19
        self.col += self.pos - (self.pos - len(value))
        return token
        

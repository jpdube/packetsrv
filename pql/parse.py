# from packet.layers.ipv4 import IPV4
from pql.lexer import Lexer
from pql.model import *
from pql.tokens_list import Tok


class Tokenizer:
    def __init__(self, tokens):
        self.tokens = tokens
        self.lookahead = None
        self.prev_token = None

    def peek(self, *token_type):
        if self.lookahead is None:
            self.lookahead = next(self.tokens)

        if self.lookahead.type in token_type:
            return self.lookahead
        else:
            return None

    def accept(self, *token_type):
        token = self.peek(*token_type)
        if token:
            self.prev_token = self.lookahead
            self.lookahead = None
        return token

    def expect(self, *token_type, error_msg=""):
        token = self.peek(*token_type)
        line = 0
        col = 0
        if token is None:
            if self.prev_token is not None:
                line = self.prev_token.line
                col = self.prev_token.col

            print(
                f"Syntax error at line: {line} column: {col} token: {self.lookahead}"
            )
            raise SyntaxError
        else:
            # if token:
            self.prev_token = self.lookahead
            self.lookahead = None
            return token


def parse_prog(tokens):
    statements = parse_stmts(tokens)
    tokens.expect(Tok.EOF)

    return statements


def parse_stmt(tokens):
    if tokens.peek(Tok.NAME):
        return parse_assignment(tokens)
    elif tokens.peek(Tok.PRINT):
        return parse_print(tokens)
    elif tokens.peek(Tok.IF):
        return parse_if(tokens)
    elif tokens.peek(Tok.WHILE):
        return parse_while(tokens)
    elif tokens.peek(Tok.VAR):
        return parse_var(tokens)
    elif tokens.peek(Tok.CONST):
        return parse_const(tokens)
    # elif tokens.peek(Tok.CONTINUE):
    #     return parse_continue(tokens)
    # elif tokens.peek(Tok.BREAK):
    #     return parse_break(tokens)
    elif tokens.peek(Tok.WITH):
        return parse_with(tokens)
    elif tokens.peek(Tok.SELECT):
        return parse_select(tokens)
    elif tokens.peek(Tok.NOW):
        return parse_now(tokens)
    else:
        return None


def parse_stmts(tokens):
    stmt_list = []
    while True:
        stmt = parse_stmt(tokens)
        if stmt is None:
            break
        stmt_list.append(stmt)
    return stmt_list


def parse_assignment(tokens):
    print("In assignment")
    var_name = tokens.expect(Tok.NAME)
    tokens.expect(Tok.ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(Tok.SEMI)
    return Store(var_name.value, value)


def parse_with(tokens):
    tokens.expect(Tok.WITH, error_msg="Expected with statement")
    sniffer = tokens.expect(Tok.NAME, error_msg="Expected name")

    where_value = None
    tok_where = tokens.expect(
        Tok.FILTER, error_msg="Filter token expected")
    if tok_where:
        where_value = parse_expression(tokens)
    else:
        return

    tokens.expect(Tok.OUTPUT, error_msg="Must specify output mode")
    fields = []
    if tokens.peek(Tok.WILDCARD):
        field = tokens.expect(Tok.WILDCARD)
        fields.append(Label("*"))
    else:
        while True:
            field = tokens.expect(Tok.NAME)
            # print(f'SELECT fields: {field}')
            if field:
                fields.append(Label(field.value))

            if tokens.accept(Tok.DELIMITER) is None:
                break

    top_value = None
    if tokens.peek(Tok.TOP):
        tokens.expect(Tok.TOP)
        top_value = parse_expression(tokens)

    limit_fields = []
    if tokens.peek(Tok.LIMIT):
        tokens.expect(Tok.LIMIT)
        offset = tokens.expect(Tok.INTEGER)
        limit_fields.append(offset)
        tokens.expect(Tok.DELIMITER)
        limit = tokens.expect(Tok.INTEGER)
        limit_fields.append(limit)

    tokens.expect(Tok.SEMI)
    return WithStatement(sniffer, fields, where_value, top_value, limit_fields)


def parse_select(tokens):
    tokens.expect(Tok.SELECT)
    fields = []
    if tokens.peek(Tok.WILDCARD):
        field = tokens.expect(Tok.WILDCARD)
        fields.append(Label("*"))
    else:
        while True:
            field = tokens.expect(Tok.NAME)
            # print(f'SELECT fields: {field}')
            if field:
                fields.append(Label(field.value))

            if tokens.accept(Tok.DELIMITER) is None:
                break

    tokens.expect(Tok.FROM)
    from_fields = []
    while True:
        ffield = tokens.expect(Tok.NAME)
        if ffield:
            from_fields.append(Label(ffield.value))
        if tokens.accept(Tok.DELIMITER) is None:
            break

    # tokens.expect(Tok.INCLUDE)
    # include_field = tokens.expect(Tok.NAME)

    where_value = None
    if tokens.peek(Tok.WHERE):
        tokens.expect(Tok.WHERE)
        where_value = parse_expression(tokens)

    top_value = None
    if tokens.peek(Tok.TOP):
        tokens.expect(Tok.TOP)
        top_value = parse_expression(tokens)

    limit_fields = []
    if tokens.peek(Tok.LIMIT):
        tokens.expect(Tok.LIMIT)
        offset = tokens.expect(Tok.INTEGER)
        limit_fields.append(offset)
        tokens.expect(Tok.DELIMITER)
        limit = tokens.expect(Tok.INTEGER)
        limit_fields.append(limit)

    tokens.expect(Tok.SEMI)
    return SelectStatement(fields,
                           from_fields, None, where_value, top_value, limit_fields
                           )


def parse_print(tokens):
    tokens.expect(Tok.PRINT)
    prt_value = parse_expression(tokens)
    tokens.expect(Tok.SEMI)
    return PrintStatement(prt_value)


def parse_date(tokens):
    token = tokens.expect(Tok.DATE)
    return Date(token.value)


def parse_string(tokens):
    token = tokens.expect(Tok.STRING)
    return String(token.value)


def parse_char(tokens):
    token = tokens.expect(Tok.CHAR)
    return Char(token.value)


def parse_integer(tokens):
    token = tokens.expect(Tok.INTEGER)
    return Integer(token.value)


def parse_float(tokens):
    token = tokens.expect(Tok.FLOAT)
    return Float(token.value)


def parse_ipv4(tokens):
    token = tokens.expect(Tok.IPV4)
    print(f"*** -> IPV4 parse: {token.value}")
    return IPv4(token.value)


def parse_mac(tokens):
    token = tokens.expect(Tok.MAC)
    return Mac(token.value)


def parse_const(tokens):
    tokens.expect(Tok.CONST)
    name = tokens.expect(Tok.NAME)
    const_type = tokens.accept(Tok.NAME)
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect(Tok.ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(Tok.SEMI)
    return ConstDecl(name.value, type, value)


def parse_var(tokens):
    tokens.expect(Tok.VAR)
    name = tokens.expect(Tok.NAME)
    const_type = tokens.accept(Tok.NAME)
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect(Tok.ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(Tok.SEMI)
    return VarDecl(name.value, type, value)


def parse_grouping(tokens):
    tokens.expect(Tok.LPAREN)
    expr = parse_expression(tokens)
    tokens.expect(Tok.RPAREN)
    return Grouping(expr)


def parse_expression(tokens):
    return parse_or(tokens)


def parse_or(tokens):
    leftval = parse_and(tokens)
    while True:
        optok = tokens.accept(Tok.LOR)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_and(tokens))


def parse_and(tokens):
    leftval = parse_relation(tokens)
    while True:
        optok = tokens.accept(Tok.LAND)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_relation(tokens))


def parse_relation(tokens):
    leftval = parse_sum(tokens)
    optok = tokens.accept(Tok.LT, Tok.LE, Tok.GT,
                          Tok.GE, Tok.EQ, Tok.NE, Tok.IN, Tok.BETWEEN)
    if not optok:
        return leftval
    return BinOp(optok.value, leftval, parse_sum(tokens))


def parse_sum(tokens):
    leftval = parse_term(tokens)
    while True:
        optok = tokens.accept(Tok.PLUS, Tok.MINUS)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_term(tokens))


def parse_load(tokens):
    t = tokens.expect(Tok.NAME)
    return Label(t.value)


def parse_term(tokens):
    leftval = parse_factor(tokens)
    while True:
        optok = tokens.accept(Tok.TIMES, Tok.MASK)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_factor(tokens))


def parse_factor(tokens):
    if tokens.peek(Tok.INTEGER):
        return parse_integer(tokens)
    elif tokens.peek(Tok.FLOAT):
        return parse_float(tokens)
    elif tokens.peek(Tok.IPV4):
        return parse_ipv4(tokens)
    elif tokens.peek(Tok.MAC):
        return parse_mac(tokens)
    elif tokens.peek(Tok.CHAR):
        return parse_char(tokens)
    elif tokens.peek(Tok.STRING):
        return parse_string(tokens)
    elif tokens.peek(Tok.DATE):
        return parse_date(tokens)
    elif tokens.peek(Tok.TRUE, Tok.FALSE):
        return parse_bool(tokens)
    elif tokens.peek(Tok.PLUS, Tok.MINUS, Tok.LNOT):
        return parse_unary(tokens)
    elif tokens.peek(Tok.NAME):
        return parse_load(tokens)
    elif tokens.peek(Tok.LPAREN):
        return parse_grouping(tokens)
    elif tokens.peek(Tok.NOW):
        return parse_now(tokens)


def parse_now(tokens):
    modifier = 'h'
    offset = 0

    now_tok = tokens.expect(Tok.NOW)
    tokens.expect(Tok.LPAREN)

    if not tokens.peek(Tok.RPAREN):
        tokens.expect(Tok.MINUS)
        offset = tokens.expect(Tok.INTEGER).value

        if tokens.peek(Tok.NAME):
            modifier = tokens.expect(Tok.NAME).value

    tokens.expect(Tok.RPAREN)

    return Now(int(offset), modifier)


def parse_bool(tokens):
    token = tokens.expect(Tok.TRUE, Tok.FALSE)
    return token.value


def parse_unary(tokens):
    optok = tokens.expect(Tok.PLUS, Tok.MINUS, Tok.LNOT)
    factor = parse_factor(tokens)
    return Unary(optok.value, factor)


def parse_while(tokens):
    tokens.expect(Tok.WHILE)
    expr = parse_expression(tokens)
    tokens.expect(Tok.LBRACE)
    while_stmt = parse_stmts(tokens)
    tokens.expect(Tok.RBRACE)

    return WhileStatement(expr, while_stmt)


def parse_if(tokens):
    tokens.expect(Tok.IF)
    expr = parse_expression(tokens)
    # expr = parse_value(tokens)
    tokens.expect(Tok.LBRACE)
    true_stmt = parse_stmts(tokens)
    tokens.expect(Tok.RBRACE)
    if tokens.accept(Tok.ELSE):
        tokens.expect(Tok.LBRACE)
        else_stmt = parse_stmts(tokens)
        tokens.expect(Tok.RBRACE)
    else:
        else_stmt = []
    return IfStatement(expr, true_stmt, else_stmt)


# def parse_break(tokens):
#     tokens.expect(Tok.BREAK)
#     tokens.expect(Tok.SEMI)
#     return BreakStatement()


# def parse_continue(tokens):
#     tokens.expect(Tok.CONTINUE)
#     tokens.expect(Tok.SEMI)
#     return ContinueStatement()


def parse_source(text):
    lexer = Lexer(text)
    tokens = lexer.tokenize()
    # for t in tokens:
    #     print(t)

    # tokens = lexer.tokenize()
    model = parse_prog(Tokenizer(tokens))
    return model


def parse_file(filename):
    with open(filename) as file:
        text = file.read()

    print(text)
    return parse_source(text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: pql filename")
    model = parse_file(sys.argv[1])
    print(model)

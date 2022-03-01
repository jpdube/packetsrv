from pql.model import *
from pql.scanner import Scanner


class Tokenizer:
    def __init__(self, tokens):
        self.tokens = tokens
        self.lookahead = None

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
            self.lookahead = None
        return token

    def expect(self, *token_type):
        token = self.peek(*token_type)
        if not token:
            print(
                f"**** SYNTAX ERROR AT:{token_type},{self.lookahead.line}:{self.lookahead.col}"
            )
            # raise SyntaxError()
        else:
            self.lookahead = None
            return token


def parse_prog(tokens):
    statements = parse_stmts(tokens)
    tokens.expect("EOF")

    return statements


def parse_stmt(tokens):
    if tokens.peek("NAME"):
        return parse_assignment(tokens)
    elif tokens.peek("PRINT"):
        return parse_print(tokens)
    elif tokens.peek("IF"):
        return parse_if(tokens)
    elif tokens.peek("WHILE"):
        return parse_while(tokens)
    elif tokens.peek("VAR"):
        return parse_var(tokens)
    elif tokens.peek("CONST"):
        return parse_const(tokens)
    elif tokens.peek("CONTINUE"):
        return parse_continue(tokens)
    elif tokens.peek("BREAK"):
        return parse_break(tokens)
    # elif tokens.peek("IN"):
    #     return parse_in(tokens)
    elif tokens.peek("SELECT"):
        return parse_select(tokens)
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
    var_name = tokens.expect("NAME")
    tokens.expect("ASSIGN")
    value = parse_expression(tokens)
    tokens.expect("SEMI")
    return Store(var_name.value, value)


def parse_select(tokens):
    tokens.expect("SELECT")
    fields = []
    if tokens.peek("WILDCARD"):
        field = tokens.expect("WILDCARD")
        fields.append(Label("*"))
    else:
        while True:
            field = tokens.expect("NAME")
            # print(f'SELECT fields: {field}')
            if field:
                fields.append(Label(field.value))
            if tokens.accept("DELIMITER") is None:
                break

    tokens.expect("FROM")
    from_fields = []
    while True:
        ffield = tokens.expect("NAME")
        # print(f'FROM fields: {ffield}')
        if ffield:
            from_fields.append(Label(ffield.value))
        if tokens.accept("DELIMITER") is None:
            break

    where_value = None
    if tokens.peek("WHERE"):
        tokens.expect("WHERE")
        where_value = parse_expression(tokens)

    # between_value = None
    # if tokens.peek("BETWEEN"):
    #     tokens.expect("BETWEEN")
    #     between_value = parse_expression(tokens)

    top_value = None
    if tokens.peek("TOP"):
        tokens.expect("TOP")
        top_value = parse_expression(tokens)

    limit_fields = []
    if tokens.peek("LIMIT"):
        tokens.expect("LIMIT")
        offset = tokens.expect("INTEGER")
        limit_fields.append(offset)
        tokens.expect("DELIMITER")
        limit = tokens.expect("INTEGER")
        limit_fields.append(limit)

    tokens.expect("SEMI")
    return SelectStatement(fields, from_fields, where_value, top_value, limit_fields)


# def parse_in(tokens):
#     token = tokens.expect("IN")
#     return InStatement(token.value)


def parse_print(tokens):
    tokens.expect("PRINT")
    prt_value = parse_expression(tokens)
    tokens.expect("SEMI")
    return PrintStatement(prt_value)


def parse_date(tokens):
    token = tokens.expect("DATE")
    return Date(token.value)


def parse_string(tokens):
    token = tokens.expect("STRING")
    return String(token.value)


def parse_char(tokens):
    token = tokens.expect("CHAR")
    return Char(token.value)


def parse_integer(tokens):
    token = tokens.expect("INTEGER")
    return Integer(token.value)


def parse_float(tokens):
    token = tokens.expect("FLOAT")
    return Float(token.value)


def parse_ipv4(tokens):
    token = tokens.expect("IPV4")
    # if tokens.peek("MASK"):
    #     tokens.expect("MASK")
    #     mask = tokens.expect("INTEGER")
    #     return IPv4(token.value, mask.value)
    # else:
    print(f"*** -> IPV4 parse: {token.value}")
    return IPv4(token.value)


def parse_mac(tokens):
    token = tokens.expect("MAC")
    return Mac(token.value)


def parse_const(tokens):
    tokens.expect("CONST")
    name = tokens.expect("NAME")
    const_type = tokens.accept("NAME")
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect("ASSIGN")
    value = parse_expression(tokens)
    tokens.expect("SEMI")
    return ConstDecl(name.value, type, value)


def parse_var(tokens):
    tokens.expect("VAR")
    name = tokens.expect("NAME")
    const_type = tokens.accept("NAME")
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect("ASSIGN")
    value = parse_expression(tokens)
    tokens.expect("SEMI")
    return VarDecl(name.value, type, value)


def parse_grouping(tokens):
    tokens.expect("LPAREN")
    expr = parse_expression(tokens)
    tokens.expect("RPAREN")
    return Grouping(expr)


def parse_expression(tokens):
    return parse_or(tokens)


def parse_or(tokens):
    leftval = parse_and(tokens)
    while True:
        optok = tokens.accept("LOR")
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_and(tokens))


def parse_and(tokens):
    leftval = parse_relation(tokens)
    while True:
        optok = tokens.accept("LAND")
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_relation(tokens))


def parse_relation(tokens):
    leftval = parse_sum(tokens)
    optok = tokens.accept("LT", "LE", "GT", "GE", "EQ", "NE", "IN")
    if not optok:
        return leftval
    return BinOp(optok.value, leftval, parse_sum(tokens))


def parse_sum(tokens):
    leftval = parse_term(tokens)
    while True:
        optok = tokens.accept("PLUS", "MINUS")
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_term(tokens))


def parse_load(tokens):
    t = tokens.expect("NAME")
    return Label(t.value)


def parse_term(tokens):
    leftval = parse_factor(tokens)
    while True:
        optok = tokens.accept("TIMES", "MASK")
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_factor(tokens))


def parse_factor(tokens):
    if tokens.peek("INTEGER"):
        return parse_integer(tokens)
    elif tokens.peek("FLOAT"):
        return parse_float(tokens)
    elif tokens.peek("IPV4"):
        return parse_ipv4(tokens)
    elif tokens.peek("MAC"):
        return parse_mac(tokens)
    elif tokens.peek("CHAR"):
        return parse_char(tokens)
    elif tokens.peek("STRING"):
        return parse_string(tokens)
    elif tokens.peek("DATE"):
        return parse_date(tokens)
    # elif tokens.peek("IN"):
    #     return parse_in(tokens)
    elif tokens.peek("TRUE", "FALSE"):
        return parse_bool(tokens)
    elif tokens.peek("PLUS", "MINUS", "LNOT"):
        return parse_unary(tokens)
    elif tokens.peek("NAME"):
        return parse_load(tokens)
    elif tokens.peek("LPAREN"):
        return parse_grouping(tokens)


def parse_bool(tokens):
    token = tokens.expect("TRUE", "FALSE")
    return token.value


def parse_unary(tokens):
    optok = tokens.expect("PLUS", "MINUS", "LNOT")
    factor = parse_factor(tokens)
    return Unary(optok.value, factor)


def parse_while(tokens):
    tokens.expect("WHILE")
    expr = parse_expression(tokens)
    tokens.expect("LBRACE")
    while_stmt = parse_stmts(tokens)
    tokens.expect("RBRACE")

    return WhileStatement(expr, while_stmt)


def parse_if(tokens):
    tokens.expect("IF")
    expr = parse_expression(tokens)
    # expr = parse_value(tokens)
    tokens.expect("LBRACE")
    true_stmt = parse_stmts(tokens)
    tokens.expect("RBRACE")
    if tokens.accept("ELSE"):
        tokens.expect("LBRACE")
        else_stmt = parse_stmts(tokens)
        tokens.expect("RBRACE")
    else:
        else_stmt = []
    return IfStatement(expr, true_stmt, else_stmt)


def parse_break(tokens):
    tokens.expect("BREAK")
    tokens.expect("SEMI")
    return BreakStatement()


def parse_continue(tokens):
    tokens.expect("CONTINUE")
    tokens.expect("SEMI")
    return ContinueStatement()


def parse_source(text):
    scanner = Scanner(text)
    tokens = scanner.tokenize()
    for t in tokens:
        print(t)
    tokens = scanner.tokenize()
    model = parse_prog(Tokenizer(tokens))  # You need to implement this part
    return model


def parse_file(filename):
    with open(filename) as file:
        text = file.read()

    print(text)
    return parse_source(text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: wabbit.parse filename")
    model = parse_file(sys.argv[1])

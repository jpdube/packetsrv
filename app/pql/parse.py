# from packet.layers.ipv4 import IPV4
from pql.lexer import Lexer, tokenize
from pql.model import *
from pql.tokens_list import *

index_field = set()
# ip_list = set()
# prev_label = []
prev_ip = 0
ip_search = {'ip.src': [], 'ip.dst': []}


class Tokenizer:
    def __init__(self, tokens):
        self.tokens = tokens
        self.lookahead = None
        self.prev_token = None

        self.prev_label = ""

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
                f"Syntax error at: {line} col: {col} token: {self.lookahead}"
            )
            raise SyntaxError
        else:
            # if token:
            self.prev_token = self.lookahead
            self.lookahead = None

            if token.value in ['ip.dst', 'ip.src']:
                self.prev_label = token.value
            return token


def parse_prog(tokens):
    statements = parse_stmts(tokens)
    tokens.expect(TOK_EOF)

    return statements


def parse_stmt(tokens):
    if tokens.peek(TOK_NAME):
        return parse_assignment(tokens)
    elif tokens.peek(TOK_SELECT):
        return parse_select(tokens)
    elif tokens.peek(TOK_NOW):
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
    # print("In assignment")
    var_name = tokens.expect(TOK_NAME)
    tokens.expect(TOK_ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(TOK_SEMI)
    return Store(var_name.value, value)


def parse_select(tokens):
    tokens.expect(TOK_SELECT)
    fields = []
    if tokens.peek(TOK_WILDCARD):
        field = tokens.expect(TOK_WILDCARD)
        fields.append(Label("*"))
    else:
        while True:
            field = tokens.expect(TOK_NAME)
            # print(f'SELECT fields: {field}')
            if field:
                fields.append(Label(field.value))

            if tokens.accept(TOK_DELIMITER) is None:
                break

    tokens.expect(TOK_FROM)
    from_fields = []
    while True:
        ffield = tokens.expect(TOK_NAME)
        if ffield:
            from_fields.append(Label(ffield.value))
        if tokens.accept(TOK_DELIMITER) is None:
            break

    where_value = None
    if tokens.peek(TOK_WHERE):
        tokens.expect(TOK_WHERE)
        where_value = parse_expression(tokens)

    groupby_value = None
    if tokens.peek(TOK_GROUP_BY):
        tokens.expect(TOK_GROUP_BY)
        groupby_value = []
        while True:
            field = tokens.expect(TOK_NAME)
            # print(f'SELECT fields: {field}')
            if field:
                groupby_value.append(Label(field.value))

            if tokens.accept(TOK_DELIMITER) is None:
                break

    interval_start = 0
    interval_end = 0
    if tokens.peek(TOK_INTERVAL):
        tokens.expect(TOK_INTERVAL)
        interval_start = tokens.expect(TOK_TIMESTAMP).value
        tokens.expect(TOK_TO)
        interval_end = tokens.expect(TOK_TIMESTAMP).value

    top_value = None
    if tokens.peek(TOK_TOP):
        tokens.expect(TOK_TOP)
        top_value = int(tokens.expect(TOK_INTEGER).value)

    limit_fields = []
    if tokens.peek(TOK_LIMIT):
        tokens.expect(TOK_LIMIT)
        offset = tokens.expect(TOK_INTEGER)
        limit_fields.append(offset)
        tokens.expect(TOK_DELIMITER)
        limit = tokens.expect(TOK_INTEGER)
        limit_fields.append(limit)

    tokens.expect(TOK_SEMI)

    return SelectStatement(fields,
                           from_fields,
                           None,
                           index_field,
                           ip_search,
                           where_value,
                           groupby_value,
                           top_value,
                           limit_fields,
                           (interval_start, interval_end)
                           )


def parse_date(tokens):
    token = tokens.expect(TOK_DATE)
    return Date(token.value)


def parse_string(tokens):
    token = tokens.expect(TOK_STRING)
    return String(token.value)


def parse_integer(tokens):
    token = tokens.expect(TOK_INTEGER)
    return Integer(token.value)


# Values:
# [0]
# [1,2]
def parse_array(tokens):
    values = []
    tokens.expect(TOK_INDEX_START)
    while True:
        val = tokens.expect(TOK_INTEGER)
        values.append(int(val.value))

        if not tokens.peek(TOK_DELIMITER):
            tokens.expect(TOK_INDEX_END)
            break
        else:
            tokens.expect(TOK_DELIMITER)

    return Array(bytes(values))


def parse_float(tokens):
    token = tokens.expect(TOK_FLOAT)
    return Float(token.value)


def parse_ipv4(tokens):
    token = tokens.expect(TOK_IPV4)
    mask_value = 32
    if tokens.peek(TOK_MASK):
        tokens.accept(TOK_MASK)
        mask = tokens.expect(TOK_INTEGER)
        mask_value = mask.value

    ip_addr = IPv4(token.value, mask_value)
    ip_search[tokens.prev_label].append((ip_addr.to_int, int(mask_value)))

    # ip_list.add((ip_addr.to_int, int(mask_value)))
    # print(f"IP: {ip_addr}:{prev_label}")
    return ip_addr


def parse_mac(tokens):
    token = tokens.expect(TOK_MAC)
    return Mac(token.value)


def parse_const(tokens):
    name = tokens.expect(TOK_CONST)
    index_field.add(name.value)
    return ConstDecl(name.value, "int", name.value)


def parse_var(tokens):
    tokens.expect(TOK_VAR)
    name = tokens.expect(TOK_NAME)
    const_type = tokens.accept(TOK_NAME)
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect(TOK_ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(TOK_SEMI)
    return VarDecl(name.value, type, value)


def parse_load(tokens):
    t = tokens.expect(TOK_NAME)
    label_name = t.value
    allowed_fields = ["eth", "ip", "tcp", "udp"]
    if tokens.peek(TOK_INDEX_START) and label_name in allowed_fields:
        tokens.expect(TOK_INDEX_START)
        offset = int(tokens.expect(TOK_INTEGER).value)
        tokens.expect(TOK_COLON)
        length = int(tokens.expect(TOK_INTEGER).value)
        tokens.expect(TOK_INDEX_END)
        return LabelByte(label_name, offset, length)

    if "." in label_name:
        index_field.add(t.value.split(".")[0].upper())

    return Label(label_name)


def parse_grouping(tokens):
    tokens.expect(TOK_LPAREN)
    expr = parse_expression(tokens)
    tokens.expect(TOK_RPAREN)
    return Grouping(expr)


def parse_expression(tokens):
    return parse_or(tokens)


def parse_or(tokens):
    leftval = parse_and(tokens)
    while True:
        optok = tokens.accept(TOK_LOR)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_and(tokens))


def parse_and(tokens):
    leftval = parse_relation(tokens)
    while True:
        optok = tokens.accept(TOK_LAND)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_relation(tokens))


def parse_relation(tokens):
    leftval = parse_sum(tokens)

    optok = tokens.accept(TOK_LT, TOK_LE, TOK_GT,
                          TOK_GE, TOK_EQ, TOK_NE, TOK_IN, TOK_BETWEEN, TOK_TO)
    # TOK_GE, TOK_EQ, TOK_NE, TOK_IN, TOK_BETWEEN, TOK_TO)
    if not optok:
        return leftval
    return BinOp(optok.type, leftval, parse_sum(tokens))


def parse_sum(tokens):
    leftval = parse_term(tokens)
    while True:
        optok = tokens.accept(TOK_PLUS, TOK_MINUS)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_term(tokens))


def parse_term(tokens):
    leftval = parse_factor(tokens)
    while True:
        optok = tokens.accept(TOK_TIMES)
        # optok = tokens.accept(TOK_TIMES, TOK_MASK)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_factor(tokens))


# def parse_mask(tokens):
#     leftval = parse_factor(tokens)
#     while True:
#         optok = tokens.accept(TOK_MASK)
#         if not optok:
#             return leftval
#         leftval = BinOp(optok.value, leftval, parse_factor(tokens))


def parse_factor(tokens):
    if tokens.peek(TOK_INTEGER):
        return parse_integer(tokens)
    elif tokens.peek(TOK_FLOAT):
        return parse_float(tokens)
    elif tokens.peek(TOK_INDEX_START):
        return parse_array(tokens)
    elif tokens.peek(TOK_IPV4):
        return parse_ipv4(tokens)
    elif tokens.peek(TOK_MAC):
        return parse_mac(tokens)
    elif tokens.peek(TOK_STRING):
        return parse_string(tokens)
    elif tokens.peek(TOK_DATE):
        return parse_date(tokens)
    elif tokens.peek(TOK_TRUE, TOK_FALSE):
        return parse_bool(tokens)
    elif tokens.peek(TOK_PLUS, TOK_MINUS, TOK_LNOT):
        return parse_unary(tokens)
    elif tokens.peek(TOK_NAME):
        return parse_load(tokens)
    elif tokens.peek(TOK_CONST):
        return parse_const(tokens)
    elif tokens.peek(TOK_LPAREN):
        return parse_grouping(tokens)
    elif tokens.peek(TOK_NOW):
        return parse_now(tokens)
    # elif tokens.peek(TOK_IN):
    #     return parse_in(tokens)


def parse_in(tokens):
    in_tok = tokens.expect(TOK_IN)
    ip = tokens.expect(TOK_IPV4)
    tokens.expect(TOK_MASK)
    mask = tokens.expect(TOK_INTEGER)

    return BinOp(in_tok.value, 0xc0a80300, 0xc0a803ff)


def parse_now(tokens):
    modifier = 'h'
    offset = 0

    now_tok = tokens.expect(TOK_NOW)
    tokens.expect(TOK_LPAREN)

    if not tokens.peek(TOK_RPAREN):
        tokens.expect(TOK_MINUS)
        offset = tokens.expect(TOK_INTEGER).value

        if tokens.peek(TOK_NAME):
            modifier = tokens.expect(TOK_NAME).value

    tokens.expect(TOK_RPAREN)

    return Now(int(offset), modifier)


def parse_bool(tokens):
    token = tokens.expect(TOK_TRUE, TOK_FALSE)
    return Boolean(token.value)


def parse_unary(tokens):
    optok = tokens.expect(TOK_PLUS, TOK_MINUS, TOK_LNOT)
    factor = parse_factor(tokens)
    return Unary(optok.value, factor)


def parse_source(text):
    tokens = tokenize(text)
    model = parse_select(Tokenizer(tokens))
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
    # print(model)

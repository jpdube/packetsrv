# from packet.layers.ipv4 import IPV4
# import pql.tokens_list as tl
import datetime
import logging
import time

from packet.layers.layer_type import LayerID, from_string
from pql.aggregate import Aggregate, Average, Bandwidth, Count, Max, Min, Sum
from pql.lexer import tokenize
from pql.model import *
from pql.tokens_list import Tokens

index_field = set()
# ip_list = set()
# prev_label = []
prev_ip = 0
ip_search = {'ip.src': [], 'ip.dst': []}
port_search = {'sport': [], 'dport': []}
id = []

log = logging.getLogger("packetdb")


class Tokenizer:
    def __init__(self, tokens):
        self.tokens = tokens
        self.lookahead = None
        self.prev_token = None
        self.prev_label = None

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
                f"""Syntax error at: {line} col: {col} token: {
                    self.lookahead} msg: {error_msg}"""
            )
            raise SyntaxError
        else:
            # if token:
            self.prev_token = self.lookahead
            self.lookahead = None

            if token.value in ['ip.dst', 'ip.src', 'tcp.dport', 'tcp.sport', 'upd.sport', 'udp.dport', 'frame.id']:
                # if token.value in ['ip.dst', 'ip.src']:
                self.prev_label = token.value
            return token


def parse_prog(tokens):
    statements = parse_stmts(tokens)
    tokens.expect(Tokens.TOK_EOF)

    return statements


def parse_stmt(tokens):
    if tokens.peek(Tokens.TOK_NAME):
        return parse_assignment(tokens)
    elif tokens.peek(Tokens.TOK_SELECT):
        return parse_select(tokens)
    elif tokens.peek(Tokens.TOK_NOW):
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
    var_name = tokens.expect(Tokens.TOK_NAME)
    tokens.expect(Tokens.TOK_ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(Tokens.TOK_SEMI)
    return Store(var_name.value, value)


def parse_aggregate(tokens) -> None | Aggregate:

    if tokens.peek(Tokens.TOK_COUNT):
        aggr_tok = tokens.expect(Tokens.TOK_COUNT)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Count(fieldname="", as_of=as_tok.value)

    if tokens.peek(Tokens.TOK_SUM):
        aggr_tok = tokens.expect(Tokens.TOK_SUM)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Sum(fieldname=aggr_tok.value, as_of=as_tok.value)

    if tokens.peek(Tokens.TOK_AVERAGE):
        aggr_tok = tokens.expect(Tokens.TOK_AVERAGE)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Average(fieldname=aggr_tok.value, as_of=as_tok.value)

    if tokens.peek(Tokens.TOK_MIN):
        aggr_tok = tokens.expect(Tokens.TOK_MIN)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Min(fieldname=aggr_tok.value, as_of=as_tok.value)

    if tokens.peek(Tokens.TOK_MAX):
        aggr_tok = tokens.expect(Tokens.TOK_MAX)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Max(fieldname=aggr_tok.value, as_of=as_tok.value)

    if tokens.peek(Tokens.TOK_BANDWIDTH):
        aggr_tok = tokens.expect(Tokens.TOK_BANDWIDTH)
        as_tok = tokens.expect(Tokens.TOK_AS)
        return Bandwidth(fieldname=aggr_tok.value, as_of=as_tok.value)

    return None


def parse_from(tokens):
    tokens.expect(Tokens.TOK_FROM)
    from_fields = []
    while True:
        ffield = tokens.expect(Tokens.TOK_NAME)
        if ffield:
            from_fields.append(ffield.value)
        if tokens.accept(Tokens.TOK_DELIMITER) is None:
            break

    return from_fields


def parse_where(tokens):
    where_value = None
    if tokens.peek(Tokens.TOK_WHERE):
        tokens.expect(Tokens.TOK_WHERE)
        where_value = parse_expression(tokens)

    return where_value


def parse_groupby(tokens):
    groupby_value = None
    if tokens.peek(Tokens.TOK_GROUP_BY):
        tokens.expect(Tokens.TOK_GROUP_BY)
        groupby_value = []
        while True:
            field = tokens.expect(Tokens.TOK_NAME)
            # print(f'SELECT fields: {field}')
            if field:
                groupby_value.append(field.value)

            if tokens.accept(Tokens.TOK_DELIMITER) is None:
                break
    return groupby_value


def parse_orderby(tokens):
    orderby_value = None
    if tokens.peek(Tokens.TOK_ORDER_BY):
        tokens.expect(Tokens.TOK_ORDER_BY)
        orderby_value = []
        while True:
            field = tokens.expect(Tokens.TOK_NAME)
            # print(f'SELECT fields: {field}')
            if field:
                orderby_value.append(field.value)

            if tokens.accept(Tokens.TOK_DELIMITER) is None:
                break
    return orderby_value


def parse_top(tokens):
    top_value = 0
    if tokens.peek(Tokens.TOK_TOP):
        tokens.expect(Tokens.TOK_TOP)
        top_value = int(tokens.expect(Tokens.TOK_INTEGER).value)

    return top_value


def parse_offset(tokens):
    top_value = 0
    if tokens.peek(Tokens.TOK_OFFSET):
        tokens.expect(Tokens.TOK_OFFSET)
        top_value = int(tokens.expect(Tokens.TOK_INTEGER).value)

    return top_value


def parse_limit(tokens):
    limit_fields = []
    if tokens.peek(Tokens.TOK_LIMIT):
        tokens.expect(Tokens.TOK_LIMIT)
        offset = tokens.expect(Tokens.TOK_INTEGER)
        limit_fields.append(offset)
        tokens.expect(Tokens.TOK_DELIMITER)
        limit = tokens.expect(Tokens.TOK_INTEGER)
        limit_fields.append(limit)

    return limit_fields


def parse_select(tokens):
    tokens.expect(Tokens.TOK_SELECT)
    fields = []
    aggregates = []
    distinct = False

    if tokens.peek(Tokens.TOK_DISTINCT):
        distinct = True
        tokens.expect(Tokens.TOK_DISTINCT)

    if tokens.peek(Tokens.TOK_WILDCARD):
        field = tokens.expect(Tokens.TOK_WILDCARD)
        fields.append(Label("*"))
    else:
        while True:
            aggr = parse_aggregate(tokens)
            if aggr:
                aggregates.append(aggr)

            if tokens.peek(Tokens.TOK_NAME):
                field = tokens.expect(Tokens.TOK_NAME)
                if field:
                    fields.append(field.value)
                    # fields.append(Label(field.value))

            if tokens.accept(Tokens.TOK_DELIMITER) is None:
                break

    from_fields = parse_from(tokens)
    where_value = parse_where(tokens)
    groupby_value = parse_groupby(tokens)
    interval_start, interval_end = parse_interval(tokens)
    orderby_value = parse_orderby(tokens)
    top_value = parse_top(tokens)
    offset_value = parse_offset(tokens)
    # limit_fields = parse_limit(tokens)
    tokens.expect(Tokens.TOK_SEMI)

    return SelectStatement(fields,
                           distinct,
                           from_fields,
                           None,
                           index_field,
                           ip_search,
                           where_value,
                           groupby_value,
                           orderby_value,
                           top_value,
                           offset_value,
                           #    limit_fields,
                           (interval_start, interval_end),
                           aggregates,
                           id
                           )


def parse_interval(tokens):
    interval_start = 0
    interval_end = 0
    if tokens.peek(Tokens.TOK_INTERVAL):
        tokens.expect(Tokens.TOK_INTERVAL)
        interval_start = tokens.expect(Tokens.TOK_TIMESTAMP).value
        tokens.expect(Tokens.TOK_TO)
        interval_end = tokens.expect(Tokens.TOK_TIMESTAMP).value

        return (date_to_timestamp(interval_start), date_to_timestamp(interval_end))
    else:
        return (0, 0)


def date_to_timestamp(str_datetime: str) -> int:
    element = datetime.strptime(str_datetime, "%Y-%m-%d %H:%M:%S")
    timestamp = datetime.timestamp(element)

    return int(timestamp)


def parse_date(tokens):
    token = tokens.expect(Tokens.TOK_DATE)
    return Date(token.value)


def parse_string(tokens):
    token = tokens.expect(Tokens.TOK_STRING)
    return String(token.value)


def parse_integer(tokens):
    token = tokens.expect(Tokens.TOK_INTEGER)
    log.debug(f"Prev token: {tokens}, token:{token}")

    if tokens.prev_label is not None and tokens.prev_label == "frame.id":
        log.debug(f"FOUND packet ID: {token.value}")
        id.append(int(token.value))
    # --- Check if value is assigned to an index field
    elif tokens.prev_label is not None:
        log.debug(f"Label: {tokens.prev_label}, {token.value}")
        ip_search[tokens.prev_label.split(".")[1]].append(int(token.value))

    return Integer(token.value)


def parse_array(tokens):
    values = []
    tokens.expect(Tokens.TOK_INDEX_START)
    while True:
        val = tokens.expect(Tokens.TOK_INTEGER)
        values.append(int(val.value))

        if not tokens.peek(Tokens.TOK_DELIMITER):
            tokens.expect(Tokens.TOK_INDEX_END)
            break
        else:
            tokens.expect(Tokens.TOK_DELIMITER)

    if tokens.prev_label is not None and tokens.prev_label == "frame.id":
        global id
        id += values
        log.debug(f"ARRAY OF IDs: {id}")
    else:
        return Array(bytes(values))


def parse_float(tokens):
    token = tokens.expect(Tokens.TOK_FLOAT)
    return Float(token.value)


def parse_ipv4(tokens):
    token = tokens.expect(Tokens.TOK_IPV4)
    mask_value = 32
    if tokens.peek(Tokens.TOK_MASK):
        tokens.accept(Tokens.TOK_MASK)
        mask = tokens.expect(Tokens.TOK_INTEGER)
        mask_value = mask.value

    ip_addr = IPv4(token.value, mask_value)
    if tokens.prev_label is not None:
        ip_search[tokens.prev_label].append((ip_addr.to_int, int(mask_value)))

    return ip_addr


def parse_mac(tokens):
    token = tokens.expect(Tokens.TOK_MAC)
    return Mac(token.value)


def parse_const(tokens):
    name = tokens.expect(Tokens.TOK_CONST)
    index_field.add(name.value)
    const_decl = from_string(name.value)
    log.debug(f"CONSTANT: {const_decl}")
    return ConstDecl(name.value, "int", const_decl)
    # return ConstDecl(name.value, "int", name.value)


def parse_var(tokens):
    tokens.expect(Tokens.TOK_VAR)
    name = tokens.expect(Tokens.TOK_NAME)
    const_type = tokens.accept(Tokens.TOK_NAME)
    if const_type:
        type = const_type.value
    else:
        type = None
    tokens.expect(Tokens.TOK_ASSIGN)
    value = parse_expression(tokens)
    tokens.expect(Tokens.TOK_SEMI)
    return VarDecl(name.value, type, value)


def parse_load(tokens):
    t = tokens.expect(Tokens.TOK_NAME)
    label_name = t.value
    allowed_fields = ["eth", "ip", "tcp", "udp"]
    if tokens.peek(Tokens.TOK_INDEX_START) and label_name in allowed_fields:
        tokens.expect(Tokens.TOK_INDEX_START)
        offset = int(tokens.expect(Tokens.TOK_INTEGER).value)
        tokens.expect(Tokens.TOK_COLON)
        length = int(tokens.expect(Tokens.TOK_INTEGER).value)
        tokens.expect(Tokens.TOK_INDEX_END)
        return LabelByte(label_name, offset, length)

    if "." in label_name:
        index_field.add(t.value.split(".")[0].upper())

    return Label(label_name)


def parse_grouping(tokens):
    tokens.expect(Tokens.TOK_LPAREN)
    expr = parse_expression(tokens)
    tokens.expect(Tokens.TOK_RPAREN)
    return Grouping(expr)


def parse_expression(tokens):
    return parse_or(tokens)


def parse_or(tokens):
    leftval = parse_and(tokens)
    while True:
        optok = tokens.accept(Tokens.TOK_LOR)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_and(tokens))


def parse_and(tokens):
    leftval = parse_relation(tokens)
    while True:
        optok = tokens.accept(Tokens.TOK_LAND)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_relation(tokens))


def parse_relation(tokens):
    leftval = parse_sum(tokens)

    optok = tokens.accept(Tokens.TOK_LT, Tokens.TOK_LE, Tokens.TOK_GT,
                          Tokens.TOK_GE, Tokens.TOK_EQ, Tokens.TOK_NE,
                          Tokens.TOK_IN, Tokens.TOK_BETWEEN,
                          Tokens.TOK_TO, Tokens.TOK_BITSHIFT_LEFT,
                          Tokens.TOK_BITSHIFT_RIGHT, Tokens.TOK_BIT_AND,
                          Tokens.TOK_BIT_OR, Tokens.TOK_BIT_XOR)
    if not optok:
        return leftval
    binop = BinOp(optok.type, leftval, parse_sum(tokens))

    return binop


def parse_sum(tokens):
    leftval = parse_term(tokens)
    while True:
        optok = tokens.accept(Tokens.TOK_PLUS, Tokens.TOK_MINUS)
        if not optok:
            return leftval
        leftval = BinOp(optok.type, leftval, parse_term(tokens))


def parse_term(tokens):
    leftval = parse_factor(tokens)
    while True:
        optok = tokens.accept(Tokens.TOK_TIMES)
        # optok = tokens.accept(Tokens.TOK_TIMES, Tokens.TOK_MASK)
        if not optok:
            return leftval
        leftval = BinOp(optok.value, leftval, parse_factor(tokens))


# def parse_mask(tokens):
#     leftval = parse_factor(tokens)
#     while True:
#         optok = tokens.accept(Tokens.TOK_MASK)
#         if not optok:
#             return leftval
#         leftval = BinOp(optok.value, leftval, parse_factor(tokens))


def parse_factor(tokens):
    if tokens.peek(Tokens.TOK_INTEGER):
        return parse_integer(tokens)
    elif tokens.peek(Tokens.TOK_FLOAT):
        return parse_float(tokens)
    elif tokens.peek(Tokens.TOK_INDEX_START):
        return parse_array(tokens)
    elif tokens.peek(Tokens.TOK_IPV4):
        return parse_ipv4(tokens)
    elif tokens.peek(Tokens.TOK_MAC):
        return parse_mac(tokens)
    elif tokens.peek(Tokens.TOK_STRING):
        return parse_string(tokens)
    elif tokens.peek(Tokens.TOK_DATE):
        return parse_date(tokens)
    elif tokens.peek(Tokens.TOK_TRUE, Tokens.TOK_FALSE):
        return parse_bool(tokens)
    elif tokens.peek(Tokens.TOK_PLUS, Tokens.TOK_MINUS, Tokens.TOK_LNOT):
        return parse_unary(tokens)
    elif tokens.peek(Tokens.TOK_NAME):
        return parse_load(tokens)
    elif tokens.peek(Tokens.TOK_CONST):
        return parse_const(tokens)
    elif tokens.peek(Tokens.TOK_LPAREN):
        return parse_grouping(tokens)
    elif tokens.peek(Tokens.TOK_NOW):
        return parse_now(tokens)
    # elif tokens.peek(Tokens.TOK_IN):
    #     return parse_in(tokens)


def parse_in(tokens):
    in_tok = tokens.expect(Tokens.TOK_IN)
    ip = tokens.expect(Tokens.TOK_IPV4)
    tokens.expect(Tokens.TOK_MASK)
    mask = tokens.expect(Tokens.TOK_INTEGER)

    return BinOp(in_tok.value, 0xc0a80300, 0xc0a803ff)


def parse_now(tokens):
    modifier = 'h'
    offset = 0

    now_tok = tokens.expect(Tokens.TOK_NOW)
    tokens.expect(Tokens.TOK_LPAREN)

    if not tokens.peek(Tokens.TOK_RPAREN):
        tokens.expect(Tokens.TOK_MINUS)
        offset = tokens.expect(Tokens.TOK_INTEGER).value

        if tokens.peek(Tokens.TOK_NAME):
            modifier = tokens.expect(Tokens.TOK_NAME).value

    tokens.expect(Tokens.TOK_RPAREN)

    return Now(int(offset), modifier)


def parse_bool(tokens):
    token = tokens.expect(Tokens.TOK_TRUE, Tokens.TOK_FALSE)
    return Boolean(token.value)


def parse_unary(tokens):
    optok = tokens.expect(Tokens.TOK_PLUS, Tokens.TOK_MINUS, Tokens.TOK_LNOT)
    factor = parse_factor(tokens)
    return Unary(optok.value, factor)


def parse_source(text):
    global index_field
    index_field = set()
    global ip_search
    ip_search = {'ip.src': [], 'ip.dst': [], 'sport': [], 'dport': []}
    global id
    id = []
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

# interp.py
#
# In order to write a compiler for a programming language, it helps to
# have some kind of specification of how programs written in the
# programming language are actually supposed to work. A language is
# more than just "syntax" or a data model.  There has to be some kind
# of operational semantics that describe what happens when a program
# in the language executes.
#
# One way to specify the operational semantics is to write a so-called
# "definitional interpreter" that directly executes the data
# model. This might seem like cheating--after all, our final goal is
# not to write an interpreter, but a compiler. However, if you can't
# write an interpreter, chances are you can't write a compiler either.
# So, the purpose of doing this is to pin down fine details as well as
# our overall understanding of what needs to happen when programs run.
#
# The idea of writing an interpreter is relatively straightforward.
# For each class in the model.py file, you're going to write a
# function similar to this:
#
#    def interpret_node_name(node, env):
#        # Execute "node" in the environment "env"
#        ...
#        return result
#
# The input to the function will be an object from model.py (node)
# along with an object respresenting the state of the execution
# environment (env).  The function will then execute the node in the
# environment and return a result.  It might also modify the
# environment (for example, when executing assignment statements,
# variable definitions, etc.).
#
# For the purposes of this projrect, assume that all programs provided
# as input are "sound"--meaning that there are no programming errors
# in the input. Our purpose is not to create a "production grade"
# interpreter.  We're just trying to understand how things actually
# work when a correct program runs.
#
# For testing, try running your interpreter on the models you
# created in the script_models.py file.
#

from pql.model import *

# Top level function that interprets an entire program. It creates the
# initial environment that's used for storing variables.


def interpret_program(model):
    # Make the initial environment (a dict)
    env = {}
    return interpret(model, env)


# Internal function to interpret a node in the environment

def interpret(node, env):
    # Expand to check for different node types
    # print(node)
    if isinstance(node, Integer):
        return int(node.value)

    elif isinstance(node, Float):
        return float(node.value)

    elif isinstance(node, String):
        return f'"{node.value}"'

    elif isinstance(node, Date):
        return node.timestamp

    elif isinstance(node, Label):
        return node.value

    elif isinstance(node, IPv4):
        return node.to_int

    elif isinstance(node, SelectStatement):
        value = interpret(node.value, env)
        print(value)
        return None

    elif isinstance(node, PrintStatement):
        value = interpret(node.value, env)
        print(value)
        return None

    elif isinstance(node, (VarDecl, ConstDecl)):
        if node.value:
            val = interpret(node.value, env)
        else:
            val = None
        env[node.name] = val
        return None

    elif isinstance(node, Load):
        return env[node.name]

    elif isinstance(node, Store):
        value = interpret(node.value, env)
        env[node.name] = value
        return None

    elif isinstance(node, Unary):
        value = interpret(node.value, env)
        if node.op == "-":
            return value * -1
        elif node.op == "+":
            return value
        elif node.op == "!":
            return not value

    elif isinstance(node, Grouping):
        print(f'Grouping -> {node}')
        return f'({interpret(node.value, env)})'

    elif isinstance(node, Boolean):
        return node.value

    elif isinstance(node, BinOp):
        leftval = interpret(node.left, env)
        rightval = interpret(node.right, env)
        if node.op == "/":
            if rightval == 0:
                return 0
            else:
                return leftval / rightval
        elif node.op == "*":
            return '*'
            # return leftval * rightval
        elif node.op == "+":
            return f'{leftval} + {rightval}'
        elif node.op == "-":
            return f'{leftval} - {rightval}'
        elif node.op == "<":
            return f'{leftval} < {rightval}'
        elif node.op == "<=":
            return f'{leftval} <= {rightval}'
        elif node.op == ">":
            return f'{leftval} > {rightval}'
        elif node.op == ">=":
            return f'{leftval} >= {rightval}'
        elif node.op == "==":
            return f'{leftval} == {rightval}'
        elif node.op == "&&":
            return f'{leftval} AND {rightval}'
        elif node.op == "||":
            return f'{leftval} OR {rightval}'
        elif node.op == "!=":
            return f'{leftval} <> {rightval}'

    elif isinstance(node, IfStatement):
        testval = interpret(node.test, env)
        if testval:
            interpret(node.true_block, env)
        else:
            interpret(node.else_block, env)
        return None

    elif isinstance(node, WhileStatement):
        while interpret(node.test, env):
            try:
                interpret(node.code_block, env)
            except Break:
                break
            except Continue:
                continue
        return None

    elif isinstance(node, BreakStatement):
        print("In break")
        raise Break()

    elif isinstance(node, ContinueStatement):
        print("In continue")
        raise Continue()

    elif isinstance(node, list):
        result = None
        for n in node:
            result = interpret(n, env)
        return result

    raise RuntimeError(f"Can't interpret {node}")


class Break(Exception):
    pass


class Continue(Exception):
    pass

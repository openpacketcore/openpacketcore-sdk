"""Python AST and Go syntax-tree inventory adapters."""

from pathlib import PurePosixPath
import ast
import re

from .model import Function, GuardError
from .execution import constant_bool, executed_nodes, same_value
from .syntax import checked_parse, compact, text, tokens, walk


def python_call(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = python_call(node.value)
        return prefix + '.' + node.attr if prefix else node.attr
    if isinstance(node, ast.Call):
        return python_call(node.func)
    return ''


def python_same(left, right):
    def value(node):
        return isinstance(node, (ast.Name, ast.Constant)) or isinstance(node, ast.Attribute) and value(node.value)

    return value(left) and value(right) and ast.dump(left) == ast.dump(right)


def python_bool(node):
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = python_bool(node.operand)
        return None if value is None else not value
    if isinstance(node, ast.BoolOp):
        values = [python_bool(value) for value in node.values]
        decisive = isinstance(node.op, ast.Or)
        if any(value is decisive for value in values):
            return decisive
        return (not decisive) if all(value is not None for value in values) else None
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        equal = isinstance(node.ops[0], (ast.Eq, ast.Is))
        unequal = isinstance(node.ops[0], (ast.NotEq, ast.IsNot))
        if (equal or unequal) and python_same(node.left, node.comparators[0]):
            return equal
    return None


def python_executed(function):
    """Follow local calls; a nested def or lambda alone executes no checks."""
    deferred = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    active = set()

    def bound(node, bindings):
        return node if isinstance(node, deferred) else bindings.get(node.id) if isinstance(node, ast.Name) else None

    def invoke(node, bindings):
        if node in active:
            return
        active.add(node)
        yield from visit(node.body, dict(bindings))
        active.remove(node)

    def visit(node, bindings):
        if isinstance(node, list):
            for child in node:
                yield from visit(child, bindings)
                if isinstance(child, (ast.Return, ast.Raise)):
                    break
            return
        if isinstance(node, deferred):
            if not isinstance(node, ast.Lambda):
                bindings[node.name] = node
            return
        if isinstance(node, ast.Call):
            local = bound(node.func, bindings)
            if local:
                yield from invoke(local, bindings)
            else:
                yield node
                yield from visit(node.func, bindings)
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                callback = bound(argument, bindings)
                if callback:
                    yield from invoke(callback, bindings)
                else:
                    yield from visit(argument, bindings)
            return
        yield node
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value:
                yield from visit(node.value, bindings)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    closure = bound(node.value, bindings)
                    if closure:
                        bindings[target.id] = closure
                    else:
                        bindings.pop(target.id, None)
            return
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            yield from visit(node.test, bindings)
            value = python_bool(node.test)
            if value is not False:
                yield from visit(node.body, dict(bindings))
            if value is not True or isinstance(node, ast.While):
                yield from visit(node.orelse, dict(bindings))
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                yield from visit(value, bindings)
                if python_bool(value) is isinstance(node.op, ast.Or):
                    break
            return
        for child in ast.iter_child_nodes(node):
            yield from visit(child, bindings)

    yield from visit(function.body, {})


def python_trivial_assertion(node, name):
    if name in {'assertTrue', 'assertFalse'} and node.args:
        return python_bool(node.args[0]) is (name == 'assertTrue')
    return name in {'assertEqual', 'assertIs', 'assertSequenceEqual', 'assertListEqual', 'assertTupleEqual', 'assertDictEqual', 'assertSetEqual', 'assertMultiLineEqual'} and len(node.args) >= 2 and python_same(*node.args[:2])


def python_gates(node):
    gates = set()
    for decorator in [node, *getattr(node, 'decorator_list', [])]:
        if isinstance(decorator, (ast.Name, ast.Attribute)) and python_call(decorator).rsplit('.', 1)[-1] in {'skip', 'skipif', 'skipUnless', 'skipIf', 'xfail'}:
            gates.add(ast.unparse(decorator))
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = python_call(child.func)
            if name.rsplit('.', 1)[-1] in {'skip', 'skipif', 'skipUnless', 'skipIf', 'skipTest', 'xfail'}:
                gates.add(ast.unparse(child))
        if isinstance(child, ast.If):
            condition = ast.unparse(child.test)
            early_return = any(isinstance(n, ast.Return) for n in ast.walk(child))
            if early_return and re.search(r'\b(?:getenv|environ)\b', condition):
                gates.add('early-return:' + condition)
    return gates


def inventory_python(files, inventory):
    for path, source in sorted(files.items()):
        if not path.endswith('.py'):
            continue
        try:
            root = ast.parse(source, filename=path)
        except SyntaxError as error:
            raise GuardError(f'{path}:{error.lineno}: Python parse error: {error.msg}') from error
        unit = 'python:' + str(PurePosixPath(path).parent)
        fixture_file = PurePosixPath(path).name.startswith(('test_', 'test-')) or PurePosixPath(path).name.endswith('_test.py') or 'tests' in PurePosixPath(path).parts

        def items(body, scope, inherited):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    class_gates = set(inherited)
                    for decorator in node.decorator_list:
                        class_gates.update(python_gates(decorator))
                    items(node.body, (*scope, node.name), class_gates)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    count, calls = 0, []
                    for child in python_executed(node):
                        if isinstance(child, ast.Assert):
                            count += python_bool(child.test) is not True
                        elif isinstance(child, ast.Call):
                            name = python_call(child.func)
                            calls.append(name)
                            leaf = name.rsplit('.', 1)[-1]
                            if (leaf.startswith('assert') or leaf in {'raises', 'warns', 'fail'}) and not python_trivial_assertion(child, leaf):
                                count += 1
                    gates = inherited | python_gates(node)
                    for child in node.body[:-1]:
                        if isinstance(child, ast.Return):
                            gates.add('early-return:unconditional')
                    name = '.'.join((*scope, node.name))
                    test = node.name.startswith('test_')
                    inventory.add(Function(f'python:{path}::{name}', node.name, unit, (PurePosixPath(path).stem, *scope), path, node.lineno, test, True, count, calls, gates, production=not (fixture_file or test), runtime_gates=gates - inherited))
                elif isinstance(node, ast.If):
                    condition = ast.unparse(node.test)
                    # The module's test declarations themselves may be gated.
                    items(node.body, scope, inherited | {'declaration-if:' + condition})
                    items(node.orelse, scope, inherited | {'declaration-else:' + condition})

        items(root.body, (), set())


GO_FAILURES = {'Error', 'Errorf', 'Fatal', 'Fatalf', 'Fail', 'FailNow'}


def go_trivial_assertion(node, call):
    if not call.startswith(('assert.', 'require.')):
        return False
    arguments = node.child_by_field_name('arguments')
    values = [tokens(argument) for argument in arguments.named_children][1:] if arguments else []
    name = call.rsplit('.', 1)[-1].removesuffix('f')
    if name in {'True', 'False'} and values:
        return constant_bool(values[0]) is (name == 'True')
    if name in {'Equal', 'EqualValues', 'Same', 'Exactly'} and len(values) >= 2:
        return same_value(*values[:2])
    return name in {'NoError', 'Nil'} and values[:1] == [['nil']]


def inventory_go(files, inventory):
    for path, source in sorted(files.items()):
        if not path.endswith('.go'):
            continue
        parsed = checked_parse('go', path, source)
        root = parsed.root_node
        fixture_file = path.endswith('_test.go')
        package = next((text(n.named_children[0]) for n in root.named_children if n.type == 'package_clause'), '')
        unit = 'go:' + str(PurePosixPath(path).parent) + '::package=' + package
        file_gates = set(re.findall(r'^//(?:go:build|\s*\+build)\s+(.+)$', source, re.M))
        for node in root.named_children:
            if node.type not in {'function_declaration', 'method_declaration'}:
                continue
            name = text(node.child_by_field_name('name'))
            body = node.child_by_field_name('body')
            if not body:
                continue
            calls, gates, count = [], set(file_gates), 0
            for child in executed_nodes(body) if fixture_file else ():
                if child.type == 'call_expression':
                    function = child.child_by_field_name('function')
                    call = text(function)
                    calls.append(call)
                    leaf = call.rsplit('.', 1)[-1]
                    if (leaf in GO_FAILURES or call.startswith(('assert.', 'require.'))) and not go_trivial_assertion(child, call):
                        count += 1
                    if leaf in {'Skip', 'Skipf', 'SkipNow'}:
                        gates.add('skip:' + compact(child))
                elif child.type == 'if_statement':
                    condition = compact(child.child_by_field_name('condition'))
                    if re.search(r'(?:os\.(?:Getenv|LookupEnv)|testing\.Short)', condition) and any(n.type == 'return_statement' for n in walk(child)):
                        gates.add('early-return:' + condition)
            statements = body.named_children[0].named_children if body.named_children and body.named_children[0].type == 'statement_list' else body.named_children
            if any(child.type == 'return_statement' for child in statements[:-1]):
                gates.add('early-return:unconditional')
            receiver = node.child_by_field_name('receiver')
            receiver_type = next((parameter.child_by_field_name('type') for parameter in receiver.named_children), None) if receiver else None
            scope = (text(receiver_type).lstrip('*'),) if receiver_type else ()
            identity = unit + '::' + '::'.join((*scope, name))
            inventory.add(Function(identity, name, unit, scope, path, node.start_point.row + 1, fixture_file and not receiver and bool(re.match(r'Test(?:[^a-z]|$)', name)), fixture_file, count, calls, gates, production=not fixture_file, runtime_gates=gates - file_gates))

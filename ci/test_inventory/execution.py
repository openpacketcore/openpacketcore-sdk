"""Small syntactic reachability checks, without evaluating repository code."""

import ast
import re

from .syntax import COMMENTS, STRINGS, parse, text, tokens


def unparenthesized(values):
    while len(values) >= 2 and values[0] == '(' and values[-1] == ')':
        depth = 0
        for index, token in enumerate(values):
            depth += (token == '(') - (token == ')')
            if depth == 0:
                break
        if index != len(values) - 1:
            break
        values = values[1:-1]
    return values


def split_tokens(values, separator):
    parts, start, depth = [], 0, 0
    for index, token in enumerate(values):
        depth += (token in {'(', '[', '{'}) - (token in {')', ']', '}'})
        if depth == 0 and token == separator:
            parts.append(values[start:index])
            start = index + 1
    return [*parts, values[start:]]


def same_value(left, right):
    """Recognize a repeated literal or value path, never repeated calls.

    This compares operands within one expression, not assertion texts across
    revisions. Calls, indexing and operators may observe different values.
    """
    left, right = unparenthesized(left), unparenthesized(right)
    if left != right or not left:
        return False
    if len(left) == 1:
        return bool(re.fullmatch(r'[\w]+', left[0]) or left[0].startswith(('"', "'", 'r"', 'r#')))
    return all(re.fullmatch(r'[A-Za-z_]\w*', value) if index % 2 == 0 else value in {'.', '::'}
               for index, value in enumerate(left)) and len(left) % 2 == 1


def literal(values):
    values = unparenthesized(values)
    if values in (['true'], ['True']):
        return True
    if values in (['false'], ['False']):
        return False
    if len(values) > 2 or len(values) == 2 and values[0] not in {'-', '+'}:
        return None
    source = ''.join(values)
    source = re.sub(r'(?<=\d)_?(?:[ui](?:8|16|32|64|128|size)|f(?:32|64))$', '', source)
    try:
        value = ast.literal_eval(source)
    except (ValueError, SyntaxError):
        return None
    return value if type(value) in {bool, int, float, str, bytes} else None


def constant_bool(values):
    """Fold obvious Boolean constants and self comparisons only."""
    values = unparenthesized(values)
    if values[:1] == ['{'] and values[-1:] == ['}']:
        # A literal tail value makes the outer assertion trivial; checks in
        # preceding statements are visited independently in the block.
        tail = split_tokens(values[1:-1], ';')[-1]
        if tail in (['true'], ['false']):
            return tail == ['true']
    if values in (['true'], ['True']):
        return True
    if values in (['false'], ['False']):
        return False
    for operator in ('||', '&&'):
        parts = split_tokens(values, operator)
        if len(parts) > 1:
            results = [constant_bool(part) for part in parts]
            decisive = operator == '||'
            if any(value is decisive for value in results):
                return decisive
            return (not decisive) if all(value is not None for value in results) else None
    for operator in ('==', '!=', '<', '<=', '>', '>='):
        parts = split_tokens(values, operator)
        if len(parts) == 2:
            if operator in {'==', '!='} and same_value(*parts):
                return operator == '=='
            left, right = (literal(part) for part in parts)
            if left is not None and right is not None:
                try:
                    if operator == '==':
                        return left == right
                    if operator == '!=':
                        return left != right
                    if operator == '<':
                        return left < right
                    if operator == '<=':
                        return left <= right
                    if operator == '>':
                        return left > right
                    return left >= right
                except TypeError:
                    return None
    if values[:1] in (['!'], ['not']):
        value = constant_bool(values[1:])
        return None if value is None else not value
    return None


def unwrap(node):
    while node and node.type == 'parenthesized_expression' and node.named_children:
        node = node.named_children[0]
    return node


def macro_fragments(node):
    """Parse ordinary Rust blocks embedded in otherwise opaque macro tokens.

    For example, select! has its own branch syntax but each branch's braced
    Rust body still has ordinary if/closure semantics. Never expand macros or
    require their DSL to parse as Rust.
    """
    fragments = []
    group = next((child for child in node.named_children if child.type == 'token_tree'), None)
    if group:
        # Common macros accept ordinary expressions. Parsing their arguments
        # exposes inactive closures/branches without expanding the macro. A
        # callback value alone is inert; only a call within an argument runs it.
        parsed = parse('rust', 'fn __inventory_fragment() { __inventory_arguments(' + text(group)[1:-1] + '); }')
        if not parsed.root_node.has_error:
            body = parsed.root_node.named_children[0].child_by_field_name('body')
            arguments = body.named_children[0].named_children[0].child_by_field_name('arguments')
            name = text(node.child_by_field_name('macro')).rsplit('::', 1)[-1]
            # Assertion diagnostics run only after a failed check, and cannot
            # independently strengthen it. Inspect the checked operands only.
            limit = 1 if name in {'assert', 'debug_assert'} else 2 if name in {'assert_eq', 'assert_ne', 'debug_assert_eq', 'debug_assert_ne'} else None
            return [(group, argument) for argument in arguments.named_children[:limit]]

    def visit(group):
        if group.type == 'token_tree' and group.children and text(group.children[0]) == '{':
            parsed = parse('rust', 'fn __inventory_fragment() ' + text(group))
            if not parsed.root_node.has_error:
                body = parsed.root_node.named_children[0].child_by_field_name('body')
                fragments.append((group, body))
                return
        if group.type not in COMMENTS | STRINGS:
            for child in group.named_children:
                visit(child)

    visit(node)
    return fragments


def executed_nodes(root):
    """Walk Rust/Go executable syntax, expanding locally invoked closures.

    Inline callbacks and closures passed to a call escape to that callee, so
    their bodies remain reachable. An arbitrary callee's callback semantics
    require review. Merely binding, referencing or dropping a closure does not
    execute it. Dead branches cannot make a closure reachable.
    """
    deferred = {'closure_expression', 'func_literal', 'function_item'}
    active = set()

    def stores_callback(function):
        return text(function).rsplit('::', 2)[-2:] in (['Box', 'new'], ['Arc', 'new'], ['Rc', 'new']) or text(function) in {'Some', 'Ok'}

    def bound(node, bindings):
        node = unwrap(node)
        if node and node.type in deferred:
            return node
        if node and node.type == 'call_expression' and stores_callback(node.child_by_field_name('function')):
            arguments = node.child_by_field_name('arguments')
            if arguments and len(arguments.named_children) == 1:
                return bound(arguments.named_children[0], bindings)
        return bindings.get(text(node)) if node and node.type == 'identifier' else None

    def invoke(node, bindings):
        identity = node.raw.id
        if identity in active:
            return
        active.add(identity)
        yield node
        body = node.child_by_field_name('body')
        if body:
            yield from visit(body, bindings)
        active.remove(identity)

    def visit(node, bindings):
        if node.type in deferred:
            return
        if node.type == 'call_expression':
            function = node.child_by_field_name('function')
            local = bound(function, bindings)
            if local:
                yield from invoke(local, bindings)
            else:
                yield node
                if function:
                    yield from visit(function, bindings)
            arguments = node.child_by_field_name('arguments')
            for argument in arguments.named_children if arguments else ():
                callback = bound(argument, bindings)
                if callback and not stores_callback(function) and text(function) not in {'drop', 'forget', 'std::mem::drop', 'std::mem::forget', 'std::hint::black_box'}:
                    yield from invoke(callback, bindings)
                else:
                    yield from visit(argument, bindings)
            return
        yield node
        if node.type == 'macro_invocation':
            for _, fragment in macro_fragments(node):
                yield from visit(fragment, dict(bindings))
            return
        if node.type in COMMENTS | STRINGS:
            return
        if node.type in {'block', 'statement_list'}:
            scope = dict(bindings)
            for child in node.named_children:
                if child.type == 'function_item':
                    scope[text(child.child_by_field_name('name'))] = child
            conditional = False
            for child in node.named_children:
                yield from visit(child, scope)
                if child.type == 'attribute_item':
                    conditional = True
                    continue
                if child.type in {'return_statement', 'return_expression'} and not conditional:
                    break
                if child.type == 'expression_statement' and child.named_children and child.named_children[0].type == 'return_expression' and not conditional:
                    break
                conditional = False
            return
        if node.type in {'let_declaration', 'short_var_declaration', 'var_spec', 'assignment_statement'}:
            pattern = node.child_by_field_name('pattern') or node.child_by_field_name('left') or node.child_by_field_name('name')
            value = node.child_by_field_name('value') or node.child_by_field_name('right')
            names = pattern.named_children if pattern and pattern.type == 'expression_list' else [pattern]
            values = value.named_children if value and value.type == 'expression_list' else [value]
            for value in values:
                if value:
                    yield from visit(value, bindings)
            for name, value in zip(names, values):
                if name and name.type == 'identifier':
                    closure = bound(value, bindings)
                    if closure:
                        bindings[text(name)] = closure
                    else:
                        bindings.pop(text(name), None)
            return
        if node.type in {'if_expression', 'if_statement', 'while_expression', 'for_statement'}:
            condition = node.child_by_field_name('condition')
            if node.type == 'for_statement' and not condition:
                clause = next((child for child in node.named_children if child.type != 'block'), None)
                condition = clause.child_by_field_name('condition') if clause and clause.type == 'for_clause' else clause
            if condition:
                value = constant_bool(tokens(condition))
                consequence = node.child_by_field_name('consequence') or node.child_by_field_name('body')
                alternative = node.child_by_field_name('alternative')
                for child in node.named_children:
                    if (child == consequence and value is False) or (child == alternative and value is True):
                        continue
                    yield from visit(child, dict(bindings))
                return
        if node.type == 'binary_expression':
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            operator = text(node.child_by_field_name('operator'))
            if left and right and operator in {'&&', '||'}:
                yield from visit(left, bindings)
                value = constant_bool(tokens(left))
                if value is None or value == (operator == '&&'):
                    yield from visit(right, bindings)
                return
        for child in node.named_children:
            yield from visit(child, bindings)

    yield from visit(root, {})

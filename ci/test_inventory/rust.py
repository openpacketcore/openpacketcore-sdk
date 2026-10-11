"""Inventory Rust test targets and their module trees without invoking Cargo."""

from pathlib import PurePosixPath
import posixpath
import re
import tomllib

from .model import Function, GuardError
from .execution import constant_bool, executed_nodes, macro_fragments, same_value, split_tokens
from .syntax import COMMENTS, STRINGS, checked_parse, compact, text, tokens, walk


TEST_ATTRIBUTES = {'test', 'rstest', 'test_case'}
ASSERTIONS = {'assert', 'assert_eq', 'assert_ne', 'assert_matches', 'debug_assert', 'debug_assert_eq', 'debug_assert_ne', 'debug_assert_matches'}
RESULT_ASSERTIONS = {'expect', 'unwrap', 'expect_err', 'unwrap_err'}
ATOMIC_METHODS = {'load', 'store', 'swap', 'compare_exchange', 'compare_exchange_weak', 'fetch_add', 'fetch_sub', 'fetch_and', 'fetch_or', 'fetch_xor', 'fetch_update', 'fetch_max', 'fetch_min'}


def attribute_name(attribute):
    node = attribute.named_children[0]
    return text(node.named_children[0]).rsplit('::', 1)[-1]


def is_test(attributes):
    for attribute in attributes:
        name = attribute_name(attribute)
        if name in TEST_ATTRIBUTES:
            return True
        if name == 'cfg_attr' and re.search(r'[,()]\s*(?:\w+::)*(?:test|rstest|test_case)(?:[,()]|\])', text(attribute)):
            return True
    return False


def attribute_gates(attributes):
    gates = set()
    for attribute in attributes:
        name, value = attribute_name(attribute), compact(attribute)
        if name == 'ignore':
            gates.add('#[ignore]')
        elif name == 'cfg' and value not in {'#[cfg(test)]', '#![cfg(test)]'}:
            gates.add(value)
        elif name == 'cfg_attr' and re.search(r'\b(?:cfg|ignore|test|rstest)\b', value[len('#[cfg_attr('):]):
            gates.add(value)
    return gates


def call_name(node):
    function = node.child_by_field_name('function')
    if function and function.type == 'generic_function':
        function = function.child_by_field_name('function')
    if function and function.type == 'field_expression':
        return text(function.child_by_field_name('field'))
    return text(function)


def result_assertion(node):
    name = call_name(node)
    if name not in RESULT_ASSERTIONS and name != 'unwrap_or_else':
        return False
    function = node.child_by_field_name('function')
    receiver = function.child_by_field_name('value') if function else None
    # Poison handling for a fixture mutex is not a result-under-test assertion.
    if receiver and receiver.type == 'call_expression' and call_name(receiver) == 'lock':
        return False
    if name == 'unwrap_or_else':
        # A panic-on-error diagnostic is the same assertion as expect/unwrap.
        arguments = node.child_by_field_name('arguments')
        return any(n.type == 'macro_invocation' and text(n.child_by_field_name('macro')).rsplit('::', 1)[-1] == 'panic' for n in walk(arguments))
    return True


def declared_type(node):
    if not node:
        return None
    if node.type in {'reference_type', 'pointer_type'}:
        return declared_type(node.child_by_field_name('type'))
    if node.type == 'generic_type':
        base = text(node.child_by_field_name('type'))
        arguments = node.child_by_field_name('type_arguments')
        if base.rsplit('::', 1)[-1] in {'Arc', 'Rc', 'Box', 'Option', 'Result'} and arguments and arguments.named_children:
            return declared_type(arguments.named_children[0])
        return base
    value = text(node)
    return value if re.fullmatch(r'(?:[A-Za-z_]\w*::)*[A-Z]\w*', value) else None


def expression_type(node, bindings):
    """Recognize explicit types and simple fixture constructors, not type-check."""
    if not node:
        return None
    if node.type == 'identifier':
        return bindings.get(text(node))
    if node.type in {'await_expression', 'try_expression', 'reference_expression', 'parenthesized_expression'}:
        return expression_type(node.named_children[0], bindings) if node.named_children else None
    if node.type == 'struct_expression':
        return declared_type(node.child_by_field_name('name'))
    if node.type != 'call_expression':
        return None
    function = node.child_by_field_name('function')
    if function and function.type == 'generic_function':
        function = function.child_by_field_name('function')
    if function and function.type == 'field_expression':
        if text(function.child_by_field_name('field')) in {'unwrap', 'expect', 'unwrap_or_default', 'clone', 'as_ref', 'as_mut'}:
            return expression_type(function.child_by_field_name('value'), bindings)
        return None
    path = text(function).split('::')
    if len(path) < 2:
        return 'return=' + text(function)
    owner = path[-2]
    if owner in {'Arc', 'Rc', 'Box', 'Option', 'Result'}:
        arguments = node.child_by_field_name('arguments')
        return expression_type(arguments.named_children[0], bindings) if arguments and arguments.named_children else None
    return '::'.join(path[:-1]) if re.fullmatch(r'[A-Z]\w*', owner) else 'return=' + text(function)


def helper_call(node, bindings):
    name = call_name(node)
    function = node.child_by_field_name('function')
    if function and function.type == 'generic_function':
        function = function.child_by_field_name('function')
    if function and function.type == 'field_expression':
        # These calls already contribute one result assertion. Without receiver
        # types, following a same-named fixture method would double-count them.
        if name in RESULT_ASSERTIONS or name == 'unwrap_or_else':
            return None
        receiver = function.child_by_field_name('value')
        # Atomic operations do not call similarly named fixture accessors.
        if name in ATOMIC_METHODS and re.search(r'\bOrdering::', compact(node.child_by_field_name('arguments'))):
            return None
        owner = 'Self' if text(receiver) == 'self' else expression_type(receiver, bindings)
        return '@method:' + (owner + '::' if owner else '') + name
    return name


def trivial_assertion(name, arguments):
    if name in {'assert', 'debug_assert'}:
        return bool(arguments) and constant_bool(arguments[0]) is True
    if name in {'assert_eq', 'debug_assert_eq'}:
        return len(arguments) >= 2 and (same_value(arguments[0], arguments[1]) or constant_bool([*arguments[0], '==', *arguments[1]]) is True)
    if name in {'assert_ne', 'debug_assert_ne'} and len(arguments) >= 2:
        return constant_bool([*arguments[0], '!=', *arguments[1]]) is True
    return False


def macro_tokens(node):
    """Remove trivially successful checks, including their lazy diagnostics."""
    original = tokens(node)
    name = text(node.child_by_field_name('macro')).rsplit('::', 1)[-1]
    argument_start = next((index for index, value in enumerate(original) if value in {'(', '{', '['}), len(original))
    if name in ASSERTIONS and trivial_assertion(name, split_tokens(original[argument_start + 1:-1], ',')):
        return []
    expanded = {group.raw.id for group, _ in macro_fragments(node)}

    def opaque(group):
        if group.raw.id in expanded or group.type in COMMENTS:
            return []
        if group.type in STRINGS or not group.children:
            return [text(group)]
        return [value for child in group.children for value in opaque(child)]

    values = opaque(node)
    result, index = [], 0
    while index < len(values):
        name = values[index]
        if name in ASSERTIONS and values[index + 1:index + 2] == ['!'] and values[index + 2:index + 3] in (['('], ['{'], ['[']):
            end, depth = index + 3, 1
            while end < len(values) and depth:
                depth += (values[end] in {'(', '{', '['}) - (values[end] in {')', '}', ']'})
                end += 1
            if not depth and trivial_assertion(name, split_tokens(values[index + 3:end - 1], ',')):
                index = end
                continue
        result.append(name)
        index += 1
    return result


def macro_calls(values, bindings):
    """Expressions inside macro token trees still contain result assertions."""
    calls, count = [], 0
    for index, name in enumerate(values):
        if not re.fullmatch(r'[A-Za-z_]\w*', name) or values[index + 1:index + 2] != ['(']:
            continue
        if values[index - 1:index] == ['.']:
            if name not in RESULT_ASSERTIONS and name != 'unwrap_or_else':
                end, depth = index + 2, 1
                while end < len(values) and depth:
                    depth += (values[end] == '(') - (values[end] == ')')
                    end += 1
                if name in ATOMIC_METHODS and 'Ordering' in values[index + 2:end]:
                    continue
                receiver = values[index - 2] if index >= 2 else ''
                owner = 'Self' if receiver == 'self' else bindings.get(receiver)
                calls.append('@method:' + (owner + '::' if owner else '') + name)
        else:
            start = index
            while start >= 2 and values[start - 1] == '::' and re.fullmatch(r'[A-Za-z_]\w*', values[start - 2]):
                start -= 2
            calls.append(''.join(values[start:index + 1]))
        if name in RESULT_ASSERTIONS and values[index - 1:index] == ['.']:
            if values[max(0, index - 4):index] != ['lock', '(', ')', '.']:
                count += 1
        if name == 'unwrap_or_else' and values[index - 1:index] == ['.']:
            depth, finish = 1, index + 2
            while finish < len(values) and depth:
                depth += (values[finish] == '(') - (values[finish] == ')')
                finish += 1
            arguments = values[index + 2:finish - 1]
            count += any(value == 'panic' and arguments[i + 1:i + 2] == ['!'] for i, value in enumerate(arguments))
    return calls, count


def checked_child_reexecution(node, bindings, test_name):
    """Recognize the checked, same-test libtest child-launch idiom."""
    condition = node.child_by_field_name('condition')
    source = compact(node)
    marker = re.search(r'(?:std::)?env::(?:var|var_os)\(([^()]+)\)\.(?:is_none|is_err)\(\)', compact(condition)) if condition else None
    if not marker or 'current_exe()' not in source or '.env(' + marker[1] + ',' not in source:
        return False
    for name, value in bindings.items():
        if value.startswith('"') and value.endswith('"'):
            source = re.sub(r'\b' + re.escape(name) + r'\b', lambda _: value, source)
    exact = re.search(r'\.args\(\["--exact","([^"\n]+)"', source)
    if not exact or exact[1] != test_name:
        return False
    launched = re.search(r'let(?:mut)?(\w+)=.*?Command::new\(.*?current_exe\(\).*?\.(?:test_output|output|status)\(\)\.(?:unwrap\(\)|expect\([^;]+\));', source)
    return bool(launched and re.search(r'assert!\(' + re.escape(launched[1]) + r'\.(?:status\.)?success\(\)', source))


def checked_callback_assertions(closure):
    """Count error checks in an inline callback with a checked outer Result.

    Test helpers can move an unwrap and an assertion into a fallible callback,
    expressing them as `?` and a conditional `return Err(...)`. The enclosing
    invocation must check success, not discard the Result or expect an error.
    As with assertion macros inside closures, syntax cannot prove that an
    arbitrary wrapper invokes the callback and forwards its errors.
    """
    arguments = closure.parent
    call = arguments.parent if arguments and arguments.type == 'arguments' else None
    if not call or call.type != 'call_expression':
        return 0
    parent = call.parent
    while parent and parent.type in {'await_expression', 'parenthesized_expression'}:
        call, parent = parent, parent.parent
    assertion = parent.parent if parent and parent.type == 'field_expression' else None
    if not assertion or assertion.type != 'call_expression' or call_name(assertion) not in {'unwrap', 'expect', 'unwrap_or_else'} or not result_assertion(assertion):
        return 0
    body = closure.child_by_field_name('body')
    if not body:
        return 0
    count = 0
    for node in executed_nodes(body):
        if node.type == 'try_expression':
            count += 1
        elif node.type == 'if_expression' and constant_bool(tokens(node.child_by_field_name('condition'))) is not False:
            consequence = node.child_by_field_name('consequence')
            for candidate in executed_nodes(consequence) if consequence else ():
                if candidate.type != 'return_expression' or not candidate.named_children:
                    continue
                returned = candidate.named_children[0]
                if returned.type == 'call_expression' and call_name(returned).rsplit('::', 1)[-1] == 'Err':
                    count += 1
                    break
    return count


def body_info(body, parameters, test_name=''):
    assertions, calls, gates, signatures = 0, [], set(), set()
    nodes = list(executed_nodes(body))
    bindings = {}
    receiver_types = {}
    for parameter in parameters.named_children if parameters else ():
        name = text(parameter.child_by_field_name('pattern'))
        owner = declared_type(parameter.child_by_field_name('type'))
        if name and owner:
            receiver_types[name] = owner
    for node in nodes:
        if node.type in {'let_declaration', 'const_item'}:
            name = node.child_by_field_name('pattern') or node.child_by_field_name('name')
            value = node.child_by_field_name('value')
            if name and value and value.type == 'string_literal':
                bindings[text(name)] = compact(value)
            if name:
                owner = declared_type(node.child_by_field_name('type')) or expression_type(value, receiver_types)
                if owner:
                    receiver_types[text(name)] = owner
    for node in nodes:
        if node.type == 'closure_expression':
            assertions += checked_callback_assertions(node)
        if node.type == 'macro_invocation':
            values = macro_tokens(node)
            assertions += sum(name in ASSERTIONS and values[i + 1:i + 2] == ['!'] for i, name in enumerate(values))
            nested_calls, nested_count = macro_calls(values, receiver_types)
            calls.extend(nested_calls)
            assertions += nested_count
            if values and text(node.child_by_field_name('macro')).rsplit('::', 1)[-1] in ASSERTIONS:
                signatures.add(compact(node))
        if node.type == 'let_declaration':
            bindings[text(node.child_by_field_name('pattern'))] = compact(node.child_by_field_name('value')) if node.child_by_field_name('value') else ''
        if node.type == 'call_expression':
            call = helper_call(node, receiver_types)
            if call:
                calls.append(call)
            if result_assertion(node):
                assertions += 1
                name = call_name(node)
                # A named expectation survives observer implementation changes.
                # Unnamed unwraps need the full expression to identify a check.
                signatures.add(name + compact(node.child_by_field_name('arguments')) if name in {'expect', 'expect_err'} else compact(node))
        if node.type in {'if_expression', 'match_expression'}:
            condition = node.child_by_field_name('condition') or node.child_by_field_name('value')
            value = compact(condition) if condition else ''
            for identifier in re.findall(r'\b[A-Za-z_]\w*\b', value):
                value += bindings.get(identifier, '')
            early_return = any(n.type == 'return_expression' for n in walk(node))
            if early_return and re.search(r'(?:env::(?:var|var_os)|option_env!|env!|cfg!)', value) and not checked_child_reexecution(node, bindings, test_name):
                gates.add('early-return:' + value)
    pending = []
    for child in body.named_children:
        if child.type == 'attribute_item':
            pending.append(child)
            continue
        conditional = bool(attribute_gates(pending))
        pending = []
        if any(n.type == 'return_expression' for n in walk(child)) and not any(n.type in {'if_expression', 'match_expression', 'closure_expression', 'loop_expression', 'for_expression', 'while_expression'} for n in walk(child)):
            # Explicit return expressions at the end of helper functions are
            # normal. Only a return preceding more statements switches tests off.
            if child != body.named_children[-1] and not conditional:
                gates.add('early-return:unconditional')
    return assertions, calls, gates, signatures


def inventory_rust(files, inventory):
    visited = set()

    def module(path, unit, names, inherited_gates, test_context, directory=None):
        path = posixpath.normpath(path)
        key = path, unit, names, tuple(sorted(inherited_gates))
        if key in visited:
            return
        visited.add(key)
        if path not in files:
            raise GuardError(f'{path}: declared Rust module is missing')
        parsed = checked_parse('rust', path, files[path])
        root = parsed.root_node
        directory = directory or (str(PurePosixPath(path).parent) if PurePosixPath(path).name in {'lib.rs', 'main.rs', 'mod.rs'} else str(PurePosixPath(path).with_suffix('')))

        def items(node, scope, module_directory, gates, support, inline=False, method=False):
            pending = []
            inner = [n for n in node.named_children if n.type == 'inner_attribute_item']
            gates = gates | attribute_gates(inner)
            support = support or any('test' in tokens(a) for a in inner)
            for child in node.named_children:
                if child.type == 'attribute_item':
                    pending.append(child)
                    continue
                if child.type in COMMENTS or child.type == 'inner_attribute_item':
                    continue
                attributes, pending = pending, []
                child_gates = gates | attribute_gates(attributes)
                child_support = support or any(attribute_name(a) == 'cfg' and 'test' in tokens(a) for a in attributes)
                if child.type == 'mod_item':
                    name = text(child.child_by_field_name('name'))
                    body = child.child_by_field_name('body')
                    explicit = []
                    for attribute in attributes:
                        if attribute_name(attribute) == 'path':
                            value = attribute.named_children[0].child_by_field_name('value')
                            if value and value.type == 'string_literal':
                                explicit.append(text(value)[1:-1])
                    path_base = module_directory if inline else str(PurePosixPath(path).parent)
                    if body:
                        child_directory = posixpath.join(path_base, explicit[0]) if explicit else posixpath.join(module_directory, name)
                        items(body, (*scope, name), child_directory, child_gates, child_support, True)
                    else:
                        if explicit:
                            candidates = [posixpath.normpath(posixpath.join(path_base, relative)) for relative in explicit]
                        else:
                            candidates = [posixpath.join(module_directory, name + '.rs'), posixpath.join(module_directory, name, 'mod.rs')]
                        present = [candidate for candidate in candidates if candidate in files]
                        if not present:
                            raise GuardError(f'{path}:{child.start_point.row + 1}: module {name} has no source in the Git tree')
                        for candidate in present:
                            module(candidate, unit, (*scope, name), child_gates, child_support)
                elif child.type == 'impl_item':
                    impl_type = text(child.child_by_field_name('type')).split('<', 1)[0]
                    body = child.child_by_field_name('body')
                    if body:
                        items(body, (*scope, impl_type), module_directory, child_gates, child_support, inline, True)
                elif child.type == 'function_item':
                    name = text(child.child_by_field_name('name'))
                    body = child.child_by_field_name('body')
                    test = is_test(attributes)
                    count, calls, body_gates, signatures = body_info(body, child.child_by_field_name('parameters'), '::'.join((*scope, name)) if test else '') if child_support or test else (0, [], set(), set())
                    function_id = unit + '::' + '::'.join((*scope, name))
                    inventory.add(Function(function_id, name, unit, scope, path, child.start_point.row + 1, test, child_support or test, count, calls, child_gates | body_gates, production=not (child_support or test), method=method, runtime_gates=body_gates, assertion_signatures=signatures, return_type=declared_type(child.child_by_field_name('return_type'))))
                elif child.type == 'macro_invocation' and text(child.child_by_field_name('macro')) == 'include':
                    literal = next((n for n in walk(child) if n.type == 'string_literal'), None)
                    if literal:
                        included = posixpath.normpath(posixpath.join(str(PurePosixPath(path).parent), text(literal)[1:-1]))
                        if included in files:
                            module(included, unit, scope, child_gates, child_support, module_directory)

        items(root, names, directory, inherited_gates, test_context)

    for manifest_path, source in sorted(files.items()):
        if PurePosixPath(manifest_path).name != 'Cargo.toml':
            continue
        try:
            manifest = tomllib.loads(source)
        except tomllib.TOMLDecodeError as error:
            raise GuardError(f'{manifest_path}: invalid Cargo manifest: {error}') from error
        if 'package' not in manifest:
            continue
        crate = str(PurePosixPath(manifest_path).parent)
        package = manifest['package']
        roots = []

        def add(kind, name, path, options=None, discovery=None):
            options = options or {}
            path = posixpath.normpath(posixpath.join(crate, path))
            if path not in files:
                if 'path' in options:
                    raise GuardError(f'{manifest_path}: target {path} is missing')
                return
            gates = set()
            if options.get('test') is False:
                gates.add('Cargo:test=false')
            gates.update('Cargo:required-feature=' + feature for feature in options.get('required-features', []))
            if discovery and package.get(discovery) is False:
                gates.add('Cargo:' + discovery + '=false')
            roots.append((kind, name, path, gates))

        library = manifest.get('lib', {})
        add('lib', 'lib', library.get('path', 'src/lib.rs'), library, None if 'lib' in manifest else 'autolib')
        binaries = manifest.get('bin', [])
        binary_names = {binary['name'] for binary in binaries}
        if package['name'] not in binary_names:
            add('bin', package['name'], 'src/main.rs', discovery='autobins')
        bin_prefix = (crate + '/' if crate != '.' else '') + 'src/bin/'
        for path in files:
            if not path.startswith(bin_prefix) or not path.endswith('.rs'):
                continue
            relative = path[len(bin_prefix):]
            if '/' not in relative:
                name = relative[:-3]
            elif relative.count('/') == 1 and relative.endswith('/main.rs'):
                name = relative.split('/')[0]
            else:
                continue
            if name not in binary_names:
                add('bin', name, 'src/bin/' + relative, discovery='autobins')
        for binary in binaries:
            default_path = 'src/main.rs' if binary['name'] == package['name'] else 'src/bin/' + binary['name'] + '.rs'
            if posixpath.join(crate, default_path) not in files:
                default_path = 'src/bin/' + binary['name'] + '/main.rs'
            add('bin', binary['name'], binary.get('path', default_path), binary)
        explicit_tests = manifest.get('test', [])
        explicit_names = {target['name'] for target in explicit_tests}
        prefix = (crate + '/' if crate != '.' else '') + 'tests/'
        for path in files:
            if not path.startswith(prefix) or not path.endswith('.rs'):
                continue
            relative = path[len(prefix):]
            if '/' not in relative:
                name = relative[:-3]
            elif relative.count('/') == 1 and relative.endswith('/main.rs'):
                name = relative.split('/')[0]
            else:
                continue
            if name not in explicit_names:
                add('test', name, 'tests/' + relative, discovery='autotests')
        for target in explicit_tests:
            add('test', target['name'], target.get('path', 'tests/' + target['name'] + '.rs'), target)
        for kind, name, path, gates in roots:
            unit = f'rust:{crate}::{kind}={name}'
            # Integration crate roots use their containing directory for mod x;
            # unlike a non-root x.rs module, they do not imply an x/ directory.
            module(path, unit, (), gates, kind == 'test', str(PurePosixPath(path).parent))

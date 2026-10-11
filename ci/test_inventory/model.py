"""Common, language-independent inventory records."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field


class GuardError(ValueError):
    """An input could not be checked; never treat this as an empty inventory."""


@dataclass
class Function:
    id: str
    name: str
    unit: str
    module: tuple[str, ...]
    file: str
    line: int
    test: bool = False
    support: bool = False
    assertions: int = 0
    calls: list[str] = field(default_factory=list)
    gates: set[str] = field(default_factory=set)
    production: bool = False
    method: bool = False
    runtime_gates: set[str] = field(default_factory=set)
    assertion_signatures: set[str] = field(default_factory=set)
    return_type: str | None = None


@dataclass
class Inventory:
    functions: dict[str, Function] = field(default_factory=dict)
    tests: dict[str, Function] = field(default_factory=dict)
    # Multiple cfg variants can define one libtest name. Retain every variant.
    variants: dict[str, list[Function]] = field(default_factory=lambda: defaultdict(list))

    def add(self, function):
        self.variants[function.id].append(function)
        if function.id not in self.functions:
            self.functions[function.id] = function
        else:
            existing = self.functions[function.id]
            existing.assertions += function.assertions
            existing.calls.extend(function.calls)
            existing.gates.update(function.gates)
            existing.runtime_gates.update(function.runtime_gates)
            existing.assertion_signatures.update(function.assertion_signatures)
        if function.test:
            self.tests[function.id] = self.functions[function.id]

    def resolve_calls(self):
        """Resolve local test helpers, conservatively avoiding ambiguous methods.

        This is a syntactic call graph, not type checking. Rust method calls
        cannot resolve to free functions, and qualified calls must match their
        qualifier. Ambiguous methods and production callees are excluded.
        """
        by_name = defaultdict(list)
        factories = defaultdict(list)
        for function in self.functions.values():
            if function.return_type:
                factories[function.unit, function.name].append(function)
            if function.support and not function.test:
                by_name[function.unit, function.name].append(function)
        edges = {}
        for function in self.functions.values():
            resolved = []
            for call in function.calls:
                method = call.startswith('@method:')
                if method:
                    call = call[len('@method:'):]
                name = call.rsplit('::', 1)[-1].rsplit('.', 1)[-1]
                options = by_name[function.unit, name]
                if function.unit.startswith('rust:'):
                    if method:
                        options = [f for f in options if f.method]
                        if call.startswith('Self::') and function.method:
                            options = [f for f in options if f.module == function.module]
                        elif '::' in call:
                            owner = call.rsplit('::', 1)[0]
                            if owner.startswith('return='):
                                factory_name = owner[len('return='):]
                                constructors = factories[function.unit, factory_name.rsplit('::', 1)[-1]]
                                if '::' in factory_name:
                                    qualifier = tuple(factory_name.split('::')[:-1])
                                    if qualifier[0] == 'crate':
                                        qualifier = qualifier[1:]
                                    constructors = [f for f in constructors if f.module[-len(qualifier):] == qualifier]
                                types = {'::'.join(f.module) if f.return_type == 'Self' and f.method else f.return_type for f in constructors}
                                owner = next(iter(types)) if len(types) == 1 else None
                            qualifier = tuple(owner.split('::')) if owner else ()
                            if qualifier and qualifier[0] == 'crate':
                                qualifier = qualifier[1:]
                            options = [f for f in options if qualifier and f.module[-len(qualifier):] == qualifier]
                        else:
                            # A unique method elsewhere in the target need not
                            # belong to this receiver (e.g. Semaphore vs a test
                            # fixture's available_permits). Without a receiver
                            # type, only consider this exact lexical module.
                            scope = function.module[:-1] if function.method else function.module
                            options = [f for f in options if f.module[:-1] == scope]
                    elif '::' in call:
                        qualifier = tuple(call.split('::')[:-1])
                        if qualifier[0] == 'Self' and function.method:
                            qualifier = (*function.module, *qualifier[1:])
                        elif qualifier[0] == 'crate':
                            qualifier = qualifier[1:]
                        elif qualifier[0] in {'self', 'super'}:
                            scope = function.module[:-1] if function.method else function.module
                            while qualifier and qualifier[0] in {'self', 'super'}:
                                if qualifier[0] == 'super':
                                    scope = scope[:-1]
                                qualifier = qualifier[1:]
                            qualifier = (*scope, *qualifier)
                        options = [f for f in options if not qualifier or f.module[-len(qualifier):] == qualifier]
                    else:
                        options = [f for f in options if not f.method]
                if len(options) == 1:
                    resolved.append(options[0].id)
                    continue
                for depth in range(len(function.module), -1, -1):
                    nearby = [f for f in options if (f.module[:-1] if method else f.module) == function.module[:depth]]
                    if len(nearby) == 1:
                        resolved.append(nearby[0].id)
                        break
            edges[function.id] = resolved
        return edges

    def coverage(self):
        edges = self.resolve_calls()
        result = {}
        for test_id in self.tests:
            reachable = set()
            active = set()

            def visit(function_id):
                if function_id in active:
                    return 0
                active.add(function_id)
                reachable.add(function_id)
                function = self.functions[function_id]
                count = function.assertions
                for callee in edges[function_id]:
                    count += visit(callee)
                active.remove(function_id)
                return count

            assertions = visit(test_id)
            # A cfg on a helper selects its implementation; it does not remove
            # a caller from libtest. Runtime skips in helpers still propagate.
            gates = set(self.functions[test_id].gates)
            gates.update(set().union(*(self.functions[name].runtime_gates for name in reachable)))
            helpers = {name for name in reachable if name != test_id and self.functions[name].assertions}
            signatures = set().union(*(self.functions[name].assertion_signatures for name in reachable))
            result[test_id] = dict(assertions=assertions, gates=gates, helpers=helpers, signatures=signatures)
        return result


@dataclass
class Finding:
    subject: str
    kind: str
    file: str
    line: int
    detail: str
    side: str = 'head'
    allowed: bool = False
    reason: str | None = None
    issue: int | None = None

    def key(self):
        return self.subject, self.kind


@dataclass
class Report:
    findings: list[Finding]
    errors: list[str]
    base_tests: int
    head_tests: int

    @property
    def success(self):
        return not self.errors and all(f.allowed for f in self.findings)

    def counts(self):
        return dict(Counter(f.kind for f in self.findings))

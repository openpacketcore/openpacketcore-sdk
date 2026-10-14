"""Required-job reachability, matrix lanes, test commands and skip inventories."""

from collections import Counter, defaultdict
import ast
import itertools
import json
import re
import shlex

import yaml

from .model import Finding, GuardError


class UniqueLoader(yaml.BaseLoader):
    """Keep GitHub's `on` key a string and reject overwritten YAML keys."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise GuardError(f'line {key_node.start_mark.line + 1}: duplicate YAML key {key!r}')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def documents(files):
    workflows = {}
    for path, source in sorted(files.items()):
        if not path.startswith('.github/workflows/') or not path.endswith(('.yml', '.yaml')):
            continue
        try:
            value = yaml.load(source, Loader=UniqueLoader)
        except (yaml.YAMLError, GuardError) as error:
            raise GuardError(f'{path}: invalid workflow: {error}') from error
        if not isinstance(value, dict) or not isinstance(value.get('jobs'), dict):
            raise GuardError(f'{path}: workflow has no jobs mapping')
        workflows[path] = value
    return workflows


def required_jobs(workflows):
    required = {}

    def visit(path, job_id, active):
        identity = f'ci:{path}::{job_id}'
        if identity in active:
            raise GuardError(f'{identity}: required job dependency cycle')
        if identity in required:
            return
        job = workflows.get(path, {}).get('jobs', {}).get(job_id)
        if not isinstance(job, dict):
            raise GuardError(f'{identity}: required job is missing')
        required[identity] = path, job_id, job
        needs = job.get('needs', [])
        if isinstance(needs, str):
            needs = [needs]
        for dependency in needs:
            visit(path, dependency, active | {identity})
        called = job.get('uses', '')
        if called.startswith('./.github/workflows/'):
            called = called[2:]
            if called not in workflows:
                raise GuardError(f'{identity}: reusable workflow {called} is missing')
            for child_id in workflows[called]['jobs']:
                visit(called, child_id, active | {identity})

    for path, workflow in workflows.items():
        for job_id, job in workflow['jobs'].items():
            if job.get('name') == 'Rust workspace':
                visit(path, job_id, set())
    return required


def location(files, path, needle, fallback=1):
    offset = files.get(path, '').find(needle)
    if offset < 0:
        return fallback
    return files.get(path, '')[:max(offset, 0)].count('\n') + 1


def matrix_lanes(job):
    matrix = job.get('strategy', {}).get('matrix', {})
    if not isinstance(matrix, dict):
        return {str(matrix)}
    axes = {key: values for key, values in matrix.items() if key not in {'include', 'exclude'}}
    if any(not isinstance(values, list) for values in axes.values()):
        return {json.dumps(matrix, sort_keys=True)}
    keys = sorted(axes)
    rows = [dict(zip(keys, values)) for values in itertools.product(*(axes[key] for key in keys))] if axes else []
    if len(rows) > 512:
        raise GuardError('Required CI matrix has more than 512 lanes')
    for excluded in matrix.get('exclude', []):
        rows = [row for row in rows if not all(row.get(key) == value for key, value in excluded.items())]
    # Include entries may add a lane or add non-axis metadata to existing lanes.
    original_rows = list(rows)
    for included in matrix.get('include', []):
        compatible = [row for row in original_rows if all(key not in axes or row.get(key) == value for key, value in included.items())]
        if not compatible:
            rows.append(included)
    return {','.join(f'{key}={value}' for key, value in sorted(row.items())) for row in rows} or {''}


TEST_COMMAND = re.compile(r'\b(?:cargo\s+(?:test|nextest)|go\s+test|(?:python3?|\S*/python3?)[\'\"]?\s+\S*(?:test[^ /]*\.py|pytest)|pytest|ctest|npm\s+test)\b')


def execution_commands(job):
    commands = Counter()
    for step in job.get('steps', []):
        source = step.get('run', '').replace('\\\n', ' ')
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith('#') or not TEST_COMMAND.search(stripped):
                continue
            commands[' '.join(stripped.split())] += 1
        # CI selects isolated contracts from literal shell arrays. Moving a
        # test between loops can change its profile/coverage even when each
        # cargo command line stays identical. Compare the expanded selections
        # too, without executing the script or expanding arbitrary shell code.
        arrays = {}
        for match in re.finditer(r'^\s*([A-Za-z_]\w*)=\((.*?)\)', source, re.M | re.S):
            try:
                values = shlex.split(match.group(2), comments=True)
            except ValueError:
                continue
            if all(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9:.-]*', value) for value in values):
                arrays[match.group(1)] = values
        loop = r'\bfor\s+(\w+)\s+in\s+[\'\"]?\$\{(\w+)\[@\]\}[\'\"]?\s*;\s*do\b(.*?)\bdone\b'
        for match in re.finditer(loop, source, re.S):
            variable, array, body = match.groups()
            if array not in arrays:
                continue
            for value in arrays[array]:
                expanded = re.sub(r'\$\{' + variable + r'\}|\$' + variable + r'\b', value, body)
                for line in expanded.splitlines():
                    stripped = line.strip()
                    if not stripped.startswith('#') and TEST_COMMAND.search(stripped):
                        commands[' '.join(stripped.split())] += 1
    return commands


def restrictive_condition(key, value):
    if value is None:
        return False
    normalized = re.sub(r'\s+', '', str(value))
    if key == 'continue-on-error':
        return normalized not in {'', 'false', '${{false}}'}
    return normalized not in {'', 'true', '${{true}}', 'always()', '${{always()}}'}


def execution_context(job):
    """Only transfer a command between required jobs in the same environment."""
    keys = ('runs-on', 'container', 'env', 'strategy', 'if', 'continue-on-error')
    return json.dumps({key: job.get(key) for key in keys}, sort_keys=True)


def step_condition_changes(old, new):
    """Match executions before conditions, independently of step names/order."""
    changes = []
    for condition in ('if', 'continue-on-error'):
        remaining = defaultdict(Counter)
        for step in old.get('steps', []):
            value = json.dumps(step.get(condition), sort_keys=True)
            for command, count in execution_commands({'steps': [step]}).items():
                remaining[command][value] += count
        unmatched = []
        for index, step in enumerate(new.get('steps', [])):
            value = json.dumps(step.get(condition), sort_keys=True)
            commands = execution_commands({'steps': [step]})
            for command, count in list(commands.items()):
                retained = min(count, remaining[command][value])
                remaining[command][value] -= retained
                commands[command] -= retained
            unmatched.append((index, step, commands))
        # An unconditional execution may replace a conditional one safely.
        # Match those broadenings before considering newly restricted runs.
        unmatched.sort(key=lambda item: restrictive_condition(condition, item[1].get(condition)))
        for index, step, commands in unmatched:
            restricted = restrictive_condition(condition, step.get(condition))
            replaced = False
            for command, count in commands.items():
                for value in sorted(remaining[command]):
                    matched = min(count, remaining[command][value])
                    remaining[command][value] -= matched
                    count -= matched
                    replaced = replaced or bool(matched)
            if restricted and replaced:
                changes.append((condition, index, step))
    return changes


def workflow_findings(base_files, head_files):
    base_docs, head_docs = documents(base_files), documents(head_files)
    before, after = required_jobs(base_docs), required_jobs(head_docs)
    findings = []
    # Reserve the executions retained in each job before matching relocations.
    # A command already running on another platform cannot replace a deleted
    # execution, and each newly added execution can cover only one relocation.
    extra_commands = defaultdict(Counter)
    for subject, (_, _, job) in after.items():
        old = before.get(subject, (None, None, {}))[2]
        retained = execution_commands(old) if execution_context(old) == execution_context(job) else Counter()
        unconditional = {'steps': [step for step in job.get('steps', []) if not any(restrictive_condition(key, step.get(key)) for key in ('if', 'continue-on-error'))]}
        extra_commands[execution_context(job)] += execution_commands(unconditional) - retained
    for subject, (path, job_id, old) in before.items():
        line = location(base_files, path, '  ' + job_id + ':')
        if subject not in after:
            findings.append(Finding(subject, 'required-ci-removed', path, line, 'job no longer contributes to Rust workspace', 'base'))
            continue
        new = after[subject][2]
        for key in ('runs-on', 'container'):
            if new.get(key) != old.get(key):
                findings.append(Finding(subject, 'required-ci-removed', path, location(head_files, path, '  ' + job_id + ':'), f'required execution environment {key} changed: {old.get(key)!r} -> {new.get(key)!r}'))
        for lane in sorted(matrix_lanes(old) - matrix_lanes(new)):
            findings.append(Finding(subject + '[' + lane + ']', 'required-ci-removed', path, line, 'required matrix lane removed', 'base'))
        for key in ('if', 'continue-on-error'):
            if new.get(key) != old.get(key) and restrictive_condition(key, new.get(key)):
                findings.append(Finding(subject, 'required-ci-removed', path, location(head_files, path, '  ' + job_id + ':'), f'required job {key} changed to {new[key]!r}'))
        for command, count in (execution_commands(old) - execution_commands(new)).items():
            available = extra_commands[execution_context(old)]
            transferred = min(count, available[command])
            available[command] -= transferred
            if count > transferred:
                findings.append(Finding(subject, 'required-ci-removed', path, location(base_files, path, command[:40], line), f'{count - transferred} required test command(s) removed or changed: {command}', 'base'))
        for condition, index, step in step_condition_changes(old, new):
            key = step.get('id', step.get('name', str(index)))
            findings.append(Finding(subject, 'required-ci-removed', path, location(head_files, path, str(key)), f'required test step {key!r} gained or changed {condition}'))
    for path, workflow in base_docs.items():
        if not any(value[0] == path for value in before.values()):
            continue
        old_events, new_events = workflow.get('on', {}), head_docs.get(path, {}).get('on', {})
        if isinstance(old_events, str):
            old_events = {old_events: ''}
        if isinstance(new_events, str):
            new_events = {new_events: ''}
        if isinstance(old_events, list):
            old_events = dict.fromkeys(old_events, '')
        if isinstance(new_events, list):
            new_events = dict.fromkeys(new_events, '')
        for event, old_options in old_events.items():
            if event not in new_events:
                findings.append(Finding(f'ci:{path}::event={event}', 'required-ci-removed', path, 1, 'required workflow trigger removed', 'base'))
            elif isinstance(new_events[event], dict):
                old_options = old_options if isinstance(old_options, dict) else {}
                for key in ('paths', 'paths-ignore', 'branches', 'branches-ignore'):
                    value = new_events[event].get(key)
                    old_value = old_options.get(key)
                    if value is not None and value != old_value:
                        # Adding accepted branches/paths widens the trigger.
                        widens = key in {'branches', 'paths'} and isinstance(value, list) and isinstance(old_value, list) and set(old_value) <= set(value)
                        if not widens:
                            findings.append(Finding(f'ci:{path}::event={event}', 'required-ci-removed', path, 1, f'required workflow {key} filter changed'))
    return findings


def skips(files):
    """Collect explicit skip selectors without running the CI plan generator."""
    found = set()
    for path, source in files.items():
        if not path.startswith(('ci/', 'scripts/', '.github/workflows/')) or path == 'ci/test-changes.json':
            continue
        if path.endswith('.json'):
            try:
                document = json.loads(source)
            except json.JSONDecodeError as error:
                raise GuardError(f'{path}: invalid JSON: {error}') from error

            def visit(value, excluded=False):
                if isinstance(value, dict):
                    if excluded and isinstance(value.get('name'), str):
                        found.add((path, value['name']))
                        return
                    for key, nested in value.items():
                        visit(nested, excluded or bool(re.search(r'skip|exclud|ignor', key, re.I)) or ('qualification' in path and key == 'tests'))
                elif isinstance(value, list):
                    for nested in value:
                        visit(nested, excluded)
                elif excluded and isinstance(value, str):
                    found.add((path, value))

            visit(document)
        elif path.endswith('.py'):
            tree = ast.parse(source, filename=path)
            for node in ast.walk(tree):
                if isinstance(node, (ast.List, ast.Tuple)):
                    values = [item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else None for item in node.elts]
                    for first, second in zip(values, values[1:]):
                        if first == '--skip' and second:
                            found.add((path, second))
                elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(re.search(r'skip|exclud|ignor', ast.unparse(target), re.I) for target in targets):
                        for literal in ast.walk(node.value):
                            if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                                found.add((path, literal.value))
        if path.endswith(('.yml', '.yaml', '.sh')):
            for selector in re.findall(r'--skip(?:=|\s+)[\'"]?([A-Za-z_][A-Za-z_0-9:]*)', source):
                found.add((path, selector))
    return found


def skip_findings(base_files, head_files, inventory):
    findings = []
    for path, selector in sorted(skips(head_files) - skips(base_files)):
        matches = [test for test in inventory.tests.values() if test.id.endswith('::' + selector) or test.name == selector]
        for test in matches:
            findings.append(Finding(test.id, 'disabled', path, location(head_files, path, selector), 'added to a CI skip/qualification list: ' + selector))
        if not matches and ('::' in selector or selector.startswith('Test')):
            findings.append(Finding(f'ci:{path}::skip={selector}', 'required-ci-removed', path, location(head_files, path, selector), 'unresolved CI skip selector added: ' + selector))
    return findings

"""Compare inventories, then require explicit, issue-backed review declarations."""

import json
import re

from .model import Finding, GuardError, Inventory, Report
from .python_go import inventory_go, inventory_python
from .rust import inventory_rust
from .workflows import skip_findings, workflow_findings


DECLARATIONS = 'ci/test-changes.json'
SEMANTIC_CHANGES = {
    'clock-source-changed': 'declared test time-source conversion; review unchanged assertions, deadlines and real-time coverage',
    'fixture-setup-changed': 'declared fixture setup correction; review the changed setup and preserved assertions',
}
KINDS = {'removed', 'disabled', 'assertions-decreased', 'required-ci-removed'} | SEMANTIC_CHANGES.keys()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError(f'{DECLARATIONS}: duplicate JSON key {key!r}')
        result[key] = value
    return result


def inventory(files):
    result = Inventory()
    inventory_rust(files, result)
    inventory_python(files, result)
    inventory_go(files, result)
    return result


def declaration_record(files):
    try:
        value = json.loads(files.get(DECLARATIONS, '{"version":1,"changes":[]}'), object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise GuardError(f'{DECLARATIONS}:{error.lineno}: {error.msg}') from error
    if not isinstance(value, dict) or set(value) != {'version', 'changes'} or type(value['version']) is not int or value['version'] != 1 or not isinstance(value['changes'], list):
        raise GuardError(f'{DECLARATIONS}: expected {{"version": 1, "changes": [...]}}')
    return value['changes']


def declarations(changes, offset):
    """Validate only this comparison's appended declarations, not history."""
    entries = {}
    for index, entry in enumerate(changes, offset):
        where = f'{DECLARATIONS}:changes[{index}]'
        if not isinstance(entry, dict):
            raise GuardError(f'{where}: entry must be an object')
        allowed_keys = {'test', 'job', 'kind', 'reason', 'issue', 'renamed_to', 'replacements', 'behavior_deleted', 'deleting_change'}
        if set(entry) - allowed_keys or not {'kind', 'reason', 'issue'} <= set(entry):
            raise GuardError(f'{where}: unknown or missing entry fields')
        if ('test' in entry) == ('job' in entry):
            raise GuardError(f'{where}: name exactly one test or job')
        subject = entry.get('test', entry.get('job'))
        if not isinstance(subject, str) or not subject or '*' in subject:
            raise GuardError(f'{where}: use the exact inventory name, not a wildcard')
        if entry['kind'] not in KINDS or not isinstance(entry['reason'], str) or not entry['reason'].strip():
            raise GuardError(f'{where}: a supported kind and nonempty reason are required')
        if entry['kind'] in SEMANTIC_CHANGES and ('test' not in entry or set(entry) != {'test', 'kind', 'reason', 'issue'}):
            raise GuardError(f'{where}: {entry["kind"]} names one test without coverage-reduction fields')
        if type(entry['issue']) is not int or entry['issue'] < 1:
            raise GuardError(f'{where}: issue must be a positive GitHub issue number')
        if 'renamed_to' in entry and (entry['kind'] != 'removed' or not isinstance(entry['renamed_to'], str) or not entry['renamed_to']):
            raise GuardError(f'{where}: renamed_to requires a removed test and an exact head name')
        if 'replacements' in entry and (not isinstance(entry['replacements'], list) or not entry['replacements'] or any(not isinstance(name, str) or not name for name in entry['replacements'])):
            raise GuardError(f'{where}: replacements must name one or more head tests')
        if 'behavior_deleted' in entry or 'deleting_change' in entry:
            if entry['kind'] != 'removed' or 'test' not in entry or entry.get('behavior_deleted') is not True:
                raise GuardError(f'{where}: behavior_deleted must be true and applies only to a removed test')
            if not isinstance(entry.get('deleting_change'), str) or not entry['deleting_change'].strip():
                raise GuardError(f'{where}: deleted behavior must cite its deleting_change')
            if 'renamed_to' in entry or 'replacements' in entry:
                raise GuardError(f'{where}: choose replacement coverage or deleted behavior, not both')
        key = subject, entry['kind']
        if key in entries:
            raise GuardError(f'{where}: duplicate declaration for {subject} / {entry["kind"]}')
        entries[key] = entry
    return entries


def analyze_files(base_files, head_files, issue_exists=None):
    before, after = inventory(base_files), inventory(head_files)
    old_record, record = declaration_record(base_files), declaration_record(head_files)
    errors = []
    # JSON scalar types matter: changing issue 42 to 42.0 is an edit even
    # though Python considers those values equal. Formatting/key order are not.
    if json.dumps(record[:len(old_record)], sort_keys=True) != json.dumps(old_record, sort_keys=True):
        errors.append(f'{DECLARATIONS}: historical entries were edited, deleted, or reordered; preserve the base record and append new declarations')
        entries = {}
    else:
        entries = declarations(record[len(old_record):], len(old_record))
    old_coverage, new_coverage = before.coverage(), after.coverage()
    findings = []
    aliases = {subject: entry['renamed_to'] for (subject, kind), entry in entries.items() if kind == 'removed' and 'renamed_to' in entry}
    for test_id, test in sorted(before.tests.items()):
        if test_id not in after.tests:
            findings.append(Finding(test_id, 'removed', test.file, test.line, 'test no longer exists at its full module path', 'base'))
    for test_id, test in sorted(after.tests.items()):
        old_id = test_id if test_id in before.tests else next((old for old, new in aliases.items() if new == test_id and old in before.tests), None)
        previous = old_coverage.get(old_id, dict(assertions=0, gates=set(), helpers=set()))
        current = new_coverage[test_id]
        for gate in sorted(current['gates'] - previous['gates']):
            # Platform-specific or child-process tests add coverage; their
            # initial scope is not a reduction from an existing test. Explicit
            # ignores/skips on a new test still require a declaration.
            if old_id is None and not re.search(r'\b(?:ignore|skip|skipif|skipIf|skipUnless|skipTest|xfail)\b', gate):
                continue
            findings.append(Finding(test_id, 'disabled', test.file, test.line, 'new test gate: ' + gate))
        if old_id is None:
            continue
        if current['assertions'] < previous['assertions']:
            findings.append(Finding(test_id, 'assertions-decreased', test.file, test.line, f'assertion count including local test helpers decreased: {previous["assertions"]} -> {current["assertions"]}'))
        # Adding unrelated checks must not conceal the disappearance of an
        # existing assertion-bearing scenario helper. This also exposes dropped
        # completion/recovery properties when a passive observer is replaced.
        for helper in sorted(previous['helpers'] - current['helpers']):
            old_helper = before.functions[helper]
            if helper not in after.functions:
                relocated = any(after.functions[name].name == old_helper.name and after.functions[name].assertions >= old_helper.assertions for name in current['helpers'])
                retained = old_helper.assertion_signatures and old_helper.assertion_signatures <= current['signatures']
                if relocated or retained:
                    continue
                findings.append(Finding(test_id, 'assertions-decreased', old_helper.file, old_helper.line, 'assertion-bearing helper removed from this test: ' + helper, 'base'))
    findings.extend(workflow_findings(base_files, head_files))
    findings.extend(skip_findings(base_files, head_files, after))
    # Setup and clock changes are explicit semantic review records, including tests
    # introduced earlier in an unmerged change. They do not authorize a removed
    # test, a new gate, fewer assertions, or any other coverage reduction.
    for (subject, kind), entry in entries.items():
        if kind not in SEMANTIC_CHANGES:
            continue
        test = after.tests.get(subject)
        if test is None:
            errors.append(f'{DECLARATIONS}: {kind} test does not exist at head: {subject}')
        elif base_files.get(test.file) == head_files.get(test.file):
            errors.append(f'{DECLARATIONS}: {kind} test source is unchanged: {subject}')
        else:
            findings.append(Finding(subject, kind, test.file, test.line,
                                    SEMANTIC_CHANGES[kind]))
    matches = {finding.key() for finding in findings}
    issue_results = {}
    for key, entry in entries.items():
        subject, kind = key
        if key not in matches:
            errors.append(f'{DECLARATIONS}: stale or misspelled declaration: {subject} / {kind}')
            continue
        targets = entry.get('replacements', []) + ([entry['renamed_to']] if 'renamed_to' in entry else [])
        missing = [name for name in targets if name not in after.tests]
        if missing:
            errors.append(f'{DECLARATIONS}: replacement/rename target does not exist at head: {missing}')
            continue
        if kind == 'removed' and not targets and not entry.get('behavior_deleted'):
            errors.append(f'{DECLARATIONS}: {subject} is removed; name its replacing head tests when behavior remains, or set behavior_deleted and cite deleting_change')
            continue
        issue = entry['issue']
        if issue not in issue_results:
            if issue_exists is None:
                raise GuardError('Issue validation is required for every declaration')
            try:
                issue_results[issue] = issue_exists(issue)
            except GuardError as error:
                # A verification outage must not suppress already collected
                # findings. They remain undeclared and are printed with errors.
                issue_results[issue] = error
        if isinstance(issue_results[issue], GuardError):
            errors.append(f'{DECLARATIONS}: {subject} / {kind}: {issue_results[issue]}')
            continue
        if not issue_results[issue]:
            errors.append(f'{DECLARATIONS}: #{issue} is not an existing issue in this repository')
            continue
        for finding in findings:
            if finding.key() == key:
                finding.allowed, finding.reason, finding.issue = True, entry['reason'], issue
    # Stable ordering is also the machine-readable output order.
    findings.sort(key=lambda finding: (finding.subject, finding.kind, finding.file, finding.line, finding.detail))
    return Report(findings, errors, len(before.tests), len(after.tests))

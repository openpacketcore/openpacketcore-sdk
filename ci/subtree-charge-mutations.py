#!/usr/bin/env python3
"""Delete each production subtree budget charge and require a failing test.

Requires ci/test-inventory-requirements.txt. Run in a clean, idle worktree with
its usual stable CARGO_TARGET_DIR and test profile. --prefix-json accepts an
argv array for the site's slot/timeout/resource wrapper. No caches are removed.
Evidence (outside the worktree) records every patch, command, result and log.
"""
import argparse
from contextlib import contextmanager
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from test_inventory.syntax import checked_parse, walk, COMMENTS, STRINGS
# Discover calls across the complete producer/consumer source trees, including
# discovery and generated projection. New read-path files need no allowlist edit.
ROOTS = ('crates/opc-mgmt-schema/src',
         'crates/opc-netconf-server/src',
         'crates/opc-yanggen/src')
TEST_MODULES = {'tests.rs', 'work_audit.rs'}
COMMANDS = {
    'server': ['cargo', 'test', '--locked', '-p', 'opc-netconf-server', '--lib',
               '--', '--test-threads=4'],
    'authenticated': ['cargo', 'test', '--locked', '-p', 'opc-yanggen',
                      '--test', 'subtree_content', '--', '--nocapture'],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sites_in(path, source):
    tree = checked_parse('rust', path, source.decode())
    sites = []
    ordinals = {}

    def visit(node, function=''):
        if node.type == 'function_item':
            function = source[node.child_by_field_name('name').raw.start_byte:
                              node.child_by_field_name('name').raw.end_byte].decode()
        if node.type == 'macro_invocation' and node.child_by_field_name('macro').text == b'quote':
            # quote! token trees are not parsed as Rust expressions. Preserve
            # interpolations and offsets; strings/comments cannot create sites.
            start, end = node.raw.start_byte, node.raw.end_byte
            masked = bytearray(source[start:end])
            for token in walk(node):
                if token.type in COMMENTS | STRINGS:
                    lo, hi = token.raw.start_byte - start, token.raw.end_byte - start
                    masked[lo:hi] = b' ' * (hi - lo)
            for match in re.finditer(rb'ctx\.budget\(\)\.charge\(', masked):
                lo = start + match.start()
                args_start = start + match.end() - 1
                hi, depth = args_start + 1, 1
                while depth:
                    depth += (source[hi:hi + 1] == b'(') - (source[hi:hi + 1] == b')')
                    hi += 1
                ordinals[function] = ordinals.get(function, 0) + 1
                sites.append(dict(id=f'{path}:{function}:{ordinals[function]}', path=path,
                                  function=function, line=source.count(b'\n', 0, lo) + 1,
                                  start=lo, end=hi, receiver='ctx.budget()',
                                  arguments=source[args_start:hi].decode(), call=source[lo:hi].decode()))
            return
        if node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'field_expression':
                field = callee.child_by_field_name('field')
                if source[field.raw.start_byte:field.raw.end_byte] == b'charge':
                    receiver = callee.child_by_field_name('value')
                    args = node.child_by_field_name('arguments')
                    ordinals[function] = ordinals.get(function, 0) + 1
                    sites.append(dict(id=f'{path}:{function}:{ordinals[function]}',
                                      path=path, function=function,
                                      line=node.start_point.row + 1,
                                      start=node.raw.start_byte, end=node.raw.end_byte,
                                      receiver=source[receiver.raw.start_byte:receiver.raw.end_byte].decode(),
                                      arguments=source[args.raw.start_byte:args.raw.end_byte].decode(),
                                      call=source[node.raw.start_byte:node.raw.end_byte].decode()))
        attributes = []
        for child in node.named_children:
            if child.type == 'attribute_item':
                attributes.append(re.sub(rb'\s+', b'', source[child.raw.start_byte:child.raw.end_byte]))
                continue
            if child.type in {'line_comment', 'block_comment'}:
                continue
            test_only = any(attr in {b'#[cfg(test)]', b'#[test]'} for attr in attributes)
            attributes = []
            if not test_only:
                visit(child, function)

    visit(tree.root_node)
    return sites


def inventory(root):
    paths = {path for name in ROOTS for path in (root / name).rglob('*.rs')}
    sources = {}
    for path in sorted(paths):
        if path.name in TEST_MODULES:
            continue
        source = path.read_bytes()
        if re.search(rb'\.\s*charge\s*\(', source):
            sources[str(path.relative_to(root))] = source
    sites = [site for name, source in sources.items() for site in sites_in(name, source)]
    return sources, sites


def replace(source, site):
    # Evaluate the receiver and original argument (including checked errors),
    # but perform no charge. A Result preserves surrounding ?/map_err syntax.
    error = ('opc_mgmt_schema::subtree::SubtreeError'
             if site['path'].startswith('crates/opc-yanggen/') else 'SubtreeError')
    replacement = ('{ let _ = (&(' + site['receiver'] + '), ' + site['arguments']
                   + '); Ok::<(), ' + error + '>(()) }').encode()
    return source[:site['start']] + replacement + source[site['end']:]


@contextmanager
def overlay(path, original, changed):
    if path.read_bytes() != original:
        raise RuntimeError(f'{path}: source changed before mutation')
    path.write_bytes(changed)
    try:
        yield
    finally:
        if path.read_bytes() != changed:
            raise RuntimeError(f'{path}: source changed during mutation; retained for inspection')
        path.write_bytes(original)


def outcome(code, log):
    summaries = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;', log)
    if not summaries or 'could not compile' in log:
        return 'invalid'
    if code == 0 and all(int(failed) == 0 for _, failed in summaries) and any(int(passed) for passed, _ in summaries):
        return 'survived'
    if code == 101 and any(int(failed) for _, failed in summaries):
        return 'killed'
    return 'invalid'


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def run(root, evidence, label, prefix, source):
    results = {}
    for name, command in COMMANDS.items():
        command = prefix + command
        log_path = evidence / f'{label}-{name}.log'
        start = time.monotonic()
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                code = process.wait()
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait()
        content = log_path.read_bytes()
        results[name] = dict(command=command, exit_code=code, outcome=outcome(code, content.decode(errors='replace')),
                             elapsed_seconds=round(time.monotonic() - start, 3),
                             log=str(log_path), log_sha256=sha(content), source=source)
        save(evidence / f'{label}-{name}.json', results[name])
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--prefix-json', type=Path)
    parser.add_argument('--site', action='append', help='exact site id; omitted means every site')
    args = parser.parse_args()
    root = args.root.resolve()
    sources, sites = inventory(root)
    if args.list:
        print(json.dumps(sites, indent=2))
        return 0
    if not args.evidence:
        parser.error('--evidence is required for a run')
    evidence = args.evidence.resolve()
    if evidence.is_relative_to(root):
        parser.error('evidence must be outside the mutated worktree')
    evidence.mkdir(parents=True, exist_ok=False)
    git = lambda *argv: subprocess.check_output(['git', *argv], cwd=root).decode().strip()
    if git('status', '--porcelain'):
        parser.error('mutation runs require a clean worktree')
    head = git('rev-parse', 'HEAD')
    prefix = json.loads(args.prefix_json.read_text()) if args.prefix_json else []
    if not isinstance(prefix, list) or not all(isinstance(arg, str) for arg in prefix):
        parser.error('prefix must be an argv array')
    selected = set(args.site or [site['id'] for site in sites])
    if selected - {site['id'] for site in sites}:
        parser.error('unknown charge site')
    manifest = dict(head=head, source_sha256={name: sha(data) for name, data in sources.items()},
                    sites=sites, selected=sorted(selected), runner_sha256=sha(Path(__file__).read_bytes()))
    save(evidence / 'manifest.json', manifest)
    baseline = run(root, evidence, 'baseline', prefix, dict(head=head, patch=None))
    if any(row['outcome'] != 'survived' for row in baseline.values()):
        save(evidence / 'summary.json', dict(success=False, baseline=baseline, sites=[]))
        return 2
    results = []
    for index, site in enumerate(sites, 1):
        if site['id'] not in selected:
            continue
        if git('status', '--porcelain') or git('rev-parse', 'HEAD') != head:
            raise RuntimeError('worktree changed between mutations')
        original = sources[site['path']]
        changed = replace(original, site)
        label = f'site-{index:03}'
        patch = ''.join(difflib.unified_diff(original.decode().splitlines(True), changed.decode().splitlines(True),
                                           fromfile='a/' + site['path'], tofile='b/' + site['path']))
        patch_path = evidence / (label + '.patch')
        patch_path.write_text(patch)
        source = dict(head=head, path=site['path'], mutated_sha256=sha(changed),
                      patch=str(patch_path), patch_sha256=sha(patch.encode()))
        with overlay(root / site['path'], original, changed):
            checks = run(root, evidence, label, prefix, source)
        status = ('invalid' if any(row['outcome'] == 'invalid' for row in checks.values()) else
                  'killed' if any(row['outcome'] == 'killed' for row in checks.values()) else 'survived')
        results.append(dict(site=site, status=status, checks=checks))
        summary = dict(head=head, baseline=baseline, sites=results, complete=len(results) == len(selected),
                       success=len(results) == len(selected) and all(row['status'] == 'killed' for row in results))
        save(evidence / 'summary.json', summary)
        print(json.dumps(dict(site=site['id'], status=status, finished=len(results), total=len(selected))), flush=True)
    if git('status', '--porcelain'):
        raise RuntimeError('worktree not restored')
    return 0 if all(row['status'] == 'killed' for row in results) else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise InterruptedError(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())

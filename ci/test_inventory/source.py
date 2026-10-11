"""Read immutable Git blobs without checking out or executing the compared code."""

from pathlib import PurePosixPath
import subprocess

from .model import GuardError


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if result.returncode:
        raise GuardError(result.stderr.decode(errors='replace').strip())
    return result.stdout


def revision(repo, value):
    # --end-of-options prevents a user-supplied revision becoming a Git option.
    return git(repo, 'rev-parse', '--verify', '--end-of-options', value + '^{commit}').decode().strip()


def is_ancestor(repo, ancestor, descendant):
    # Callers supply already resolved object IDs, never unchecked Git options.
    result = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', ancestor, descendant], capture_output=True)
    if result.returncode not in {0, 1}:
        raise GuardError(result.stderr.decode(errors='replace').strip())
    return result.returncode == 0


def read_revision(repo, ref):
    ref = revision(repo, ref)
    entries = git(repo, 'ls-tree', '-r', '-z', ref).split(b'\0')
    wanted = []
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = raw_path.decode('utf-8')
        suffix = PurePosixPath(path).suffix
        if kind != b'blob' or suffix not in {'.rs', '.py', '.go', '.toml', '.json', '.yml', '.yaml', '.sh'}:
            continue
        if mode == b'120000':
            raise GuardError(f'{path}: tracked source symlink needs explicit parser support')
        wanted.append((path, oid))
    payload = b''.join(oid + b'\n' for _, oid in wanted)
    result = subprocess.run(['git', '-C', str(repo), 'cat-file', '--batch'], input=payload, capture_output=True)
    if result.returncode:
        raise GuardError(result.stderr.decode(errors='replace'))
    data, offset, files = result.stdout, 0, {}
    for path, expected_oid in wanted:
        end = data.index(b'\n', offset)
        oid, kind, size = data[offset:end].split()
        if oid != expected_oid or kind != b'blob':
            raise GuardError(f'{path}: unexpected Git object')
        offset = end + 1
        size = int(size)
        try:
            files[path] = data[offset:offset + size].decode('utf-8')
        except UnicodeDecodeError as error:
            raise GuardError(f'{path}: source is not UTF-8') from error
        offset += size + 1
    if offset != len(data):
        raise GuardError('Unexpected trailing Git batch output')
    return ref, files

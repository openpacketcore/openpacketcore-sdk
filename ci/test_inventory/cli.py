"""CLI and GitHub read-only issue validation for the inventory guard."""

from dataclasses import asdict
from pathlib import Path
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from .guard import analyze_files
from .model import GuardError
from .source import git, is_ancestor, read_revision, revision


def github_issue_exists(repository, issue):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise GuardError('Expected --repository OWNER/NAME for issue validation')
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'sdk-test-inventory-guard'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    url = f'https://api.github.com/repos/{repository}/issues/{issue}'
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code in {404, 410}:
            return False
        raise GuardError(f'Cannot verify issue #{issue}: GitHub HTTP {error.code}') from error
    except (OSError, ValueError) as error:
        raise GuardError(f'Cannot verify issue #{issue}: {type(error).__name__}') from error
    return value.get('number') == issue and 'pull_request' not in value and value.get('repository_url', '').lower() == f'https://api.github.com/repos/{repository}'.lower()


def event_revisions(repo, event_name, event):
    if event_name == 'pull_request':
        pull = event['pull_request']
        base, head = pull['base']['sha'], pull['head']['sha']
        return git(repo, 'merge-base', revision(repo, base), revision(repo, head)).decode().strip(), head
    if event_name == 'merge_group':
        return event['merge_group']['base_sha'], event['merge_group']['head_sha']
    if event_name == 'workflow_dispatch':
        head = os.environ['GITHUB_SHA']
        branch = event['repository']['default_branch']
        base = git(repo, 'merge-base', revision(repo, 'refs/remotes/origin/' + branch), revision(repo, head)).decode().strip()
        return base, head
    if event_name == 'push':
        head = event['after']
        if event.get('deleted') or head == '0' * 40:
            raise GuardError('A deleted branch has no head to inventory')
        if event.get('ref', '').startswith('refs/heads/train/'):
            branch = event['repository']['default_branch']
            base = git(repo, 'merge-base', revision(repo, 'refs/remotes/origin/' + branch), revision(repo, head)).decode().strip()
            return base, head
        before = event.get('before', '')
        if not before or before == '0' * 40:
            raise GuardError('Initial branch push needs an explicit base revision')
        return before, head
    raise GuardError('Supply both --base and --head, or run on a pull_request/merge_group/push/workflow_dispatch event')


def comparison_revisions(repo, base=None, head=None):
    current_head = revision(repo, 'HEAD')
    if head and not base:
        raise GuardError('An explicit --head requires --base for a historical comparison')
    event_file = os.environ.get('GITHUB_EVENT_PATH')
    if not base and os.environ.get('GITHUB_ACTIONS') == 'true':
        if not event_file:
            raise GuardError('GitHub Actions requires its event file to select the comparison')
        base, head = event_revisions(repo, os.environ.get('GITHUB_EVENT_NAME'), json.loads(Path(event_file).read_text()))
        base_sha, head_sha = revision(repo, base), revision(repo, head)
        if not is_ancestor(repo, base_sha, head_sha) or not is_ancestor(repo, head_sha, current_head):
            raise GuardError('The event base must be an ancestor of its head, and the event head must be in the checked-out HEAD')
        return base_sha, head_sha, 'GitHub event'
    try:
        main_sha = revision(repo, 'refs/remotes/origin/main')
    except GuardError as error:
        raise GuardError('Local inventory validation requires origin/main; fetch its history before running the guard') from error
    backlog_target = head is not None and base in {'origin/backlog', 'refs/remotes/origin/backlog'}
    base_ref = 'refs/remotes/origin/backlog' if backlog_target else base
    base_sha = revision(repo, base_ref) if base_ref else git(repo, 'merge-base', current_head, main_sha).decode().strip()
    head_sha = revision(repo, head) if head else current_head
    if backlog_target:
        if base_sha == head_sha:
            raise GuardError(f'Base and head resolve to the same commit ({head_sha}); refusing an empty comparison')
        if not is_ancestor(repo, base_sha, head_sha) or not is_ancestor(repo, head_sha, current_head):
            raise GuardError('The backlog base must be an ancestor of its head, and its head must be in the checked-out HEAD')
        return base_sha, head_sha, 'explicit backlog target'
    if not is_ancestor(repo, base_sha, current_head) or not is_ancestor(repo, base_sha, main_sha):
        raise GuardError(f'Base {base_sha} must be an ancestor of both HEAD ({current_head}) and origin/main ({main_sha}); a branch-only or unrelated base cannot qualify this change')
    if not is_ancestor(repo, base_sha, head_sha):
        raise GuardError(f'Base {base_sha} must also be an ancestor of the comparison head {head_sha}')
    if base is not None and head is not None and base_sha == head_sha:
        raise GuardError(f'Base and head resolve to the same commit ({head_sha}); refusing an empty comparison')
    return base_sha, head_sha, 'explicit common ancestor' if base else 'merge-base(HEAD, origin/main)'


def annotation(value, property_value=False):
    value = str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    return value.replace(':', '%3A').replace(',', '%2C') if property_value else value


def main(argv=None):
    parser = argparse.ArgumentParser(description='Require issue-backed declarations for test and required-CI coverage reductions')
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--base', help='base commit; locally an ancestor of HEAD and origin/main (default: their merge base), or origin/backlog with an explicit --head')
    parser.add_argument('--head', help='explicit historical comparison head, used with --base; defaults to HEAD locally')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', 'openpacketcore/openpacketcore-sdk'))
    parser.add_argument('--json', type=Path, help='write the complete report, including allowlisted findings')
    args = parser.parse_args(argv)
    try:
        base, head, selection = comparison_revisions(args.repo, args.base, args.head)
        print(f'base = {selection}: {base}; comparison head = {head}')
        if base == head:
            payload = dict(base=base, head=head, success=True, nothing_to_compare=True,
                           base_tests=None, head_tests=None, findings=[], errors=[])
            if args.json:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(json.dumps(payload, indent=2) + '\n')
            print('Nothing to compare: base and head are the same commit; PASS')
            return 0
        base_sha, base_files = read_revision(args.repo, base)
        head_sha, head_files = read_revision(args.repo, head)
        report = analyze_files(base_files, head_files, lambda issue: github_issue_exists(args.repository, issue))
        print(f'Base {base_sha}: {report.base_tests} tests; head {head_sha}: {report.head_tests} tests')
        for finding in report.findings:
            label = 'DECLARED' if finding.allowed else 'UNDECLARED'
            message = f'{label} {finding.kind} {finding.subject}: {finding.detail}'
            if finding.allowed:
                message += f' (#{finding.issue}: {finding.reason})'
            print(f'{finding.side} {finding.file}:{finding.line}: {message}')
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                level = 'notice' if finding.allowed else 'error'
                print(f'::{level} file={annotation(finding.file, True)},line={finding.line}::{annotation(message)}')
        for error in report.errors:
            print('ERROR ' + error)
        payload = dict(base=base_sha, head=head_sha, success=report.success, base_tests=report.base_tests, head_tests=report.head_tests, findings=[asdict(f) for f in report.findings], errors=report.errors)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(payload, indent=2) + '\n')
        print(f'{len(report.findings)} flagged change(s), {sum(f.allowed for f in report.findings)} declared; ' + ('PASS' if report.success else 'FAIL'))
        return 0 if report.success else 1
    except (GuardError, OSError, KeyError, ValueError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

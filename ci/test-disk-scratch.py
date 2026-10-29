#!/usr/bin/env python3
"""Scratch containment and workflow regressions, including controlled root fixtures."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ci/disk-scratch.sh"
RAM = {"1021994", "858458f6"}
CONTEXT = {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "rust-local-kernel-lifecycle",
           "GITHUB_WORKFLOW_REF": "owner/repository/.github/workflows/ci.yml@refs/heads/test"}

# All mounts and privilege transitions stay inside this private mount namespace
# and synthetic fixture. No host mount or existing data is used as a victim.
PRIVILEGED_FIXTURE = r'''
from pathlib import Path
import importlib.util, os, shutil, stat, subprocess, sys
helper, root, uid, gid, mode = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
runner = root / 'runner'
if mode == 'search-only':
    ancestor = root/'search-only'
    ancestor.mkdir(mode=0o711)
    ancestor.chmod(0o711)
    runner = ancestor/'runner'
    runner.mkdir(mode=0o700)
    os.chown(runner, uid, gid)
env = dict(os.environ, RUNNER_TEMP=str(runner), GITHUB_ENV=str(root/'job-env'),
           GITHUB_JOB='rust-local-kernel-lifecycle',
           GITHUB_WORKFLOW_REF='owner/repository/.github/workflows/ci.yml@refs/heads/test')
if mode == 'symlink':
    alias = root/'alias'
    alias.symlink_to(root, target_is_directory=True)
    env['RUNNER_TEMP'] = str(alias/'runner')
setpriv = [shutil.which('setpriv'), f'--reuid={uid}', f'--regid={gid}', '--init-groups']
def run(*args, environment=env):
    return subprocess.run([*setpriv, 'bash', str(helper), *args], env=environment, text=True, capture_output=True)
mounted = None
try:
    prepared = run('prepare')
    assert prepared.returncode == 0, prepared.stderr
    env.update(dict(line.split('=', 1) for line in (root/'job-env').read_text().splitlines()))
    scratch = Path(env['TMPDIR'])
    own_marker = scratch/'own'
    own_marker.write_text('own')
    blocked = scratch/'root-owned'
    blocked.mkdir(mode=0o700)
    (blocked/'data').write_text('root fixture')
    foreign = root/'foreign'
    foreign.mkdir(mode=0o700)
    marker = foreign/'keep'
    marker.write_text('foreign')
    if mode in ['bind', 'tmpfs']:
        mounted = scratch/'mount'
        mounted.mkdir()
        command = ['mount', '--bind', str(foreign), str(mounted)] if mode=='bind' else ['mount', '-t', 'tmpfs', 'tmpfs', str(mounted)]
        subprocess.run(command, check=True)
        if mode=='tmpfs':
            (mounted/'keep').write_text('mounted data')
        result = run('cleanup', '--privileged')
        assert result.returncode != 0, result.stderr
        assert 'mount point' in result.stderr, result.stderr
        assert marker.read_text() == 'foreign', 'cleanup escaped through the bind mount'
        if mode=='tmpfs':
            assert (mounted/'keep').read_text() == 'mounted data'
        assert scratch.exists(), 'refused cleanup must restore its root'
    elif mode=='symlink':
        victim = foreign/'runner'/scratch.name
        victim.mkdir(parents=True)
        (victim/'keep').write_text('foreign')
        alias.unlink()
        alias.symlink_to(foreign, target_is_directory=True)
        result=run('cleanup','--privileged')
        assert result.returncode==0, result.stderr
        assert not scratch.exists(), 'cleanup must use the recorded physical parent'
        assert (victim/'keep').read_text()=='foreign', 'changed runner alias must not redirect deletion'
    elif mode=='sudo-race':
        victim = foreign/scratch.name
        victim.mkdir()
        (victim/'keep').write_text('foreign')
        tools=root/'tools'
        tools.mkdir()
        sudo=tools/'sudo'
        sudo.write_text('#!/bin/sh\nset -eu\nmv -- "$RUNNER_TEMP" "$SCRATCH_TEST_SAVED"\nln -s -- "$SCRATCH_TEST_FOREIGN" "$RUNNER_TEMP"\nexec "$SCRATCH_TEST_REAL_SUDO" "$@"\n')
        sudo.chmod(0o755)
        saved=root/'saved-runner'
        race_env=dict(env, PATH=str(tools)+os.pathsep+env['PATH'], SCRATCH_TEST_SAVED=str(saved),
                      SCRATCH_TEST_FOREIGN=str(foreign), SCRATCH_TEST_REAL_SUDO=shutil.which('sudo'))
        try:
            result=run('cleanup','--privileged',environment=race_env)
        finally:
            if runner.is_symlink():
                runner.unlink()
                saved.rename(runner)
        assert result.returncode != 0, result.stderr
        assert 'Not a directory' in result.stderr, result.stderr
        assert (victim/'keep').read_text() == 'foreign', 'sudo followed a replaced ancestor'
        assert own_marker.read_text() == 'own', 'delegation must not perform partial cleanup'
    elif mode=='move-race':
        spec=importlib.util.spec_from_file_location('scratch', helper.with_suffix('.py'))
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original=module.rename_new
        def replace(source,name,destination,new_name):
            if new_name=='scratch':
                os.rename(name,name+'.saved',src_dir_fd=source,dst_dir_fd=source)
                os.rename(str(foreign),name,dst_dir_fd=source)
            original(source,name,destination,new_name)
        module.rename_new=replace
        try:
            module.cleanup(str(runner), str(scratch), env['OPC_CI_DISK_TMPDIR_ID'],
                           env['OPC_CI_DISK_PARENT_ID'],uid,privileged=True)
        except RuntimeError as error:
            assert 'binding changed' in str(error), str(error)
        else:
            raise AssertionError('staging accepted a replacement inode')
        assert (scratch/'keep').read_text()=='foreign'
        assert (scratch.with_name(scratch.name+'.saved')/'own').read_text()=='own'
    else:
        result=run('cleanup','--privileged')
        assert result.returncode==0, result.stderr
        assert 'Permission denied' not in result.stderr
        assert not scratch.exists() and runner.exists() and (root/'job-env').exists()
finally:
    if mounted is not None:
        subprocess.run(['umount',str(mounted)],check=True)
    for parent, directories, files in os.walk(root):
        for path in [Path(parent), *(Path(parent)/name for name in directories+files)]:
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
            os.lchown(path, uid, gid)
'''


def filesystem(path):
    return subprocess.check_output(["stat", "-f", "-c", "%t", "--", str(path)], text=True).strip()


def disk_parent():
    for path in [os.environ.get("RUNNER_TEMP"), str(ROOT), "/var/tmp", tempfile.gettempdir()]:
        if path and Path(path).is_dir() and os.access(path, os.W_OK | os.X_OK) and filesystem(path) not in RAM:
            return str(Path(path).resolve())
    raise RuntimeError("scratch tests require an available writable disk filesystem")


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=disk_parent())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.env = dict(os.environ, RUNNER_TEMP=str(self.runner), GITHUB_ENV=str(self.root / "job-env"))
        for key in list(self.env):
            if key.startswith("OPC_CI_DISK_"):
                self.env.pop(key)

    def run_helper(self, *args, env=None):
        return subprocess.run(["bash", str(HELPER), *args], env=self.env if env is None else env,
                              capture_output=True, text=True)

    def prepare(self):
        result = self.run_helper("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env.update(dict(line.split("=", 1) for line in Path(self.env["GITHUB_ENV"]).read_text().splitlines()))
        return Path(self.env["TMPDIR"])

    def identity_env(self, runner, scratch):
        identity = lambda path: f"{path.stat().st_dev}:{path.stat().st_ino}"
        return dict(self.env, RUNNER_TEMP=str(runner), OPC_CI_DISK_TMPDIR=str(scratch),
                    OPC_CI_DISK_PARENT=str(runner), OPC_CI_DISK_TMPDIR_ID=identity(scratch),
                    OPC_CI_DISK_PARENT_ID=identity(runner))

    def test_prepare_resolves_symlinked_runner_ancestor_and_cleanup_uses_recorded_parent(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.env["RUNNER_TEMP"] = str(alias / self.runner.name)
        scratch = self.prepare()
        self.assertEqual(self.env["OPC_CI_DISK_PARENT"], str(self.runner))
        self.assertEqual(scratch.parent, self.runner)
        (scratch / "owned").write_text("data")
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "keep").write_text("foreign")
        victim = foreign / self.runner.name / scratch.name
        victim.mkdir(parents=True)
        (victim / "keep").write_text("foreign scratch")
        alias.unlink()
        alias.symlink_to(foreign, target_is_directory=True)
        self.assertEqual(self.run_helper("cleanup").returncode, 0)
        self.assertFalse(scratch.exists())
        self.assertEqual((foreign / "keep").read_text(), "foreign")
        self.assertEqual((victim / "keep").read_text(), "foreign scratch")

    def test_preparation_records_private_directory_identity(self):
        scratch = self.prepare()
        self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.env.get("OPC_CI_DISK_TMPDIR_ID"), f"{scratch.stat().st_dev}:{scratch.stat().st_ino}")
        self.assertEqual(self.env.get("OPC_CI_DISK_PARENT_ID"), f"{self.runner.stat().st_dev}:{self.runner.stat().st_ino}")
        (scratch / "owned").write_text("data")
        self.assertEqual(self.run_helper("cleanup").returncode, 0)
        self.assertFalse(scratch.exists())
        self.assertEqual(self.run_helper("cleanup").returncode, 0, "already retired identities are idempotent")

    def test_symlinked_ancestor_is_refused_without_touching_its_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        scratch = outside / "opc-disk-scratch.Ab12Cd34"
        scratch.mkdir()
        marker = scratch / "keep"
        marker.write_text("foreign")
        alias = self.root / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        env = self.identity_env(alias, alias / scratch.name)
        result = self.run_helper("cleanup", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "foreign")

    def test_dotdot_parent_is_refused_with_a_valid_scratch_basename(self):
        scratch = self.root / "opc-disk-scratch.Ab12Cd34"
        scratch.mkdir()
        marker = scratch / "keep"
        marker.write_text("foreign")
        runner = self.runner / ".."
        env = self.identity_env(runner, runner / scratch.name)
        result = self.run_helper("cleanup", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(marker.exists())

    def test_unset_and_empty_cleanup_identity_are_refused(self):
        for value in [None, ""]:
            with self.subTest(value=value):
                env = dict(self.env)
                if value is not None:
                    env["OPC_CI_DISK_TMPDIR"] = value
                result = self.run_helper("cleanup", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.runner.exists())

    def test_root_and_empty_runner_are_refused(self):
        for value in [None, "", "/", "relative", str(self.runner / "..")]:
            with self.subTest(value=value):
                env = dict(self.env)
                env.pop("RUNNER_TEMP", None)
                if value is not None:
                    env["RUNNER_TEMP"] = value
                self.assertNotEqual(self.run_helper("prepare", env=env).returncode, 0)

    def test_every_recorded_cleanup_value_is_required(self):
        scratch = self.prepare()
        marker = scratch / "keep"
        marker.write_text("data")
        for key in ["RUNNER_TEMP", "OPC_CI_DISK_PARENT", "OPC_CI_DISK_TMPDIR", "OPC_CI_DISK_TMPDIR_ID", "OPC_CI_DISK_PARENT_ID"]:
            for value in [None, ""]:
                with self.subTest(key=key, value=value):
                    env = dict(self.env)
                    env.pop(key)
                    if value is not None:
                        env[key] = value
                    self.assertNotEqual(self.run_helper("cleanup", env=env).returncode, 0)
                    self.assertEqual(marker.read_text(), "data")

    def test_valid_scratch_basename_outside_the_recorded_parent_is_refused(self):
        scratch = self.root / "opc-disk-scratch.Ab12Cd34"
        scratch.mkdir(mode=0o700)
        marker = scratch / "keep"
        marker.write_text("foreign")
        env = self.identity_env(self.runner, scratch)
        result = self.run_helper("cleanup", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated", result.stderr)
        self.assertEqual(marker.read_text(), "foreign")

    def test_replaced_parent_identity_is_refused(self):
        scratch = self.prepare()
        saved = self.runner.with_name("saved")
        self.runner.rename(saved)
        self.runner.mkdir()
        replacement = self.runner / scratch.name
        replacement.mkdir(mode=0o700)
        marker = replacement / "keep"
        marker.write_text("foreign")
        result = self.run_helper("cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parent identity changed", result.stderr)
        self.assertEqual(marker.read_text(), "foreign")

    def test_descendant_symlink_is_unlinked_without_following_it(self):
        scratch = self.prepare()
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_text("foreign")
        (scratch / "alias").symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_helper("cleanup").returncode, 0)
        self.assertFalse(scratch.exists())
        self.assertEqual(marker.read_text(), "foreign")

    def test_replacement_inode_and_symlink_root_are_refused(self):
        for symlink in [False, True]:
            with self.subTest(symlink=symlink):
                scratch = self.prepare()
                saved = scratch.with_name(scratch.name + ".saved")
                scratch.rename(saved)
                if symlink:
                    scratch.symlink_to(saved, target_is_directory=True)
                else:
                    scratch.mkdir()
                    (scratch / "keep").write_text("replacement")
                self.assertNotEqual(self.run_helper("cleanup").returncode, 0)
                self.assertTrue(saved.exists())
                if not symlink:
                    self.assertTrue((scratch / "keep").exists())

    def test_both_ram_filesystem_types_are_rejected_before_export(self):
        tools = self.root / "tools"
        tools.mkdir()
        stat = tools / "stat"
        stat.write_text('#!/bin/sh\nprintf "%s\\n" "$SCRATCH_TEST_MAGIC"\n')
        stat.chmod(0o755)
        for magic in RAM:
            with self.subTest(magic=magic):
                env = dict(self.env, PATH=str(tools) + os.pathsep + self.env["PATH"], SCRATCH_TEST_MAGIC=magic)
                result = self.run_helper("prepare", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("disk-backed", result.stderr)
                self.assertEqual(list(self.runner.iterdir()), [])
                self.assertFalse(Path(env["GITHUB_ENV"]).exists())

    def test_privileged_cleanup_is_rejected_outside_the_two_job_owners(self):
        scratch = self.prepare()
        marker = scratch / "keep"
        marker.write_text("data")
        for workflow, job in [("ci.yml", "session-net-i686-tests"), ("egress-fence.yml", "host-tests"),
                              ("performance.yml", "latency"), ("ci.yml", "privileged")]:
            with self.subTest(workflow=workflow, job=job):
                env = dict(self.env, GITHUB_ACTIONS="true", GITHUB_JOB=job,
                           GITHUB_WORKFLOW_REF=f"owner/repository/.github/workflows/{workflow}@refs/heads/test")
                result = self.run_helper("cleanup", "--privileged", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not allowed in this job", result.stderr)
                self.assertTrue(marker.exists())

    def test_sudo_failure_is_propagated_without_partial_cleanup(self):
        scratch = self.prepare()
        marker = scratch / "keep"
        marker.write_text("data")
        tools = self.root / "tools"
        tools.mkdir()
        sudo = tools / "sudo"
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SCRATCH_TEST_SUDO"\nexit 42\n')
        sudo.chmod(0o755)
        capture = self.root / "sudo-argv"
        env = dict(self.env, **CONTEXT, PATH=str(tools) + os.pathsep + self.env["PATH"], SCRATCH_TEST_SUDO=str(capture))
        result = self.run_helper("cleanup", "--privileged", env=env)
        self.assertEqual(result.returncode, 42)
        self.assertTrue(marker.exists())
        self.assertIn("privileged-cleanup", capture.read_text().splitlines())

    def privileged_fixture(self, mode):
        result = subprocess.run(["sudo", "-n", "unshare", "-m", "--propagation", "private", "--",
                                 "/usr/bin/python3", "-I", "-c", PRIVILEGED_FIXTURE,
                                 str(HELPER), str(self.root), str(os.getuid()), str(os.getgid()), mode],
                                env=dict(self.env, **CONTEXT), text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_privileged_cleanup_retires_root_owned_entries_quietly(self):
        self.privileged_fixture("ordinary")

    def test_search_only_ancestor_needs_no_read_permission(self):
        self.privileged_fixture("search-only")

    def test_privileged_cleanup_uses_recorded_parent_after_symlink_swap(self):
        self.privileged_fixture("symlink")

    def test_bind_mount_on_the_same_device_is_refused(self):
        self.privileged_fixture("bind")

    def test_foreign_filesystem_mount_is_refused(self):
        self.privileged_fixture("tmpfs")

    def test_sudo_revalidates_a_replaced_ancestor_before_deletion(self):
        self.privileged_fixture("sudo-race")

    def test_protected_move_rejects_a_replacement_inode_before_deletion(self):
        self.privileged_fixture("move-race")



if __name__ == "__main__":
    unittest.main()

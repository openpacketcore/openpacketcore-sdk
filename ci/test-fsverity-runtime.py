#!/usr/bin/env python3
"""Linux integration contracts for the private fs-verity filesystem owner.

These tests mount real images and require the same passwordless mount, chown,
umount and losetup privileges as the harness. Fixtures always clean their own
resources, including the leftovers from a deliberately interrupted old helper.
"""

import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "ci/setup-fsverity-tmp.sh"
SPEC = importlib.util.spec_from_file_location("fsverity_runtime", HARNESS.with_name("fsverity-runtime.py"))
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


def privileged(*args):
    return subprocess.run(
        ["/usr/bin/sudo", "-n", *map(str, args)], check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout


class SafetyTests(unittest.TestCase):
    """Controlled races use ordinary fixture files, never shared devices."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fsverity-safety-")
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def candidate(self, name, parent=None):
        path = (parent or self.runner) / (RUNTIME.PREFIX + name)
        path.mkdir(mode=0o700)
        (path / "ext4.img").write_bytes(b"fixture-owned image")
        (path / "tmp").mkdir(mode=0o700)
        if hasattr(RUNTIME, "mark_owned"):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                RUNTIME.mark_owned(descriptor)
            finally:
                os.close(descriptor)
        return path

    def guardian(self):
        guardian = RUNTIME.Guardian(-1)
        guardian.inventory = lambda **_kwargs: ([], [])
        return guardian

    def test_live_legacy_and_foreign_prefixes_are_preserved(self):
        # Both are legitimate pre-attachment layouts of other tools. Neither
        # participates in this owner's locks, even when its image is unopened.
        legacy = self.runner / "opc-fsverity.live"
        foreign = self.runner / "fs-verity-runtime.other-tool"
        for directory in (legacy, foreign):
            directory.mkdir(mode=0o700)
            (directory / "ext4.img").write_bytes(b"live pre-mount image")
            (directory / "tmp").mkdir(mode=0o700)
        (foreign / "mutable").mkdir()
        sentinel = foreign / "mutable" / "database"
        sentinel.write_bytes(b"other tool's mutable state")
        self.guardian().sweep(self.runner)
        self.assertEqual((legacy / "ext4.img").read_bytes(), b"live pre-mount image")
        self.assertEqual(sentinel.read_bytes(), b"other tool's mutable state")

    def renamed_during_inventory(self, release):
        stale = self.candidate("stale")
        active = self.candidate("active", self.root)
        sentinel = active / "must-survive"
        sentinel.write_text("locked active inode")
        descriptor = os.open(active, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guardian = self.guardian()
        parked = self.root / "parked-stale-inode"

        def inventory(**_kwargs):
            if not parked.exists():
                stale.rename(parked)
                active.rename(stale)
            return [], []

        guardian.inventory = inventory
        try:
            try:
                if release:
                    guardian.release(stale)
                else:
                    guardian.sweep(self.runner)
            except RuntimeError:
                pass  # Rejecting a changed name is the safe outcome.
            self.assertEqual((stale / "must-survive").read_text(), "locked active inode")
            self.assertGreater(os.fstat(descriptor).st_nlink, 0)
        finally:
            os.close(descriptor)

    def test_sweep_never_deletes_a_replacement_locked_inode(self):
        self.renamed_during_inventory(release=False)

    def test_release_never_deletes_a_replacement_locked_inode(self):
        self.renamed_during_inventory(release=True)

    def test_attachment_open_cannot_cross_inventory_and_delete(self):
        directory = self.candidate("attach-race")
        guardian = self.guardian()
        opened = []
        previous = signal.signal(signal.SIGIO, lambda *_args: None)

        def inventory(**_kwargs):
            try:
                # Models the backing-file open that precedes LOOP_CONFIGURE.
                opened.append(os.open(directory / "ext4.img", os.O_RDONLY | os.O_NONBLOCK))
            except BlockingIOError:
                pass  # An exclusive image lease serialized this open.
            return [], []

        guardian.inventory = inventory
        try:
            guardian.sweep(self.runner)
            for descriptor in opened:
                self.assertGreater(os.fstat(descriptor).st_nlink, 0,
                                   "deleted an image opened for concurrent attachment")
        finally:
            for descriptor in opened:
                os.close(descriptor)
            signal.signal(signal.SIGIO, previous)

    def test_fallback_cleanup_never_detaches_an_inventory_name(self):
        fixture = RuntimeTests()
        fixture.root = self.root
        fixture.runner = self.runner
        fixture.process = None
        fixture.extra_mounts = []
        fixture.extra_images = []
        fixture.temporary = unittest.mock.Mock()
        image = self.candidate("reuse") / "ext4.img"
        calls = []

        def fake_privileged(*arguments):
            calls.append(arguments)
            if arguments[:2] == ("losetup", "--associated"):
                return "/dev/loop123456\n"  # A fixture name, never a real device.
            return ""

        with patch(__name__ + ".privileged", side_effect=fake_privileged), \
                patch.object(RUNTIME, "detach_verified_loop", create=True) as detach, \
                patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1)), \
                patch.object(fixture, "wait_for_guardians", create=True):
            fixture.tearDown()
        self.assertNotIn(("losetup", "--detach", "/dev/loop123456"), calls)
        detach.assert_called_once_with(image, "/dev/loop123456")

    def test_captured_orphan_pipe_obeys_helper_deadline(self):
        # Keep subreaper state and finite descendants out of the test runner.
        program = '''
import ctypes, importlib.util, sys
spec = importlib.util.spec_from_file_location('runtime', sys.argv[1])
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
guardian = runtime.Guardian(-1)
expired = False
try:
    guardian.run([sys.executable, '-c', 'import os,time; child=os.fork(); os._exit(0) if child else time.sleep(.6)'],
                 capture=True, cleanup=True, timeout=.15)
except TimeoutError:
    expired = True
finally:
    guardian.reap_descendants()
assert expired, 'orphan-held output bypassed the helper deadline'
'''
        result = subprocess.run(["python3", "-c", program, str(HARNESS.with_name("fsverity-runtime.py"))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fsverity test-")
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.environment = os.environ | {
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_ENV": str(self.root / "github-env"),
        }
        self.process = None
        self.extra_mounts = []
        self.extra_images = []

    def images(self):
        return list(self.runner.glob("*/ext4.img")) + self.extra_images

    def attached(self):
        resources = []
        for image in self.images():
            loops = privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME")
            mounts = subprocess.run(
                ["findmnt", "--mountpoint", str(image.parent / "tmp"), "--noheadings"],
                capture_output=True, text=True, timeout=5,
            )
            if loops.strip() or mounts.returncode == 0:
                resources.append({"image": str(image), "loops": loops.strip(), "mounts": mounts.stdout.strip()})
        return resources

    def tearDown(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        # Even the RED must not strand a loop mount on the shared host.
        for mountpoint in reversed(self.extra_mounts):
            mounted = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, timeout=5,
            )
            if mounted.returncode == 0:
                privileged("umount", mountpoint)
        for image in self.images():
            mountpoint = image.parent / "tmp"
            mounted = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, timeout=5,
            )
            if mounted.returncode == 0:
                privileged("umount", mountpoint)
            for loop in privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").split():
                privileged("losetup", "--detach", loop)
        self.temporary.cleanup()

    def wait_for(self, predicate, description, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail(f"timed out waiting for {description}")

    def interrupted_setup(self, signum):
        ready = self.root / "mounted"
        shim = self.root / "bin"
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
subprocess.run(['/usr/bin/sudo', '-n', *arguments], check=True)
if arguments[0] == 'mount':
    Path(os.environ['MOUNT_READY']).write_text(str(os.getpid()))
    while True:
        signal.pause()
""")
        sudo.chmod(0o755)
        self.process = subprocess.Popen(
            [str(HARNESS), "--", "true"],
            env=self.environment | {"PATH": str(shim) + ":" + os.environ["PATH"], "MOUNT_READY": str(ready)},
            start_new_session=True,
        )
        self.wait_for(ready.exists, "the real loop mount")
        self.assertTrue(self.attached(), "fixture did not mount a real image")
        os.killpg(self.process.pid, signum)
        self.process.wait(timeout=10)
        # Give an independent cleanup guardian time to finish after interruption.
        deadline = time.monotonic() + 10
        while list(self.runner.iterdir()) and time.monotonic() < deadline:
            time.sleep(0.02)
        leftovers = {"directories": [str(p) for p in self.runner.iterdir()], "attached": self.attached()}
        print("interruption leftovers: " + json.dumps(leftovers), flush=True)
        self.assertEqual(leftovers, {"directories": [], "attached": []})

    def test_interrupted_setup_releases_mount_loop_and_image(self):
        """Interrupt after mount succeeds but before setup can export its root."""
        self.interrupted_setup(signal.SIGTERM)

    def test_killed_launcher_during_setup_releases_mount_loop_and_image(self):
        self.interrupted_setup(signal.SIGKILL)

    def run_command(self, *command, environment=None, expected=0):
        result = subprocess.run(
            [str(HARNESS), "--", *map(str, command)],
            env=self.environment | (environment or {}),
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_normal_exit_scopes_environment_and_removes_runtime(self):
        report = self.root / "report.json"
        ordinary = self.root / "mutable"
        ordinary.mkdir()
        original = "PRESERVED=1\n"
        Path(self.environment["GITHUB_ENV"]).write_text(original)
        self.run_command("python3", "-c", """
import json, os, pathlib, stat, sys
root = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
info = root.stat()
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'required': os.environ['OPC_FS_VERITY_QUALIFICATION'],
    'owner': info.st_uid, 'mode': stat.S_IMODE(info.st_mode),
    'snapshot_device': info.st_dev,
    'mutable_device': pathlib.Path(os.environ['TMPDIR']).stat().st_dev,
    'tmpdir': os.environ['TMPDIR'], 'root': str(root),
}))
""", report, environment={"TMPDIR": str(ordinary)})
        data = json.loads(report.read_text())
        self.assertEqual(data["required"], "required")
        self.assertEqual((data["owner"], data["mode"]), (os.getuid(), 0o700))
        self.assertNotEqual(data["snapshot_device"], data["mutable_device"])
        self.assertEqual(data["tmpdir"], str(ordinary))
        self.assertFalse(Path(data["root"]).exists())
        self.assertEqual(Path(self.environment["GITHUB_ENV"]).read_text(), original)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_failing_command_keeps_exit_status_and_removes_runtime(self):
        self.run_command("sh", "-c", "exit 37", expected=37)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_runtime_mount_is_not_visible_to_other_jobs(self):
        report = self.root / "snapshot-root"
        finish = self.root / "finish"
        self.process = subprocess.Popen(
            [str(HARNESS), "--", "python3", "-c", """
import os, pathlib, time
pathlib.Path(%r).write_text(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
deadline = time.monotonic() + 10
while not pathlib.Path(%r).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('parent did not finish mount visibility check')
    time.sleep(0.02)
""" % (str(report), str(finish))],
            env=self.environment, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            self.wait_for(report.exists, "wrapped command snapshot root")
            mountpoint = Path(report.read_text()).parent
            outside = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(outside.returncode, 1, outside.stdout + outside.stderr)
        finally:
            finish.touch()
            output, _ = self.process.communicate(timeout=10)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(self.attached(), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_restrictive_umask_preserves_private_root_and_cleanup(self):
        result = subprocess.run(
            [str(HARNESS), "--", "true"], env=self.environment,
            capture_output=True, text=True, timeout=20, umask=0o777,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_wrapped_command_retains_original_stdin(self):
        data = b"caller input\x00\n"
        result = subprocess.run(
            [str(HARNESS), "--", "python3", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            env=self.environment, input=data, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, data)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_private_namespace_does_not_pin_another_jobs_runtime_mount(self):
        other = self.root / "opc-fsverity.other-job"
        other.mkdir()
        image = other / "ext4.img"
        with image.open("xb") as stream:
            stream.truncate(32 * 1024**2)
        mountpoint = other / "tmp"
        mountpoint.mkdir()
        self.extra_images.append(image)
        self.extra_mounts.append(mountpoint)
        subprocess.run(["mkfs.ext4", "-q", str(image)], check=True, timeout=10)
        privileged("mount", "-o", "loop,nosuid,nodev", image, mountpoint)
        self.run_command("python3", "-c", """
import subprocess
result = subprocess.run(['findmnt', '--mountpoint', %r, '--noheadings'], capture_output=True)
assert result.returncode == 1, result.stdout
""" % str(mountpoint))
        # Dropping the copied mount must never unmount the original job's view.
        parent = subprocess.run(
            ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(parent.returncode, 0, parent.stderr)
        self.assertTrue(image.exists())

    def test_caller_lock_is_held_through_killed_launcher_cleanup(self):
        ready = self.root / "ready"
        lock = self.root / "caller-lock"
        with lock.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.process = subprocess.Popen(
                [str(HARNESS), "--", "python3", "-c", """
import pathlib, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(%r).touch()
time.sleep(10)
""" % str(ready)],
                env=self.environment, pass_fds=(stream.fileno(),), start_new_session=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        self.wait_for(ready.exists, "TERM-resistant command")
        self.process.kill()
        self.process.wait(timeout=5)
        with lock.open("w") as observer:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.wait_for(lambda: not list(self.runner.iterdir()), "guardian cleanup")
            self.wait_for(lambda: self.lock_available(observer), "caller lock release")
        self.process.communicate(timeout=5)
        self.assertEqual(self.attached(), [])

    @staticmethod
    def lock_available(stream):
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def test_cleanup_detaches_an_additional_binding_to_its_own_image(self):
        self.run_command("python3", "-c", """
import os, pathlib, subprocess
image = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT']).parents[1] / 'ext4.img'
subprocess.run(['sudo', '-n', 'losetup', '--find', '--show', str(image)], check=True)
""")
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_detach_refuses_a_different_backing_file(self):
        image = self.root / "image"
        with image.open("xb") as stream:
            stream.truncate(32 * 1024**2)
        self.extra_images.append(image)
        other = self.root / "other-image"
        other.write_bytes(b"different inode")
        loop = privileged("losetup", "--find", "--show", image).strip()
        result = subprocess.run(
            ["sudo", "-n", "python3", str(ROOT / "ci/fsverity-runtime.py"), "--detach-loop", str(other), loop],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to detach", result.stderr)
        self.assertEqual(privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").strip(), loop)

    def test_cleanup_waits_for_pending_loop_autoclear(self):
        ready = self.root / "ready"
        finish = self.root / "finish"
        held = self.root / "device-held"
        self.process = subprocess.Popen(
            [str(HARNESS), "--", "python3", "-c", """
import pathlib, time
pathlib.Path(%r).touch()
deadline = time.monotonic() + 10
while not pathlib.Path(%r).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('parent did not release command')
    time.sleep(0.02)
""" % (str(ready), str(finish))],
            env=self.environment, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.wait_for(ready.exists, "mounted runtime")
        image = self.images()[0]
        loop = privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").strip()
        # Model a device observer such as udev: LOOP_CLR_FD marks autoclear,
        # but the binding remains until this separate process closes its FD.
        observer = subprocess.Popen(["/usr/bin/sudo", "-n", "python3", "-c", """
import os, pathlib, time
descriptor = os.open(%r, os.O_RDONLY)
pathlib.Path(%r).touch()
time.sleep(1.5)
os.close(descriptor)
""" % (loop, str(held))])
        try:
            self.wait_for(held.exists, "external loop descriptor")
            finish.touch()
            output, _ = self.process.communicate(timeout=10)
        finally:
            observer.wait(timeout=5)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(self.attached(), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_preparation_failure_removes_runtime(self):
        shim = self.root / "bin"
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os, sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
if arguments[0] == 'chown':
    sys.exit(42)
os.execv('/usr/bin/sudo', ['sudo', '-n', *arguments])
""")
        sudo.chmod(0o755)
        self.run_command("true", environment={"PATH": str(shim) + ":" + os.environ["PATH"]}, expected=42)
        self.assertEqual(list(self.runner.iterdir()), [])

    def failing_sudo(self, operation):
        shim = self.root / ("bin-" + operation)
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os, sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
if arguments[0] == %r and (arguments[0] != 'umount' or
        arguments[-1].startswith(os.environ['RUNNER_TEMP'] + '/')):
    sys.exit(42)
os.execv('/usr/bin/sudo', ['sudo', '-n', *arguments])
""" % operation)
        sudo.chmod(0o755)
        return {"PATH": str(shim) + ":" + os.environ["PATH"]}

    def test_cleanup_failure_fails_gate_and_next_sweep_preserves_attachment(self):
        # An explicit extra binding survives destruction of the owner's private
        # mount namespace, keeping this an actually attached startup-sweep case.
        self.run_command("python3", "-c", """
import os, pathlib, subprocess
image = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT']).parents[1] / 'ext4.img'
subprocess.run(['sudo', '-n', 'losetup', '--find', '--show', str(image)], check=True)
""", environment=self.failing_sudo("umount"), expected=1)
        images = self.images()
        self.assertEqual(len(images), 1)
        self.assertTrue(self.attached())
        self.run_command("true")
        self.assertEqual(self.images(), images)
        self.assertTrue(self.attached())

    def test_inventory_failure_preserves_stale_directory(self):
        stale = self.runner / "fs-verity-runtime.stale"
        stale.mkdir(mode=0o700)
        image = stale / "ext4.img"
        image.write_bytes(b"retain without complete inventory")
        self.run_command("true", environment=self.failing_sudo("losetup"), expected=1)
        self.assertEqual(image.read_bytes(), b"retain without complete inventory")

    def test_signal_and_kill_during_command_release_resources(self):
        for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=signum):
                ready = self.root / f"ready-{signum}"
                self.process = subprocess.Popen(
                    [str(HARNESS), "--", "python3", "-c", """
import pathlib, signal, sys
pathlib.Path(sys.argv[1]).touch()
while True:
    signal.pause()
""", str(ready)], env=self.environment, start_new_session=True,
                )
                self.wait_for(ready.exists, "the wrapped command")
                os.killpg(self.process.pid, signum)
                self.process.wait(timeout=10)
                self.wait_for(lambda: not list(self.runner.iterdir()), "guardian cleanup")
                self.assertEqual(self.attached(), [])

    def test_escaped_term_resistant_descendant_is_reaped_before_unmount(self):
        report = self.root / "descendant"
        self.run_command("python3", "-c", """
import os, pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', '''
import os, pathlib, signal, sys
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.chdir(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
while True:
    signal.pause()
''', sys.argv[1]])
deadline = time.monotonic() + 5
while not pathlib.Path(sys.argv[1]).exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('descendant did not start')
    time.sleep(.01)
""", report)
        self.assertFalse(Path(f"/proc/{report.read_text()}").exists())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_orphan_is_reaped_while_the_wrapped_command_is_still_running(self):
        self.run_command("python3", "-c", """
import os, pathlib, subprocess, sys, time
parent = subprocess.Popen([sys.executable, '-c', '''
import os, sys
child = os.fork()
if child == 0:
    os._exit(0)
print(child, flush=True)
os._exit(0)
'''], stdout=subprocess.PIPE, text=True)
child = int(parent.stdout.read())
parent.wait(timeout=5)
deadline = time.monotonic() + 2
while pathlib.Path(f'/proc/{child}').exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('orphan zombie retained until the gate exits')
    time.sleep(.01)
""")
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_startup_sweeps_only_unattached_owned_unlocked_directories(self):
        stale = self.runner / "fs-verity-runtime.stale"
        stale.mkdir(mode=0o700)
        (stale / "ext4.img").write_bytes(b"unattached image")
        active = self.runner / "fs-verity-runtime.active"
        active.mkdir(mode=0o700)
        unknown = self.runner / "unrelated"
        unknown.mkdir(mode=0o700)
        public = self.runner / "fs-verity-runtime.public"
        public.mkdir(mode=0o755)
        symlink = self.runner / "fs-verity-runtime.symlink"
        symlink.symlink_to(unknown, target_is_directory=True)
        descriptor = os.open(active, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.run_command("true")
        finally:
            os.close(descriptor)
        self.assertFalse(stale.exists())
        self.assertEqual(set(self.runner.iterdir()), {active, unknown, public, symlink})

    def test_startup_reclaims_legacy_unattached_images(self):
        legacy = self.runner / "opc-fsverity.stale"
        legacy.mkdir(mode=0o700)
        (legacy / "ext4.img").write_bytes(b"old unattached image")
        outer = self.runner / "fs-verity-runtime.older"
        outer.mkdir(mode=0o700)
        nested = outer / "opc-fsverity.nested"
        nested.mkdir(mode=0o700)
        (nested / "ext4.img").write_bytes(b"old nested unattached image")
        self.run_command("true")
        self.assertFalse(legacy.exists())
        self.assertFalse(outer.exists())

    def test_startup_preserves_loop_backing_inode_even_through_other_path(self):
        for prefix in ("fs-verity-runtime.", "opc-fsverity."):
            with self.subTest(prefix=prefix):
                directory = self.runner / (prefix + "attached")
                directory.mkdir(mode=0o700)
                image = directory / "ext4.img"
                with image.open("xb") as stream:
                    stream.truncate(32 * 1024**2)
                outside = self.root / (prefix + "same-image-other-path")
                os.link(image, outside)
                self.extra_images.append(outside)
                loop = privileged("losetup", "--find", "--show", outside).strip()
                self.run_command("true")
                self.assertTrue(image.is_file())
                self.assertEqual(privileged("losetup", "--associated", outside, "--noheadings", "--output", "NAME").strip(), loop)

    def test_startup_preserves_a_mounted_directory_without_an_image(self):
        directory = self.runner / "fs-verity-runtime.mounted"
        directory.mkdir(mode=0o700)
        source = self.root / "bind-source"
        source.mkdir(mode=0o700)
        (source / "sentinel").write_text("preserve me")
        privileged("mount", "--bind", source, directory)
        self.extra_mounts.append(directory)
        self.run_command("true")
        self.assertEqual((directory / "sentinel").read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()

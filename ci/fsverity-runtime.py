#!/usr/bin/env python3
"""Run a Linux gate with private fs-verity storage and an interruption guardian.

Usage: ci/setup-fsverity-tmp.sh -- COMMAND [ARG ...]

Only the command receives the snapshot environment. Mutable TMPDIR, databases,
WALs and build output stay on ordinary storage. A detached child owns the mount
and watches a pipe held only by the launcher, so even SIGKILL of the launcher
initiates cleanup. The guardian is a subreaper: escaped command descendants are
disposed of before releasing their filesystem. Cleanup errors fail the gate.
"""

import ctypes
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time


PREFIX = "fs-verity-runtime."
SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def within(path, directory):
    return Path(path).is_relative_to(directory)


def walk_error(error):
    raise error


def detach_loop(image, loop):
    """Pin the device while verifying its backing inode and clearing it.

    A name-only inventory followed by losetup -d could detach a reused loop ID.
    Holding the device open prevents autoclear/reuse between verification and
    LOOP_CLR_FD. This small operation runs through sudo, like mount/umount.
    """
    descriptor = os.open(loop, os.O_RDONLY | os.O_CLOEXEC)
    try:
        status = fcntl.ioctl(descriptor, 0x4C05, bytes(232))  # LOOP_GET_STATUS64
        device, inode = struct.unpack_from("=QQ", status)
        info = os.stat(image, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or (device, inode) != (info.st_dev, info.st_ino):
            raise RuntimeError("loop backing identity changed; refusing to detach")
        fcntl.ioctl(descriptor, 0x4C01)  # LOOP_CLR_FD; closes after this descriptor.
    finally:
        os.close(descriptor)


class Guardian:
    def __init__(self, owner):
        self.owner = owner
        self.interrupted = False

    def stopping(self):
        if select.select([self.owner], [], [], 0)[0]:
            self.interrupted = True  # The launcher exited or was killed.
        return self.interrupted

    def run(self, command, *, capture=False, cleanup=False, timeout=30, env=None):
        process = subprocess.Popen(
            command, env=env, start_new_session=True,
            stdout=subprocess.PIPE if capture else None,
            text=True,
        )
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while process.poll() is None:
                self.reap_finished_adoptees(process.pid)
                if not cleanup and self.stopping():
                    raise InterruptedError("fs-verity command owner interrupted")
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError(f"fs-verity helper timed out: {command[0]}")
                try:
                    output, _ = process.communicate(timeout=0.05)
                except subprocess.TimeoutExpired:
                    continue
                break
            else:
                output, _ = process.communicate()
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
            return output
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)

    def reap_finished_adoptees(self, command_pid):
        # A subreaper must collect orphan zombies during a long-running gate,
        # not only when the gate exits. Popen retains its own child's status.
        children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text().split()
        for child in children:
            if int(child) != command_pid:
                os.waitpid(int(child), os.WNOHANG)

    def inventory(self):
        loops = json.loads(self.run(
            ["sudo", "-n", "losetup", "--list", "--json", "--output", "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN"],
            capture=True, cleanup=True,
        ))["loopdevices"]
        mounts = json.loads(self.run(
            ["findmnt", "--json", "--list", "--output", "TARGET,MAJ:MIN"],
            capture=True, cleanup=True,
        ))["filesystems"]
        return loops, mounts

    def attachments(self, directory):
        """Fail closed on inventory errors; compare backing inode, not loop ID."""
        loops, mounts = self.inventory()
        mounted = [mount for mount in mounts if within(mount["target"], directory)]
        if mounted:
            # A startup sweep must not traverse a mounted filesystem either.
            return [], mounted
        files = set()
        for root, _directories, names in os.walk(directory, followlinks=False, onerror=walk_error):
            for name in names:
                info = (Path(root) / name).lstat()
                if stat.S_ISREG(info.st_mode):
                    files.add((f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}", info.st_ino))
        attached = [loop for loop in loops if
                    (loop["back-maj:min"], loop["back-ino"]) in files
                    or within(loop["back-file"], directory)]
        return attached, mounted

    def sweep(self, root):
        for directory in root.glob(PREFIX + "*"):
            try:
                info = directory.lstat()
            except FileNotFoundError:
                continue  # Another owner completed cleanup during this scan.
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                continue
            try:
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except FileNotFoundError:
                continue
            try:
                opened = os.fstat(descriptor)
                if not opened.st_nlink:
                    continue
                if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode) != (info.st_dev, info.st_ino, info.st_uid, info.st_mode):
                    raise RuntimeError("fs-verity runtime changed during startup inspection")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                attached, mounted = self.attachments(directory)
                if attached or mounted:
                    print(f"fs-verity: retaining attached runtime {directory}", file=sys.stderr)
                    continue
                shutil.rmtree(directory)
            finally:
                os.close(descriptor)

    def reap_descendants(self):
        """Only this subreaper's own children may be signalled or waited for."""
        deadline = time.monotonic() + 6
        while True:
            while True:
                try:
                    child, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    return
                if not child:
                    break
            children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text().split()
            for child in children:
                try:
                    descriptor = os.pidfd_open(int(child))
                except ProcessLookupError:
                    continue
                try:
                    # A live, unreaped child cannot have its PID reused.
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(descriptor)
            if time.monotonic() >= deadline:
                raise TimeoutError("fs-verity command descendants did not exit")
            time.sleep(0.02)

    def release(self, directory):
        self.reap_descendants()
        attached, mounted = self.attachments(directory)
        mountpoint = str(directory / "tmp")
        if mounted:
            if len(mounted) != 1 or mounted[0]["target"] != mountpoint:
                raise RuntimeError("unexpected mounts in fs-verity runtime; retaining it")
            self.run(["sudo", "-n", "umount", "--", mountpoint], cleanup=True)
        # mount -o loop normally autoclears its loop on unmount. If it did not,
        # detach only a currently verified binding to our own backing file.
        attached, mounted = self.attachments(directory)
        for loop in attached:
            image = directory / "ext4.img"
            info = image.stat()
            if (loop["back-maj:min"], loop["back-ino"]) != (f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}", info.st_ino):
                raise RuntimeError("unexpected loop backing file; retaining fs-verity runtime")
            self.run(["sudo", "-n", sys.executable, str(Path(__file__).resolve()),
                      "--detach-loop", str(image), loop["name"]], cleanup=True)
        attached, mounted = self.attachments(directory)
        if attached or mounted:
            raise RuntimeError("fs-verity runtime still attached after cleanup")
        shutil.rmtree(directory)

    def execute(self, command):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "cannot become fs-verity subreaper")
        root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        directory = None
        descriptor = None
        root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Creation and startup sweep share a directory lock. Runtime locks
            # protect concurrent owners without PID files or age guesses.
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.stopping():
                        raise InterruptedError("fs-verity owner exited while waiting for startup lock")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("fs-verity startup lock timed out")
                    time.sleep(0.05)
            self.sweep(root)
            if self.stopping():
                raise InterruptedError("fs-verity owner exited during startup")
            directory = Path(tempfile.mkdtemp(prefix=PREFIX, dir=root))
            try:
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            except OSError:
                shutil.rmtree(directory)
                raise
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        finally:
            os.close(root_descriptor)
        try:
            image = directory / "ext4.img"
            mountpoint = directory / "tmp"
            mountpoint.mkdir()
            with image.open("xb") as stream:
                stream.truncate(4 * 1024**3)
            self.run(["mkfs.ext4", "-q", "-b", "4096", "-O", "verity", str(image)])
            self.run(["sudo", "-n", "mount", "-o", "loop,nosuid,nodev", str(image), str(mountpoint)])
            self.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
            snapshots = mountpoint / "snapshots"
            snapshots.mkdir(mode=0o700)
            info = snapshots.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise RuntimeError("fs-verity snapshot root must remain current-user private mode 0700")
            self.run(command, timeout=None, env=os.environ | {
                "OPC_FS_VERITY_SNAPSHOT_ROOT": str(snapshots.resolve(strict=True)),
                "OPC_FS_VERITY_QUALIFICATION": "required",
            })
            return 0
        except subprocess.CalledProcessError as error:
            return error.returncode if error.returncode > 0 else 128 - error.returncode
        except InterruptedError:
            return 143
        finally:
            try:
                self.release(directory)
            finally:
                os.close(descriptor)


def main():
    command = sys.argv[1:]
    if len(command) == 3 and command[0] == "--detach-loop":
        detach_loop(command[1], command[2])
        return 0
    if command[:1] == ["--"]:
        command = command[1:]
    if sys.platform != "linux" or not os.environ.get("RUNNER_TEMP") or not command:
        print("usage: RUNNER_TEMP=<private scratch root> ci/setup-fsverity-tmp.sh -- COMMAND [ARG ...] (Linux)", file=sys.stderr)
        return 2
    reader, writer = os.pipe()
    interrupted = None

    def interrupt(signum, _frame):
        nonlocal writer, interrupted
        interrupted = signum
        if writer is not None:
            os.close(writer)
            writer = None

    for signum in SIGNALS:
        signal.signal(signum, interrupt)
    child = os.fork()
    if child == 0:
        if writer is not None:
            os.close(writer)
        os.setsid()
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        guardian = Guardian(reader)
        for signum in SIGNALS:
            signal.signal(signum, lambda _signum, _frame: setattr(guardian, "interrupted", True))
        try:
            result = guardian.execute(command)
        except Exception as error:
            print(f"fs-verity: {error}", file=sys.stderr, flush=True)
            result = 1
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(result)
    os.close(reader)
    try:
        _, status = os.waitpid(child, 0)
        result = os.waitstatus_to_exitcode(status)
        return 128 + interrupted if interrupted else (result if result >= 0 else 128 - result)
    finally:
        if writer is not None:
            os.close(writer)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run a Linux gate with private fs-verity storage and an interruption guardian.

Usage: ci/setup-fsverity-tmp.sh -- COMMAND [ARG ...]

Only the command receives the snapshot environment. Mutable TMPDIR, databases,
WALs and build output stay on ordinary storage. A detached child owns the mount
in a private mount namespace and watches a pipe held only by the launcher, so
even SIGKILL of the launcher initiates cleanup. The guardian is a subreaper:
escaped command descendants are disposed of before releasing their filesystem.
Cleanup errors fail the gate.
"""

import array
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import secrets
import shutil
import signal
import socket
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
        try:
            status = fcntl.ioctl(descriptor, 0x4C05, bytes(232))  # LOOP_GET_STATUS64
        except OSError as error:
            if error.errno == errno.ENXIO:
                return  # Autoclear completed after the inventory was read.
            raise
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
        self.inherited_mounts = []

    def discard_inherited_runtime_mounts(self):
        # unshare initially clones the host's mounts. Drop our private copies
        # of unrelated runtime mounts so we cannot pin an older job's image.
        # Retain their inventory for the startup sweep: the original mounts
        # outside this namespace may still be attached.
        mounts = json.loads(self.run(
            ["findmnt", "--json", "--list", "--output", "TARGET,SOURCE"],
            capture=True, cleanup=True,
        ))["filesystems"]
        required = [Path.cwd().resolve(), Path(os.environ["RUNNER_TEMP"]).resolve()]
        if os.environ.get("TMPDIR"):
            required.append(Path(os.environ["TMPDIR"]).resolve())
        for mount in sorted(mounts, key=lambda item: len(Path(item["target"]).parts), reverse=True):
            target = Path(mount["target"])
            if (not mount["source"].startswith("/dev/loop")
                    or not any(part.startswith((PREFIX, "opc-fsverity.")) for part in target.parts)
                    or any(within(path, target) for path in required)):
                continue
            self.inherited_mounts.append(mount)
            self.run(["sudo", "-n", "umount", "--recursive", "--", str(target)], cleanup=True)

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
        mounted = [mount for mount in mounts + self.inherited_mounts if within(mount["target"], directory)]
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
        # Include images left by the former split-step setup helper, both
        # directly under RUNNER_TEMP and inside an old runtime parent.
        for directory in [*root.glob(PREFIX + "*"), *root.glob("opc-fsverity.*")]:
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
        # LOOP_CLR_FD may defer autoclear until a device observer closes its
        # descriptor. Keep the image and ownership lock until it really clears.
        deadline = time.monotonic() + 5
        while True:
            attached, mounted = self.attachments(directory)
            if not attached and not mounted:
                break
            if mounted or time.monotonic() >= deadline:
                raise RuntimeError("fs-verity runtime still attached after cleanup")
            time.sleep(0.05)
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
                directory.chmod(0o700)
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if descriptor is not None:
                    os.close(descriptor)
                shutil.rmtree(directory)
                raise
        finally:
            os.close(root_descriptor)
        try:
            image = directory / "ext4.img"
            mountpoint = directory / "tmp"
            mountpoint.mkdir(mode=0o700)
            mountpoint.chmod(0o700)
            with image.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.truncate(4 * 1024**3)
            self.run(["mkfs.ext4", "-q", "-b", "4096", "-O", "verity", str(image)])
            self.run(["sudo", "-n", "mount", "-o", "loop,nosuid,nodev", str(image), str(mountpoint)])
            self.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
            snapshots = mountpoint / "snapshots"
            snapshots.mkdir(mode=0o700)
            snapshots.chmod(0o700)
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


def receive_guardian(address, parent):
    # sudo closes inherited descriptors. Transfer the owner pipe, original
    # stdin and caller-owned locks only after returning to the caller's UID.
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.connect("\0" + address)
        peer, uid, _gid = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if peer != parent or uid != os.getuid():
            raise RuntimeError("unexpected fs-verity owner socket peer")
        data, ancillary, flags, _address = connection.recvmsg(
            1024**2, socket.CMSG_SPACE(253 * array.array("i").itemsize))
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise RuntimeError("incomplete fs-verity owner descriptor transfer")
    message = json.loads(data)
    descriptors = array.array("i")
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(value)
    targets = message["targets"]
    if len(descriptors) != len(targets) + 1:
        raise RuntimeError("missing fs-verity owner descriptors")
    # Copy above every source/target first, so restoring an inherited FD cannot
    # overwrite another received descriptor that has not been restored yet.
    minimum = max([*descriptors, *targets]) + 1
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, minimum) for fd in descriptors]
    for fd in descriptors:
        os.close(fd)
    owner = copies[0]
    for source, target in zip(copies[1:], targets):
        os.dup2(source, target, inheritable=True)
        os.close(source)
    os.environ.clear()
    os.environ.update(message["environment"])
    if os.readlink("/proc/self/ns/mnt") == message["namespace"]:
        raise RuntimeError("fs-verity guardian did not enter a private mount namespace")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    guardian = Guardian(owner)
    for signum in SIGNALS:
        signal.signal(signum, lambda _signum, _frame: setattr(guardian, "interrupted", True))
    guardian.discard_inherited_runtime_mounts()
    return guardian.execute(message["command"])


def launch(command):
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
    process = None
    try:
        # Abstract sockets leave no filesystem entry after an interrupted
        # bootstrap, and do not depend on RUNNER_TEMP's pathname length.
        address = "fs-verity-owner-" + secrets.token_hex(24)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
            server.bind("\0" + address)
            server.listen(1)
            server.settimeout(0.05)
            targets = [0]
            for name in Path("/proc/self/fd").iterdir():
                fd = int(name.name)
                try:
                    if fd > 2 and os.get_inheritable(fd):
                        targets.append(fd)
                except OSError:
                    continue  # The directory iterator's transient descriptor.
            if len(targets) + 1 > 253:
                raise RuntimeError("too many inherited fs-verity owner descriptors")
            groups = ",".join(map(str, os.getgroups()))
            group_args = ["--groups", groups] if groups else ["--clear-groups"]
            # Mounts must not enter the host namespace: an unrelated job could
            # otherwise inherit one and keep the loop pinned after our exit.
            # Drop privilege before executing Python or restoring user env.
            process = subprocess.Popen([
                "/usr/bin/sudo", "-n", "/usr/bin/unshare", "--mount", "--propagation", "private", "--",
                "/usr/bin/setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()),
                *group_args, "--", sys.executable, str(Path(__file__).resolve()),
                "--guardian", address, str(os.getpid()),
            ], start_new_session=True)
            deadline = time.monotonic() + 30
            while True:
                try:
                    connection, _ = server.accept()
                    break
                except socket.timeout:
                    if process.poll() is not None:
                        raise subprocess.CalledProcessError(process.returncode or 1, "fs-verity namespace bootstrap")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("fs-verity namespace bootstrap timed out")
            with connection:
                connection.settimeout(30)
                _peer, uid, _gid = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != os.getuid():
                    raise RuntimeError("unexpected fs-verity guardian socket peer")
                message = json.dumps({"targets": targets, "environment": dict(os.environ),
                                      "namespace": os.readlink("/proc/self/ns/mnt"), "command": command})
                connection.sendmsg([message.encode()], [(
                    socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [reader, *targets]))])
        os.close(reader)
        reader = None
        result = process.wait()
        return 128 + interrupted if interrupted else (result if result >= 0 else 128 - result)
    finally:
        if writer is not None:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        if process is not None:
            process.wait()  # The guardian retains caller locks through cleanup.


def main():
    command = sys.argv[1:]
    if len(command) == 3 and command[0] == "--detach-loop":
        detach_loop(command[1], command[2])
        return 0
    if len(command) == 3 and command[0] == "--guardian":
        return receive_guardian(command[1], int(command[2]))
    if command[:1] == ["--"]:
        command = command[1:]
    if sys.platform != "linux" or not os.environ.get("RUNNER_TEMP") or not command:
        print("usage: RUNNER_TEMP=<private scratch root> ci/setup-fsverity-tmp.sh -- COMMAND [ARG ...] (Linux)", file=sys.stderr)
        return 2
    return launch(command)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"fs-verity: {error}", file=sys.stderr, flush=True)
        sys.exit(1)

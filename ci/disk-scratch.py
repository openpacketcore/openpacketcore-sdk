#!/usr/bin/env python3
"""Prepare private disk scratch and retire only its recorded directory identity."""

import contextlib
import ctypes
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import string
import subprocess
import sys

DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
ANCESTOR = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
ALLOWED = {("ci.yml", "rust-local-kernel-lifecycle"), ("ipsec-xfrm.yml", "privileged")}
RAM = {0x1021994, 0x858458F6}


def identity(fd):
    info = os.fstat(fd)
    return f"{info.st_dev}:{info.st_ino}"


def mount_id(fd):
    for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
        if line.startswith("mnt_id:"):
            return int(line.split()[1])
    raise RuntimeError("cannot verify scratch mount identity")


def canonical_parts(path):
    if (not path or not path.startswith("/") or path == "/"
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            or any(ord(c) < 32 for c in path)):
        raise RuntimeError("scratch paths must be absolute, canonical, and non-root")
    return path.split("/")[1:]


@contextlib.contextmanager
def open_parent(path, uid):
    parts = canonical_parts(path)
    descriptors = [os.open("/", ANCESTOR)]
    try:
        for index, part in enumerate(parts):
            flags = DIRECTORY if index == len(parts) - 1 else ANCESTOR
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        parent = descriptors[-1]
        info = os.fstat(parent)
        if info.st_uid != uid or info.st_mode & 0o300 != 0o300:
            raise RuntimeError("runner scratch parent must be owned and writable by the caller")
        if os.readlink(f"/proc/self/fd/{parent}") != path:
            raise RuntimeError("runner scratch parent moved while it was being verified")
        yield parent, descriptors
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def prepare():
    runner = os.environ.get("RUNNER_TEMP", "")
    environment = os.environ.get("GITHUB_ENV", "")
    if not environment:
        raise RuntimeError("GITHUB_ENV is required")
    # Resolve a runner's stable setup path once. Cleanup never resolves this
    # potentially symlinked spelling: it uses the pinned, recorded parent.
    canonical_parts(runner)
    runner = os.path.realpath(runner, strict=True)
    with open_parent(runner, os.getuid()) as (parent, _):
        name = "opc-disk-scratch." + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        os.mkdir(name, 0o700, dir_fd=parent)
        try:
            fd = os.open(name, DIRECTORY, dir_fd=parent)
            try:
                magic = int(subprocess.check_output(
                    ["stat", "-f", "-c", "%t", "--", f"/proc/self/fd/{fd}"],
                    pass_fds=(fd,), text=True).strip(), 16)
                if magic in RAM:
                    raise RuntimeError("durable tests require disk-backed runner scratch")
                scratch = runner + "/" + name
                values = {"TMPDIR": scratch, "OPC_CI_DISK_TMPDIR": scratch, "OPC_CI_DISK_PARENT": runner,
                          "OPC_CI_DISK_TMPDIR_ID": identity(fd), "OPC_CI_DISK_PARENT_ID": identity(parent)}
                with open(environment, "a", encoding="utf-8") as output:
                    output.write("".join(f"{key}={value}\n" for key, value in values.items()))
            finally:
                os.close(fd)
        except BaseException:
            os.rmdir(name, dir_fd=parent)
            raise


def allowed_job(workflow, job):
    match = re.fullmatch(r"[^/@\s]+/[^/@\s]+/\.github/workflows/([^/@\s]+)@[^\s]+", workflow)
    if match is None or (match[1], job) not in ALLOWED:
        raise RuntimeError("privileged scratch cleanup is not allowed in this job")


def checked_values(runner, scratch, expected, parent_identity):
    canonical_parts(runner)
    canonical_parts(scratch)
    name = scratch.rsplit("/", 1)[1]
    if scratch != runner + "/" + name or not re.fullmatch(r"opc-disk-scratch\.[A-Za-z0-9]{8}", name):
        raise RuntimeError("refusing to remove unrelated runner scratch")
    if not all(re.fullmatch(r"[0-9]+:[1-9][0-9]*", value) for value in [expected, parent_identity]):
        raise RuntimeError("recorded scratch and parent identities are required")
    return name


def open_scratch(parent, name, expected, uid):
    try:
        fd = os.open(name, DIRECTORY, dir_fd=parent)
    except FileNotFoundError:
        return None
    info = os.fstat(fd)
    if identity(fd) != expected or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise RuntimeError("scratch identity, owner or permissions changed")
    return fd


def entry_identity(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    return f"{info.st_dev}:{info.st_ino}"


def rename_new(source, name, destination, new_name):
    # RENAME_NOREPLACE never overwrites a binding created by another actor.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(source, os.fsencode(name), destination, os.fsencode(new_name), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


@contextlib.contextmanager
def frozen(fd, privileged):
    info = os.fstat(fd)
    try:
        if privileged:
            os.fchown(fd, 0, -1)
            os.fchmod(fd, 0o700)
        yield
    finally:
        if privileged:
            # Restore only the pinned inode, including on a refused deletion.
            os.fchown(fd, info.st_uid, info.st_gid)
            os.fchmod(fd, stat.S_IMODE(info.st_mode))


def remove_contents(directory, device, mounting, privileged):
    for name in os.listdir(directory):
        node = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(node)
            # Stronger than rm --one-file-system: mount ID also catches bind
            # mounts whose backing directory is on the same device.
            if info.st_dev != device or mount_id(node) != mounting:
                raise RuntimeError("refusing to cross a scratch mount point")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, DIRECTORY, dir_fd=directory)
                try:
                    if identity(child) != identity(node) or mount_id(child) != mounting:
                        raise RuntimeError("scratch child changed while pinning")
                    with frozen(child, privileged):
                        remove_contents(child, device, mounting, privileged)
                        os.rmdir(name, dir_fd=directory)
                finally:
                    os.close(child)
            else:
                os.unlink(name, dir_fd=directory)
        finally:
            os.close(node)


@contextlib.contextmanager
def protected_staging(ancestors, directory):
    # A root-owned parent protects the staging binding, even from a caller
    # that already opened the runner parent before privileged cleanup.
    device, mounting = os.fstat(directory).st_dev, mount_id(directory)
    parent = None
    for candidate in ancestors:
        info = os.fstat(candidate)
        if (info.st_dev == device and mount_id(candidate) == mounting and info.st_uid == 0
                and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX)):
            parent = candidate
            break
    if parent is None:
        raise RuntimeError("scratch has no protected staging ancestor on its mount")
    name = ".opc-disk-scratch-cleanup." + secrets.token_hex(16)
    os.mkdir(name, 0o700, dir_fd=parent)
    staging = os.open(name, DIRECTORY, dir_fd=parent)
    try:
        yield staging
    finally:
        empty = not os.listdir(staging)
        os.close(staging)
        if empty:
            os.rmdir(name, dir_fd=parent)
        else:
            print("::error::preserved occupied scratch staging directory: "
                  + os.readlink(f"/proc/self/fd/{parent}") + "/" + name, file=sys.stderr)


def cleanup(runner, scratch, expected, parent_identity, uid, privileged=False):
    name = checked_values(runner, scratch, expected, parent_identity)
    with open_parent(runner, uid) as (parent, ancestors):
        if identity(parent) != parent_identity:
            raise RuntimeError("runner scratch parent identity changed")
        directory = open_scratch(parent, name, expected, uid)
        if directory is None:
            return
        try:
            device, mounting = os.fstat(directory).st_dev, mount_id(directory)
            if privileged:
                with protected_staging(ancestors, directory) as staging:
                    moved = False
                    try:
                        rename_new(parent, name, staging, "scratch")
                        moved = True
                        # The move may have captured a replacement. No caller
                        # can change this root-owned binding after this check.
                        if entry_identity(staging, "scratch") != expected:
                            raise RuntimeError("scratch binding changed before protected removal")
                        with frozen(directory, True):
                            remove_contents(directory, device, mounting, True)
                            os.rmdir("scratch", dir_fd=staging)
                        moved = False
                    finally:
                        if moved:
                            rename_new(staging, "scratch", parent, name)
            else:
                remove_contents(directory, device, mounting, False)
                if entry_identity(parent, name) != expected:
                    raise RuntimeError("scratch binding changed before final retirement")
                os.rmdir(name, dir_fd=parent)
        finally:
            os.close(directory)


def main():
    os.umask(0o077)
    args = sys.argv[1:]
    if args == ["prepare"]:
        prepare()
        return 0
    if args in [["cleanup"], ["cleanup", "--privileged"]]:
        # Require valid runner metadata, but never resolve or traverse it for
        # deletion; the recorded physical parent is the sole path authority.
        canonical_parts(os.environ.get("RUNNER_TEMP", ""))
        values = [os.environ.get(key, "") for key in
                  ["OPC_CI_DISK_PARENT", "OPC_CI_DISK_TMPDIR", "OPC_CI_DISK_TMPDIR_ID", "OPC_CI_DISK_PARENT_ID"]]
        checked_values(*values)
        if len(args) == 2:
            workflow, job = os.environ.get("GITHUB_WORKFLOW_REF", ""), os.environ.get("GITHUB_JOB", "")
            allowed_job(workflow, job)
            # Do not attempt a partial unprivileged deletion before sudo.
            return subprocess.run(["sudo", "-n", "/usr/bin/python3", "-I", str(Path(__file__).resolve()),
                                   "privileged-cleanup", *values, workflow, job], check=False).returncode
        cleanup(*values, os.getuid())
        return 0
    if args and args[0] == "privileged-cleanup" and len(args) == 7:
        if os.geteuid() != 0 or not os.environ.get("SUDO_UID", "").isdigit():
            raise RuntimeError("privileged scratch cleanup requires sudo caller identity")
        allowed_job(args[5], args[6])
        cleanup(*args[1:5], int(os.environ["SUDO_UID"]), privileged=True)
        return 0
    raise RuntimeError("usage: disk-scratch.sh prepare | cleanup [--privileged]")


if __name__ == "__main__":
    # Normal termination restores a refused/staged directory. SIGKILL can
    # preserve a protected residue, but cannot redirect deletion by pathname.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1) from None

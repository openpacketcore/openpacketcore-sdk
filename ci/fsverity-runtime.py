#!/usr/bin/env python3
"""Run a Linux gate with private fs-verity storage and an interruption guardian.

Usage: ci/setup-fsverity-tmp.sh -- COMMAND [ARG ...]

Only the command receives the snapshot environment. Mutable TMPDIR, databases,
WALs and build output stay on ordinary storage. A detached child owns the mount
in a separate mount namespace with slave propagation and watches a pipe held
only by the launcher, so
even SIGKILL of the launcher initiates cleanup. The guardian is a subreaper:
escaped command descendants are disposed of before releasing their filesystem.
Cleanup errors fail the gate.
"""

import array
import ctypes
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


PREFIX = "opc-sdk-fsverity-runtime."
OWNER_ATTRIBUTE = "user.opc_sdk_fsverity_owner"
GUARDIAN_ATTRIBUTE = "user.opc_sdk_fsverity_guardian"
STAGING_ATTRIBUTE = "user.opc_sdk_fsverity_staging"
STAGING_PREFIX = ".opc-sdk-fsverity-remove."
OWNER_ID = str(Path(__file__).resolve().parent.parent).encode()
SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
CLEANUP_HELPER_SECONDS = 30


def within(path, directory):
    return Path(path).is_relative_to(directory)


def identity(descriptor):
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def mark_owned(descriptor):
    os.setxattr(descriptor, OWNER_ATTRIBUTE, OWNER_ID)


def is_owned(descriptor, *, uid=None):
    info = os.fstat(descriptor)
    try:
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == (os.getuid() if uid is None else uid)
                and stat.S_IMODE(info.st_mode) == 0o700
                and os.getxattr(descriptor, OWNER_ATTRIBUTE) == OWNER_ID)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP):
            return False
        raise


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("fs-verity cleanup deadline expired")
    return value


def send_message(connection, message, descriptors=()):
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))] if descriptors else []
    connection.sendmsg([json.dumps(message).encode()], ancillary)


def receive_message(connection):
    data, ancillary, flags, _address = connection.recvmsg(1024**2, socket.CMSG_SPACE(253 * 4))
    descriptors = []
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.extend(array.array("i", value))
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("incomplete fs-verity descriptor transfer")
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        return json.loads(data), descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def verify_loop(image, descriptor, *, missing_ok=False):
    info = os.fstat(descriptor)
    if not stat.S_ISBLK(info.st_mode) or os.major(info.st_rdev) != 7:
        raise RuntimeError("refusing to detach a non-device")
    try:
        status = fcntl.ioctl(descriptor, 0x4C05, bytes(232))  # LOOP_GET_STATUS64
    except OSError as error:
        if error.errno == errno.ENXIO:
            return False
        raise
    if struct.unpack_from("=QQ", status) != identity(image):
        if missing_ok:
            return False  # An inventory name was already cleared and reused.
        raise RuntimeError("loop backing identity changed; refusing to detach")
    return True


def configure_loop(image, deadline):
    control = os.open("/dev/loop-control", os.O_RDWR | os.O_CLOEXEC)
    try:
        while True:
            remaining(deadline)
            number = fcntl.ioctl(control, 0x4C82)  # LOOP_CTL_GET_FREE
            descriptor = os.open(f"/dev/loop{number}", os.O_RDWR | os.O_CLOEXEC)
            try:
                config = bytearray(304)  # struct loop_config from linux/loop.h
                struct.pack_into("=I", config, 0, image)
                struct.pack_into("=I", config, 60, 4)  # LO_FLAGS_AUTOCLEAR
                fcntl.ioctl(descriptor, 0x4C0A, config)  # LOOP_CONFIGURE, on the pinned FD
                return descriptor, number
            except OSError as error:
                os.close(descriptor)
                if error.errno != errno.EBUSY:
                    raise
    finally:
        os.close(control)


def process_stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[1]), int(fields[19])  # PPID, starttime


def open_loop(path):
    # O_PATH cannot block on a FIFO or activate a device. Reopen this same
    # checked inode through procfs, never by resolving the caller's name again.
    node = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(node)
        if not stat.S_ISBLK(info.st_mode) or os.major(info.st_rdev) != 7:
            raise RuntimeError("refusing to open a non-loop device")
        descriptor = os.open(f"/proc/self/fd/{node}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        if identity(descriptor) != identity(node) or os.fstat(descriptor).st_rdev != info.st_rdev:
            os.close(descriptor)
            raise RuntimeError("loop device identity changed while pinning")
        return descriptor
    finally:
        os.close(node)


def rename_new(source, name, destination, new_name):
    """Move without ever replacing a destination that another actor created."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(source, os.fsencode(name), destination, os.fsencode(new_name), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def validate_parent(parent, uid, directory=None):
    info = os.fstat(parent)
    if info.st_uid != uid or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o300 != 0o300:
        raise RuntimeError("runtime parent must be writable and owned by the caller")
    if directory is not None:
        above = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            if identity(above) != identity(parent):
                raise RuntimeError("runtime parent does not contain the pinned directory")
        finally:
            os.close(above)


@contextmanager
def exclusive(descriptor, deadline):
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            time.sleep(min(.05, remaining(deadline)))
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def staging_root(parent, uid, deadline):
    """Persistent, checkout-specific metadata; only root can write inside.

    An empty anchor interrupted before its marker is written is safe to finish
    initializing. Transaction creation/marking is serialized here, so an empty
    unmarked transaction interrupted during mkdir is also recoverable. No live
    runtime can ever be put in an unmarked transaction.
    """
    ancestor = os.dup(parent)
    descriptor = None
    name = ".opc-sdk-fsverity-staging." + str(uid) + "." + hashlib.sha256(OWNER_ID).hexdigest()[:24]
    marker = json.dumps({"owner": OWNER_ID.decode(), "uid": uid}, sort_keys=True).encode()
    try:
        device = os.fstat(parent).st_dev
        while True:
            remaining(deadline)
            info = os.fstat(ancestor)
            if info.st_uid == 0 and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX):
                break
            above = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
            if os.fstat(above).st_dev != device or identity(above) == identity(ancestor):
                os.close(above)
                raise RuntimeError("no protected ancestor on runtime filesystem; retaining runtime")
            os.close(ancestor)
            ancestor = above
        try:
            os.mkdir(name, mode=0o700, dir_fd=ancestor)
        except FileExistsError:
            pass
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
        info = os.fstat(descriptor)
        if info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0 and not os.listdir(descriptor):
            os.fchmod(descriptor, 0o700)  # Interrupted mkdir, or restrictive caller umask.
            info = os.fstat(descriptor)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("untrusted fs-verity staging root")
        with exclusive(descriptor, deadline):
            try:
                observed = os.getxattr(descriptor, STAGING_ATTRIBUTE)
            except OSError as error:
                if error.errno != errno.ENODATA or os.listdir(descriptor):
                    raise
                os.setxattr(descriptor, STAGING_ATTRIBUTE, marker)
                os.fsync(descriptor)
                os.fsync(ancestor)
                observed = marker
            if observed != marker:
                raise RuntimeError("fs-verity staging root belongs to another owner")
            yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(ancestor)


@contextmanager
def protected_directory(parent, deadline, *, uid, transaction):
    """Root-only transaction namespace with a durable recovery identity."""
    descriptor = anchor = None
    name = STAGING_PREFIX + secrets.token_hex(16)
    try:
        with staging_root(parent, uid, deadline) as root:
            anchor = os.dup(root)
            os.mkdir(name, mode=0o700, dir_fd=root)
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            os.fchmod(descriptor, 0o700)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = {"owner": OWNER_ID.decode(), "uid": uid, "parent": identity(parent),
                      "pid": os.getpid(), "start": process_stat(os.getpid())[1],
                      "boot": Path('/proc/sys/kernel/random/boot_id').read_text().strip(), **transaction}
            os.setxattr(descriptor, STAGING_ATTRIBUTE, json.dumps(record).encode())
            os.fsync(descriptor)
            os.fsync(root)  # Persist authority before changing runtime ownership.
        yield descriptor
    finally:
        if descriptor is not None:
            try:
                if not os.listdir(descriptor):
                    os.rmdir(name, dir_fd=anchor)
                else:
                    print(f"fs-verity: retaining recoverable staging directory {name}", file=sys.stderr)
            finally:
                os.close(descriptor)
        if anchor is not None:
            os.close(anchor)


def create_runtime(parent, name, uid, gid, deadline):
    validate_parent(parent, uid)
    directory = image = temporary = None
    published = False
    try:
        with protected_directory(parent, deadline, uid=uid,
                                 transaction={"action": "create", "name": name}) as staging:
            os.mkdir("runtime", mode=0o700, dir_fd=staging)
            try:
                directory = os.open("runtime", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging)
                os.fchmod(directory, 0o700)
                os.mkdir("tmp", mode=0o700, dir_fd=directory)
                temporary = os.open("tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.fchmod(temporary, 0o700)
                image = os.open("ext4.img", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=directory)
                os.fchmod(image, 0o600)
                os.ftruncate(image, 4 * 1024**3)
                mark_owned(directory)
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for descriptor in (temporary, image, directory):
                    os.fchown(descriptor, uid, gid)
                remaining(deadline)
                rename_new(staging, "runtime", parent, name)
                published = True
                return [directory, image]
            finally:
                if not published:
                    # Nothing has been published or handed to the caller: only
                    # root can address these entries in the protected parent.
                    if directory is not None:
                        if "ext4.img" in os.listdir(directory):
                            os.unlink("ext4.img", dir_fd=directory)
                        if "tmp" in os.listdir(directory):
                            os.rmdir("tmp", dir_fd=directory)
                    os.rmdir("runtime", dir_fd=staging)
    finally:
        if temporary is not None:
            os.close(temporary)
        if not published:
            for descriptor in (image, directory):
                if descriptor is not None:
                    os.close(descriptor)


def remove_verified_runtime(parent, directory, image, temporary, name, uid, deadline):
    validate_parent(parent, uid, directory)
    if not is_owned(directory, uid=uid):
        return False
    image_info, tmp_info = os.fstat(image), os.fstat(temporary)
    if (not stat.S_ISREG(image_info.st_mode) or image_info.st_uid != uid or image_info.st_nlink != 1
            or not stat.S_ISDIR(tmp_info.st_mode) or tmp_info.st_uid != uid
            or stat.S_IMODE(tmp_info.st_mode) != 0o700
            or fcntl.fcntl(image, fcntl.F_GETLEASE) != fcntl.F_WRLCK):
        return False
    moved = False
    transaction = {"action": "remove", "name": name, "directory": identity(directory),
                   "image": identity(image), "temporary": identity(temporary)}
    with protected_directory(parent, deadline, uid=uid, transaction=transaction) as staging:
        try:
            # Freeze precisely the pinned directories. Even an actor that
            # opened these directories before staging cannot replace entries
            # via its old dirfds after their ownership changes to root.
            os.fchown(directory, 0, -1)
            os.fchmod(directory, 0o700)
            os.fchown(temporary, 0, -1)
            os.fchmod(temporary, 0o700)
            if (set(os.listdir(directory)) != {"ext4.img", "tmp"} or os.listdir(temporary)
                    or Guardian.entry_identity(directory, "ext4.img") != identity(image)
                    or Guardian.entry_identity(directory, "tmp") != identity(temporary)):
                return False
            remaining(deadline)
            rename_new(parent, name, staging, "runtime")
            moved = True
            # renameat2 may have moved a replacement: check AFTER the move into
            # the protected namespace, before any unlink or rmdir. No caller
            # can change these bindings between this check and deletion.
            if Guardian.entry_identity(staging, "runtime") != identity(directory):
                raise RuntimeError("runtime binding changed before protected removal")
            os.unlink("ext4.img", dir_fd=directory)
            os.rmdir("tmp", dir_fd=directory)
            os.rmdir("runtime", dir_fd=staging)
            moved = False
            return True
        finally:
            try:
                if moved:
                    rename_new(staging, "runtime", parent, name)
            finally:
                # Restore only our pinned inodes, including on a refused move;
                # never chown an entry looked up again by name.
                os.fchown(temporary, tmp_info.st_uid, tmp_info.st_gid)
                os.fchown(directory, uid, -1)


def recover_transaction(parent, staging, record, uid, deadline):
    """Resume only the pinned identities recorded before privileged takeover."""
    name = record["name"]
    if not name.startswith(PREFIX) or "/" in name or record["action"] not in ("create", "remove"):
        raise RuntimeError("invalid fs-verity recovery record")
    entries = set(os.listdir(staging))
    if not entries <= {"runtime"}:
        raise RuntimeError("unexpected entries in fs-verity recovery transaction")
    location, runtime_name = (staging, "runtime") if entries else (parent, name)
    if not entries and record["action"] == "create":
        return True  # Published creation is caller-owned, reclaimed by ordinary sweep.
    if not entries:
        # A failed restore may have renamed the frozen original within this
        # parent. Its journaled inode, not a fresh pathname match, is authority.
        runtime_name = None
        for candidate in os.listdir(parent):
            remaining(deadline)
            try:
                if list(Guardian.entry_identity(parent, candidate)) == record["directory"]:
                    runtime_name = candidate
                    break
            except FileNotFoundError:
                continue
        if runtime_name is None:
            return True
    try:
        directory = os.open(runtime_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=location)
    except FileNotFoundError:
        return False
    temporary = image = None
    leased = False
    previous = signal.signal(signal.SIGIO, lambda *_args: None)
    try:
        info = os.fstat(directory)
        if record["action"] == "remove" and list(identity(directory)) != record["directory"]:
            if location == staging:
                # The interrupted helper moved a substituted object. Preserve
                # it by moving it back; never delete or chown that foreign inode.
                try:
                    rename_new(staging, "runtime", parent, name)
                except FileExistsError:
                    rename_new(staging, "runtime", parent, PREFIX + "restored." + secrets.token_hex(16))
            return False
        # A restrictive umask can leave mkdir's root-owned inode at mode 000
        # before create reaches fchmod, still inside authenticated staging.
        modes = (0, 0o700) if (record["action"] == "create" and location == staging
                              and info.st_uid == 0) else (0o700,)
        if info.st_uid not in (0, uid) or stat.S_IMODE(info.st_mode) not in modes:
            return
        if record["action"] == "remove" and not is_owned(directory, uid=info.st_uid):
            return
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        # Creation may have stopped before its first child/marker was made;
        # only an authenticated, root-only create transaction permits that.
        contents = set(os.listdir(directory))
        if not contents <= {"ext4.img", "tmp"}:
            return
        if "tmp" in contents:
            temporary = os.open("tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            tmp_info = os.fstat(temporary)
            if (tmp_info.st_uid not in (0, uid) or stat.S_IMODE(tmp_info.st_mode) not in (0, 0o700)
                    or os.listdir(temporary) or tmp_info.st_dev != info.st_dev
                    or record["action"] == "remove" and list(identity(temporary)) != record["temporary"]):
                return
        if "ext4.img" in contents:
            node = os.open("ext4.img", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                image_info = os.fstat(node)
                if (not stat.S_ISREG(image_info.st_mode) or image_info.st_uid not in (0, uid)
                        or image_info.st_nlink != 1
                        or record["action"] == "remove" and list(identity(node)) != record["image"]):
                    return
                image = os.open(f"/proc/self/fd/{node}", os.O_RDWR | os.O_CLOEXEC)
            finally:
                os.close(node)
            try:
                fcntl.fcntl(image, fcntl.F_SETLEASE, fcntl.F_WRLCK)
                leased = True
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EINVAL, errno.ENOTSUP):
                    return
                raise
        loops, mounts = Guardian(-1).inventory(deadline=deadline)
        path = os.readlink(f"/proc/self/fd/{directory}")
        backing = identity(image) if image is not None else record.get("image")
        if (any(within(mount["target"], path) for mount in mounts)
                or backing is not None and any(
                    (loop["back-maj:min"], loop["back-ino"]) ==
                    (f"{os.major(backing[0])}:{os.minor(backing[0])}", backing[1]) for loop in loops)):
            return
        os.fchown(directory, 0, -1)
        os.fchmod(directory, 0o700)
        if temporary is not None:
            os.fchown(temporary, 0, -1)
            os.fchmod(temporary, 0o700)
        if (set(os.listdir(directory)) != contents
                or image is not None and Guardian.entry_identity(directory, "ext4.img") != identity(image)
                or temporary is not None and (os.listdir(temporary)
                    or Guardian.entry_identity(directory, "tmp") != identity(temporary))):
            raise RuntimeError("runtime entries changed during recovery")
        if location != staging:
            remaining(deadline)
            rename_new(parent, runtime_name, staging, "runtime")
        # Only the root helper can replace bindings inside staging now.
        if Guardian.entry_identity(staging, "runtime") != identity(directory):
            raise RuntimeError("runtime binding changed during recovery")
        if image is not None:
            if fcntl.fcntl(image, fcntl.F_GETLEASE) != fcntl.F_WRLCK:
                return
            os.unlink("ext4.img", dir_fd=directory)
        if temporary is not None:
            os.rmdir("tmp", dir_fd=directory)
        os.rmdir("runtime", dir_fd=staging)
        return True
    finally:
        if leased:
            fcntl.fcntl(image, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        signal.signal(signal.SIGIO, previous)
        for descriptor in (image, temporary, directory):
            if descriptor is not None:
                os.close(descriptor)


def recover_staging(parent, uid, deadline):
    validate_parent(parent, uid)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    with staging_root(parent, uid, deadline) as root:
        for name in os.listdir(root):
            remaining(deadline)
            if not name.startswith(STAGING_PREFIX):
                continue
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            except FileNotFoundError:
                continue  # A live transaction completed after the listing.
            try:
                info = os.fstat(descriptor)
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) not in (0, 0o700):
                    continue
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                try:
                    record = json.loads(os.getxattr(descriptor, STAGING_ATTRIBUTE))
                except OSError as error:
                    if error.errno == errno.ENODATA and not os.listdir(descriptor):
                        os.rmdir(name, dir_fd=root)  # Stopped before recording any resources.
                        continue
                    raise
                if (record.get("owner") != OWNER_ID.decode() or record.get("uid") != uid
                        or record.get("parent") != list(identity(parent))):
                    continue
                if record.get("boot") == boot:
                    try:
                        if process_stat(record["pid"])[1] == record["start"]:
                            continue
                    except (ProcessLookupError, FileNotFoundError):
                        pass
                completed = recover_transaction(parent, descriptor, record, uid, deadline)
                if completed and not os.listdir(descriptor):
                    os.rmdir(name, dir_fd=root)
            finally:
                os.close(descriptor)


def privileged_helper(address, parent, deadline):
    """Pinned caller-owned resources; destructive operations exclude writers."""
    descriptors = []
    result_fds = []
    response = {"ok": True}
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(remaining(deadline))
        connection.connect("\0" + address)
        peer, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != parent or uid != int(os.environ["SUDO_UID"]):
            raise RuntimeError("unexpected privileged fs-verity caller")
        request, descriptors = receive_message(connection)
        try:
            operation = request["operation"]
            if operation == "recover":
                recover_staging(descriptors[0], uid, deadline)
            elif operation in ("create", "remove"):
                name = request["name"]
                if not name.startswith(PREFIX) or "/" in name:
                    raise RuntimeError("invalid owned runtime name")
                if operation == "create":
                    result_fds = create_runtime(descriptors[0], name, uid, int(os.environ["SUDO_GID"]), deadline)
                else:
                    response["removed"] = remove_verified_runtime(*descriptors, name, uid, deadline)
            elif operation == "kill-child":
                owner_start = request["owner_start"]
                if process_stat(parent)[1] != owner_start:
                    raise RuntimeError("descendant owner changed identity")
                pid = int(next(line.split()[1] for line in
                               Path(f"/proc/self/fdinfo/{descriptors[0]}").read_text().splitlines()
                               if line.startswith("Pid:")))
                if pid > 0:
                    try:
                        if process_stat(pid) != (parent, request["child_start"]):
                            raise RuntimeError("refusing to signal an unowned process")
                        signal.pidfd_send_signal(descriptors[0], signal.SIGKILL)
                    except (ProcessLookupError, FileNotFoundError):
                        pass
            else:
                image = descriptors[0]
                info = os.fstat(image)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                    raise RuntimeError("privileged image is not owned by the caller")
                if operation == "attach":
                    if info.st_nlink != 1:
                        raise RuntimeError("refusing to attach an unlinked or aliased image")
                    result_fd, response["loop_index"] = configure_loop(image, deadline)
                    result_fds = [result_fd]
                elif operation == "pin":
                    result_fd = open_loop(request["loop"])
                    result_fds = [result_fd]
                    if not verify_loop(image, result_fd, missing_ok=request.get("missing_ok", False)):
                        os.close(result_fd)
                        result_fds = []
                elif operation == "detach":
                    if verify_loop(image, descriptors[1]):
                        fcntl.ioctl(descriptors[1], 0x4C01)  # LOOP_CLR_FD, never by name
                else:
                    raise RuntimeError("unknown privileged fs-verity operation")
            send_message(connection, response, result_fds)
        except (OSError, ValueError, RuntimeError) as error:
            send_message(connection, {"error": str(error),
                                      "os_error": isinstance(error, OSError),
                                      "errno": getattr(error, "errno", None)})
        finally:
            for descriptor in descriptors + result_fds:
                os.close(descriptor)


def privileged_request(operation, descriptors, *, deadline=None, result=None, **parameters):
    deadline = deadline or time.monotonic() + 5
    address = "opc-sdk-fsverity-helper-" + secrets.token_hex(24)
    returned = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind("\0" + address)
        server.listen(1)
        process = subprocess.Popen(["sudo", "-n", sys.executable, "-I", str(Path(__file__).resolve()),
                                    "--privileged", address, str(os.getpid()),
                                    str(deadline - min(.1, remaining(deadline) / 10))], start_new_session=True)
        try:
            while True:
                server.settimeout(min(.05, remaining(deadline)))
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    if process.poll() is not None:
                        raise RuntimeError("privileged fs-verity helper exited before connecting")
                    continue
                uid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if uid == 0:
                    break
                connection.close()
            with connection:
                connection.settimeout(remaining(deadline))
                send_message(connection, {"operation": operation, "timeout": remaining(deadline), **parameters}, descriptors)
                response, returned = receive_message(connection)
                if "error" in response:
                    if response.get("os_error"):
                        raise OSError(response["errno"], response["error"])
                    raise RuntimeError(response["error"])
            process.wait(timeout=remaining(deadline))
            if process.returncode:
                raise RuntimeError("privileged fs-verity helper failed")
            if result is not None:
                result.update(response)
            return returned
        except BaseException as error:
            for descriptor in returned:
                os.close(descriptor)
            if isinstance(error, subprocess.TimeoutExpired):
                raise TimeoutError("privileged fs-verity helper deadline expired") from error
            raise
        finally:
            # Closing the connection releases any helper-side pins. Helpers
            # have their own finite socket/configuration bounds and no children.
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise TimeoutError("privileged fs-verity helper deadline expired") from error


def detach_verified_loop(image, loop, *, missing_ok=False):
    image_fd = os.dup(image) if isinstance(image, int) else os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pinned = []
    try:
        if os.geteuid() == 0:
            pinned = [open_loop(loop)]
            if verify_loop(image_fd, pinned[0], missing_ok=missing_ok):
                fcntl.ioctl(pinned[0], 0x4C01)
        else:
            pinned = privileged_request("pin", [image_fd], loop=loop, missing_ok=missing_ok)
            if pinned:
                privileged_request("detach", [image_fd, pinned[0]])
    finally:
        for descriptor in [image_fd, *pinned]:
            os.close(descriptor)


class Guardian:
    def __init__(self, owner):
        self.owner = owner
        self.interrupted = False
        self.directory_fd = None
        self.parent_fd = None
        self.image_fd = None
        self.image_identity = None
        self.loop_fd = None

    def stopping(self):
        if select.select([self.owner], [], [], 0)[0]:
            self.interrupted = True
        return self.interrupted

    def run(self, command, *, capture=False, cleanup=False, timeout=30, env=None, deadline=None):
        if deadline is None and timeout is not None:
            deadline = time.monotonic() + timeout
        # Disposal fits inside a helper's absolute budget, including pipe EOF.
        reserve = min(1, max(.01, remaining(deadline) / 4)) if deadline else 0
        work_deadline = deadline - reserve if deadline else None
        process = subprocess.Popen(command, env=env, start_new_session=True,
                                   stdout=subprocess.PIPE if capture else None, text=True)
        failed = True
        try:
            while True:
                self.reap_finished_adoptees(process.pid)
                if not cleanup and self.stopping():
                    raise InterruptedError("fs-verity command owner interrupted")
                interval = min(.05, remaining(work_deadline)) if work_deadline else .05
                try:
                    output, _ = process.communicate(timeout=interval)
                    break
                except subprocess.TimeoutExpired:
                    continue  # An exited child may still have an orphan-held pipe.
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
            failed = False
            return output
        finally:
            if failed:
                disposal = deadline or time.monotonic() + 6
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except PermissionError:
                        self.kill_child(process.pid, disposal)
                    try:
                        process.wait(timeout=min(1, remaining(disposal)))
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except PermissionError:
                            self.kill_child(process.pid, disposal)
                        process.wait(timeout=remaining(disposal))
                self.reap_descendants(deadline=disposal)
                if process.stdout:
                    process.stdout.close()

    def reap_finished_adoptees(self, command_pid):
        children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text().split()
        for child in children:
            if int(child) != command_pid:
                os.waitpid(int(child), os.WNOHANG)

    def kill_child(self, child, deadline):
        descriptor = os.pidfd_open(child)
        try:
            if process_stat(child)[0] != os.getpid():
                raise RuntimeError("refusing to dispose of a non-child")
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except PermissionError:
                privileged_request("kill-child", [descriptor], deadline=deadline,
                                   owner_start=process_stat(os.getpid())[1],
                                   child_start=process_stat(child)[1])
        finally:
            os.close(descriptor)

    def reap_descendants(self, *, deadline=None):
        deadline = deadline or time.monotonic() + 6
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
                    self.kill_child(int(child), deadline)
                except (ProcessLookupError, FileNotFoundError):
                    pass
            time.sleep(min(.02, remaining(deadline)))

    def inventory(self, *, deadline=None):
        loops = json.loads(self.run(
            ["sudo", "-n", "losetup", "--list", "--json", "--output", "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN"],
            capture=True, cleanup=True, deadline=deadline,
        ))["loopdevices"]
        mounts = json.loads(self.run(
            ["findmnt", "--json", "--list", "--output", "TARGET,MAJ:MIN"],
            capture=True, cleanup=True, deadline=deadline,
        ))["filesystems"]
        return loops, mounts

    def attachments(self, directory, descriptor, *, deadline=None):
        loops, mounts = self.inventory(deadline=deadline)
        mounted = [mount for mount in mounts if within(mount["target"], directory)]
        if self.image_identity is None:
            info = os.stat("ext4.img", dir_fd=descriptor, follow_symlinks=False)
            device, inode = info.st_dev, info.st_ino
        else:
            device, inode = self.image_identity
        backing = f"{os.major(device)}:{os.minor(device)}", inode
        return [loop for loop in loops if (loop["back-maj:min"], loop["back-ino"]) == backing], mounted

    @contextmanager
    def startup_lock(self, descriptor, *, cleanup=False):
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not cleanup and self.stopping():
                    raise InterruptedError("fs-verity owner exited while waiting for startup lock")
                time.sleep(min(.05, remaining(deadline)))
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)

    @staticmethod
    def same_binding(directory, descriptor, parent):
        try:
            info = os.stat(directory.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return (info.st_dev, info.st_ino) == identity(descriptor)

    def remove_runtime(self, directory, descriptor, parent, *, deadline):
        # New owner namespace + worktree marker + exact layout. Never traverse
        # legacy directories or arbitrary contents below a familiar prefix.
        if not directory.name.startswith(PREFIX) or not is_owned(descriptor):
            return False
        # Observe mounts before layout checks: an owned runtime can have no
        # image, or a nonempty tmp because another filesystem is mounted there.
        _loops, mounts = self.inventory(deadline=deadline)
        if any(within(mount["target"], directory) for mount in mounts):
            return False
        if set(os.listdir(descriptor)) != {"ext4.img", "tmp"}:
            return False
        image_info = os.stat("ext4.img", dir_fd=descriptor, follow_symlinks=False)
        tmp_info = os.stat("tmp", dir_fd=descriptor, follow_symlinks=False)
        if (not stat.S_ISREG(image_info.st_mode) or image_info.st_uid != os.getuid()
                or not stat.S_ISDIR(tmp_info.st_mode) or tmp_info.st_uid != os.getuid()
                or stat.S_IMODE(tmp_info.st_mode) != 0o700):
            return False
        image = os.open("ext4.img", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        try:
            temporary = os.open("tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        except BaseException:
            os.close(image)
            raise
        leased = False
        old_handler = signal.signal(signal.SIGIO, lambda *_args: None)
        try:
            info = os.fstat(image)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or os.listdir(temporary)
                    or self.image_identity is not None and identity(image) != self.image_identity):
                return False
            # A write lease refuses an already-open backing file and blocks
            # fresh opens through inventory+unlink, including outside flocks.
            # All owner attachment paths also hold the root/runtime locks.
            try:
                fcntl.fcntl(image, fcntl.F_SETLEASE, fcntl.F_WRLCK)
                leased = True
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EINVAL, errno.ENOTSUP):
                    return False
                raise
            attached, mounted = self.attachments(directory, descriptor, deadline=deadline)
            if attached or mounted or not self.same_binding(directory, descriptor, parent):
                return False
            if (fcntl.fcntl(image, fcntl.F_GETLEASE) != fcntl.F_WRLCK
                    or set(os.listdir(descriptor)) != {"ext4.img", "tmp"}
                    or os.listdir(temporary)
                    or identity(image) != self.entry_identity(descriptor, "ext4.img")
                    or identity(temporary) != self.entry_identity(descriptor, "tmp")):
                return False
            remaining(deadline)
            result = {}
            privileged_request("remove", [parent, descriptor, image, temporary],
                               name=directory.name, deadline=time.monotonic() + CLEANUP_HELPER_SECONDS,
                               result=result)
            return result["removed"]
        finally:
            if leased:
                fcntl.fcntl(image, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            signal.signal(signal.SIGIO, old_handler)
            os.close(temporary)
            os.close(image)

    @staticmethod
    def entry_identity(descriptor, name):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        return info.st_dev, info.st_ino

    def sweep(self, root):
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.startup_lock(parent):
                privileged_request("recover", [parent], deadline=time.monotonic() + CLEANUP_HELPER_SECONDS)
                for name in os.listdir(parent):
                    if not name.startswith(PREFIX):
                        continue
                    try:
                        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                                or stat.S_IMODE(info.st_mode) != 0o700):
                            continue
                        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    except (FileNotFoundError, NotADirectoryError):
                        continue
                    try:
                        if not is_owned(descriptor):
                            continue
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            continue
                        if not self.remove_runtime(root / name, descriptor, parent, deadline=time.monotonic() + 5):
                            print(f"fs-verity: retaining runtime {root / name}", file=sys.stderr)
                    finally:
                        os.close(descriptor)
        finally:
            os.close(parent)

    def release(self, directory):
        descriptor = self.directory_fd
        parent = self.parent_fd
        borrowed = descriptor is None
        if borrowed:
            parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        errors = []
        try:
            try:
                self.reap_descendants()
            except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
                errors.append(error)
            # The lifetime runtime lock protects this owner during slow child,
            # unmount and detach work; do not block other owners' startup lock.
            attached, mounted = self.attachments(directory, descriptor)
            if not self.same_binding(directory, descriptor, parent):
                raise RuntimeError("runtime parent binding changed before teardown")
            if mounted:
                if len(mounted) != 1 or mounted[0]["target"] != str(directory / "tmp"):
                    raise RuntimeError("unexpected mounts in fs-verity runtime; retaining it")
                self.run(["sudo", "-n", "umount", "--", str(directory / "tmp")], cleanup=True)
            if self.loop_fd is not None:
                privileged_request("detach", [self.image_fd, self.loop_fd])
                os.close(self.loop_fd)
                self.loop_fd = None
            attached, _mounted = self.attachments(directory, descriptor)
            for loop in attached:
                detach_verified_loop(self.image_fd if self.image_fd is not None else directory / "ext4.img",
                                     loop["name"], missing_ok=True)
            if self.image_fd is not None:
                os.close(self.image_fd)
                self.image_fd = None
            with self.startup_lock(parent, cleanup=True):
                deadline = time.monotonic() + 5
                while True:
                    attached, mounted = self.attachments(directory, descriptor, deadline=deadline)
                    if not attached and not mounted:
                        break
                    time.sleep(min(.05, remaining(deadline)))
                if errors:
                    raise RuntimeError(f"descendant cleanup failed: {errors}")
                if not self.remove_runtime(directory, descriptor, parent, deadline=time.monotonic() + 5):
                    raise RuntimeError("runtime ownership/layout changed; retaining it")
        finally:
            if borrowed:
                os.close(descriptor)
                os.close(parent)

    def execute(self, command):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot become fs-verity subreaper")
        root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        self.sweep(root)
        if self.stopping():
            raise InterruptedError("fs-verity owner exited during startup")
        self.parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        directory = None
        try:
            with self.startup_lock(self.parent_fd):
                name = PREFIX + secrets.token_hex(16)
                # Initialize under a protected parent too: creation rollback
                # must not have the same name-substitution bug as final removal.
                self.directory_fd, self.image_fd = privileged_request(
                    "create", [self.parent_fd], name=name,
                    deadline=time.monotonic() + CLEANUP_HELPER_SECONDS)
                self.image_identity = identity(self.image_fd)
                directory = root / name
                try:
                    fcntl.flock(self.directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    mark_owned(self.directory_fd)
                    os.setxattr(self.directory_fd, GUARDIAN_ATTRIBUTE,
                                f"{os.getpid()}:{process_stat(os.getpid())[1]}".encode())
                except BaseException:
                    os.close(self.image_fd)
                    self.image_fd = None
                    if not self.remove_runtime(directory, self.directory_fd, self.parent_fd,
                                               deadline=time.monotonic() + 5):
                        raise RuntimeError("new runtime changed during initialization; retaining it")
                    raise
            try:
                mountpoint = directory / "tmp"
                self.run(["mkfs.ext4", "-q", "-b", "4096", "-O", "verity",
                          f"/proc/{os.getpid()}/fd/{self.image_fd}"])
                with self.startup_lock(self.parent_fd):
                    if not self.same_binding(directory, self.directory_fd, self.parent_fd):
                        raise RuntimeError("runtime moved before attachment")
                    if identity(self.image_fd) != self.entry_identity(self.directory_fd, "ext4.img"):
                        raise RuntimeError("runtime image changed before attachment")
                    result = {}
                    self.loop_fd, = privileged_request("attach", [self.image_fd], result=result)
                    device = os.fstat(self.loop_fd).st_rdev
                    loop = f"/dev/loop{result['loop_index']}"
                    node = os.stat(loop, follow_symlinks=False)
                    if not stat.S_ISBLK(node.st_mode) or node.st_rdev != device:
                        raise RuntimeError("loop device node mismatch before mount")
                    self.run(["sudo", "-n", "mount", "-o", "nosuid,nodev", loop, str(mountpoint)])
                if mountpoint.stat().st_dev != device:
                    raise RuntimeError("mounted device mismatch before chown")
                self.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
                snapshots = mountpoint / "snapshots"
                snapshots.mkdir(mode=0o700)
                snapshots.chmod(0o700)
                info = snapshots.stat()
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise RuntimeError("fs-verity snapshot root must remain current-user private mode 0700")
                self.run(command, timeout=None, env=os.environ | {
                    "OPC_FS_VERITY_SNAPSHOT_ROOT": str(snapshots),
                    "OPC_FS_VERITY_QUALIFICATION": "required",
                })
                return 0
            except subprocess.CalledProcessError as error:
                return error.returncode if error.returncode > 0 else 128 - error.returncode
            except InterruptedError:
                return 143
            finally:
                self.release(directory)
        finally:
            for descriptor in (self.loop_fd, self.image_fd, self.directory_fd, self.parent_fd):
                if descriptor is not None:
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
        raise RuntimeError("fs-verity guardian did not enter a separate mount namespace")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    guardian = Guardian(owner)
    for signum in SIGNALS:
        signal.signal(signum, lambda _signum, _frame: setattr(guardian, "interrupted", True))
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
                "/usr/bin/sudo", "-n", "/usr/bin/unshare", "--mount", "--propagation", "slave", "--",
                "/usr/bin/setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()),
                *group_args, "--", sys.executable, str(Path(__file__).resolve()),
                "--guardian", address, str(os.getpid()),
            ], start_new_session=True)
            deadline = time.monotonic() + 30
            while True:
                try:
                    connection, _ = server.accept()
                    _peer, uid, _gid = struct.unpack("3i", connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                    if uid == os.getuid():
                        break
                    connection.close()
                    remaining(deadline)
                except socket.timeout:
                    if process.poll() is not None:
                        raise subprocess.CalledProcessError(process.returncode or 1, "fs-verity namespace bootstrap")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("fs-verity namespace bootstrap timed out")
            with connection:
                connection.settimeout(30)
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
        detach_verified_loop(command[1], command[2])
        return 0
    if len(command) == 4 and command[0] == "--privileged":
        privileged_helper(command[1], int(command[2]), float(command[3]))
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

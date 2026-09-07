#!/usr/bin/env python3
"""Produce and consume the SDK-702 release-test executable attestation.

This wrapper is intentionally a small, auditable trust boundary.  It does not
run the million-operation test when invoked with ``--check``.  The normal mode
creates one fresh owner-private external target directory, builds exactly one
test executable there, pins and hashes its descriptor, writes a canonical create-new
attestation in a fresh mode-0700 namespace, and execs that pinned descriptor.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Iterable


TRUSTED_GIT = pathlib.Path("/usr/bin/git")
ATTESTATION_KIND = "sdk702_trusted_release_attestation_wrapper/v2"
ATTESTATION_LEAF = "sdk702-release-build-attestation.json"
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DIAGNOSTICS = 64 * 1024
MAX_EXECUTABLE = 512 * 1024 * 1024
MAX_PROCESS_LOSS_V9_EVIDENCE = 128 * 1024
MAX_PROCESS_LOSS_V1_EVIDENCE = 64 * 1024
PROCESS_LOSS_V9_LEAF = "persistent-consumer-v9.json"
PROCESS_LOSS_V1_LEAF = "batch-release-gate-v1.json"
FS_VERITY_SNAPSHOT_NAMESPACE_PREFIX = "sdk702-release-snapshots-"
FS_VERITY_SNAPSHOT_ROOT_ENV = "OPC_FS_VERITY_SNAPSHOT_ROOT"
FS_VERITY_QUALIFICATION_ENV = "OPC_FS_VERITY_QUALIFICATION"
GIT_TIMEOUT_SECONDS = 30
BUILD_TIMEOUT_SECONDS = 20 * 60
PROCESS_TERM_GRACE_SECONDS = 2
PROCESS_KILL_REAP_SECONDS = 2
LEASE_PIN_DOMAIN = "sdk702_trusted_release_attestation_wrapper/lease-procfd/v1"
# The fixed qualification schedule is 1,800s sustained plus 60s burst.  The
# extra four minutes are bounded setup, durability, and publication headroom;
# this ceiling is not a performance or throughput relaxation.
RELEASE_RUNTIME_TIMEOUT_SECONDS = 1800 + 60 + 240
LIBTEST_ARGS = (
    "--ignored",
    "--exact",
    "release_1010000_operation_successor_scale_is_bounded_and_recoverable",
    "--nocapture",
)
RECIPE = (
    "OPC_FS_VERITY_QUALIFICATION=required "
    "OPC_FS_VERITY_SNAPSHOT_ROOT=<existing-absolute-external-fs-verity-root> "
    "/usr/bin/python3 ci/sdk702-release-attest.py --cargo <absolute-trusted-cargo> --target-dir <absent-absolute-external-target> "
    "--snapshot-root <existing-absolute-external-fs-verity-root> "
    "--attestation-namespace <absent-absolute-external-namespace> "
    "--evidence <absent-absolute-external-namespace> "
    "--process-loss-evidence <absolute-external-testkit-v9-json> "
    "--lease <absolute-external-lock-file>"
)


class QualificationError(RuntimeError):
    """A redaction-safe failure: callers never receive filesystem diagnostics."""


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file_descriptor(fd: int, maximum: int = MAX_EXECUTABLE) -> tuple[str, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
        raise QualificationError("pinned executable is not a bounded regular file")
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.read(fd, 64 * 1024)
        if not block:
            break
        total += len(block)
        if total > maximum:
            raise QualificationError("pinned executable grew beyond bounded limit")
        digest.update(block)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or total != before.st_size:
        raise QualificationError("pinned executable changed while hashing")
    return digest.hexdigest(), before


def read_bounded_regular_file_with_identity(path: pathlib.Path, maximum: int) -> tuple[bytes, os.stat_result, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            raise QualificationError("trusted release input is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise QualificationError("trusted release input grew beyond bounded limit")
            chunks.append(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or total != before.st_size:
            raise QualificationError("trusted release input changed while read")
        encoded = b"".join(chunks)
        return encoded, before, digest_bytes(encoded)
    finally:
        os.close(descriptor)


def read_bounded_regular_file(path: pathlib.Path, maximum: int) -> bytes:
    return read_bounded_regular_file_with_identity(path, maximum)[0]


def descriptor_identity(stat_result: os.stat_result) -> tuple[int, int, int]:
    return stat_result.st_dev, stat_result.st_ino, stat_result.st_size


def directory_identity(stat_result: os.stat_result) -> tuple[int, int]:
    return stat_result.st_dev, stat_result.st_ino


def require_private_directory(stat_result: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(stat_result.st_mode)
        or stat_result.st_uid != os.geteuid()
        or stat.S_IMODE(stat_result.st_mode) != 0o700
    ):
        raise QualificationError(f"{label} must be current-user-owned mode-0700 directory")


def require_private_regular_file(stat_result: os.stat_result, label: str, maximum: int | None) -> None:
    if (
        not stat.S_ISREG(stat_result.st_mode)
        or stat_result.st_uid != os.geteuid()
        or stat.S_IMODE(stat_result.st_mode) & 0o077
        or stat_result.st_size < 0
        or (maximum is not None and stat_result.st_size > maximum)
    ):
        raise QualificationError(f"{label} must be a current-user-owned private regular file")


def canonical_direct_leaf(value: str, label: str, *, must_exist: bool) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise QualificationError(f"{label} must be an absolute direct leaf")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise QualificationError(f"{label} parent must be a canonical directory") from error
    canonical = parent / path.name
    if must_exist and not os.path.lexists(canonical):
        raise QualificationError(f"{label} must be an existing absolute direct leaf")
    return canonical


def open_private_parent(path: pathlib.Path, label: str) -> tuple[int, tuple[int, int]]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        descriptor_stat = os.fstat(descriptor)
        pathname_stat = os.stat(path, follow_symlinks=False)
        require_private_directory(descriptor_stat, label)
        require_private_directory(pathname_stat, label)
        identity = directory_identity(descriptor_stat)
        if directory_identity(pathname_stat) != identity:
            raise QualificationError(f"{label} identity changed while opening")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def private_leaf_stat_at(parent_descriptor: int, name: str, label: str, maximum: int | None) -> os.stat_result:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise QualificationError(f"{label} cannot be statted") from error
    require_private_regular_file(metadata, label, maximum)
    return metadata


def read_bounded_private_descriptor(descriptor: int, label: str, maximum: int) -> tuple[bytes, os.stat_result, str]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    before = os.fstat(descriptor)
    require_private_regular_file(before, label, maximum)
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, 64 * 1024)
        if not block:
            break
        total += len(block)
        if total > maximum:
            raise QualificationError(f"{label} grew beyond bounded limit")
        chunks.append(block)
    after = os.fstat(descriptor)
    if descriptor_identity(before) != descriptor_identity(after) or total != before.st_size:
        raise QualificationError(f"{label} changed while read")
    encoded = b"".join(chunks)
    return encoded, before, digest_bytes(encoded)


@dataclasses.dataclass
class PinnedProcessLossPair:
    evidence_root_path: pathlib.Path
    parent_path: pathlib.Path
    parent_descriptor: int
    parent_identity: tuple[int, int]
    v9_path: pathlib.Path
    v1_path: pathlib.Path
    v9_descriptor: int
    v1_descriptor: int
    v9_identity: tuple[int, int, int]
    v1_identity: tuple[int, int, int]

    def close(self) -> None:
        for descriptor in (self.v9_descriptor, self.v1_descriptor, self.parent_descriptor):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _revalidate_parent(self) -> None:
        descriptor_stat = os.fstat(self.parent_descriptor)
        pathname_stat = os.stat(self.parent_path, follow_symlinks=False)
        require_private_directory(descriptor_stat, "process-loss pair parent")
        require_private_directory(pathname_stat, "process-loss pair parent")
        if directory_identity(descriptor_stat) != self.parent_identity or directory_identity(pathname_stat) != self.parent_identity:
            raise QualificationError("process-loss pair parent identity changed")

    def _revalidate_leaf(
        self,
        name: str,
        descriptor: int,
        identity: tuple[int, int, int],
        label: str,
        maximum: int,
    ) -> None:
        pathname_stat = private_leaf_stat_at(self.parent_descriptor, name, label, maximum)
        descriptor_stat = os.fstat(descriptor)
        require_private_regular_file(descriptor_stat, label, maximum)
        if descriptor_identity(pathname_stat) != identity or descriptor_identity(descriptor_stat) != identity:
            raise QualificationError(f"{label} identity changed")

    def revalidate(self) -> None:
        self._revalidate_parent()
        self._require_exact_names()
        self._revalidate_leaf(
            PROCESS_LOSS_V9_LEAF,
            self.v9_descriptor,
            self.v9_identity,
            "process-loss evidence",
            MAX_PROCESS_LOSS_V9_EVIDENCE,
        )
        self._revalidate_leaf(
            PROCESS_LOSS_V1_LEAF,
            self.v1_descriptor,
            self.v1_identity,
            "process-loss V1 pair evidence",
            MAX_PROCESS_LOSS_V1_EVIDENCE,
        )
        self._require_exact_names()
        self._revalidate_parent()

    def _require_exact_names(self) -> None:
        try:
            names = sorted(os.listdir(self.parent_descriptor))
        except OSError as error:
            raise QualificationError("process-loss pair namespace cannot be read") from error
        if names != sorted([PROCESS_LOSS_V1_LEAF, PROCESS_LOSS_V9_LEAF]):
            raise QualificationError("process-loss pair namespace must contain only the fixed V1/V9 leaves")

    def read(self) -> tuple[tuple[bytes, os.stat_result, str], tuple[bytes, os.stat_result, str]]:
        self.revalidate()
        v9 = read_bounded_private_descriptor(
            self.v9_descriptor, "process-loss evidence", MAX_PROCESS_LOSS_V9_EVIDENCE
        )
        v1 = read_bounded_private_descriptor(
            self.v1_descriptor, "process-loss V1 pair evidence", MAX_PROCESS_LOSS_V1_EVIDENCE
        )
        self.revalidate()
        return v9, v1


def pin_process_loss_pair(value: str) -> PinnedProcessLossPair:
    v9_path = canonical_direct_leaf(value, "process-loss evidence", must_exist=True)
    if v9_path.name != PROCESS_LOSS_V9_LEAF:
        raise QualificationError("process-loss evidence must use the fixed V9 pair leaf")
    v1_path = v9_path.with_name(PROCESS_LOSS_V1_LEAF)
    if not os.path.lexists(v1_path):
        raise QualificationError("process-loss V1 pair evidence must be an existing absolute direct leaf")
    parent_descriptor, parent_identity = open_private_parent(v9_path.parent, "process-loss pair parent")
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        v9_descriptor = os.open(PROCESS_LOSS_V9_LEAF, flags, dir_fd=parent_descriptor)
        try:
            v1_descriptor = os.open(PROCESS_LOSS_V1_LEAF, flags, dir_fd=parent_descriptor)
            try:
                evidence_root = v9_path.parent.parent
                if evidence_root is None or not evidence_root.is_dir():
                    raise QualificationError("process-loss pair must be nested below an existing evidence root")
                pair = PinnedProcessLossPair(
                    evidence_root.resolve(strict=True),
                    v9_path.parent,
                    parent_descriptor,
                    parent_identity,
                    v9_path,
                    v1_path,
                    v9_descriptor,
                    v1_descriptor,
                    descriptor_identity(os.fstat(v9_descriptor)),
                    descriptor_identity(os.fstat(v1_descriptor)),
                )
                pair.revalidate()
                return pair
            except BaseException:
                os.close(v1_descriptor)
                raise
        except BaseException:
            os.close(v9_descriptor)
            raise
    except BaseException:
        os.close(parent_descriptor)
        raise


@dataclasses.dataclass
class PinnedLeaseLeaf:
    path: pathlib.Path
    parent_path: pathlib.Path
    parent_descriptor: int
    parent_identity: tuple[int, int]
    leaf_descriptor: int | None
    leaf_identity: tuple[int, int, int, int] | None

    def close(self) -> None:
        if self.leaf_descriptor is not None:
            try:
                os.close(self.leaf_descriptor)
            except OSError:
                pass
            self.leaf_descriptor = None
        try:
            os.close(self.parent_descriptor)
        except OSError:
            pass

    def _revalidate_parent(self) -> None:
        descriptor_stat = os.fstat(self.parent_descriptor)
        pathname_stat = os.stat(self.parent_path, follow_symlinks=False)
        require_private_directory(descriptor_stat, "lease parent")
        require_private_directory(pathname_stat, "lease parent")
        if directory_identity(descriptor_stat) != self.parent_identity or directory_identity(pathname_stat) != self.parent_identity:
            raise QualificationError("lease parent identity changed")

    @staticmethod
    def _identity(stat_result: os.stat_result) -> tuple[int, int, int, int]:
        return stat_result.st_dev, stat_result.st_ino, stat.S_IMODE(stat_result.st_mode), stat_result.st_uid

    def _revalidate_open_leaf(self) -> os.stat_result:
        if self.leaf_descriptor is None or self.leaf_identity is None:
            raise QualificationError("lease descriptor is not pinned")
        pathname_stat = private_leaf_stat_at(self.parent_descriptor, self.path.name, "lease", None)
        descriptor_stat = os.fstat(self.leaf_descriptor)
        require_private_regular_file(descriptor_stat, "lease", None)
        if self._identity(pathname_stat) != self.leaf_identity or self._identity(descriptor_stat) != self.leaf_identity:
            raise QualificationError("lease pathname or descriptor identity changed")
        return descriptor_stat

    def _procfd_reference(self) -> pathlib.Path:
        if self.leaf_descriptor is None:
            raise QualificationError("lease descriptor is not pinned")
        return pathlib.Path("/proc") / str(os.getpid()) / "fd" / str(self.leaf_descriptor)

    def _revalidate_procfd_reference(self) -> pathlib.Path:
        """Prove the direct-child procfd reference resolves to the retained inode."""
        reference = self._procfd_reference()
        try:
            pathname_stat = os.stat(reference)
            descriptor = os.open(reference, os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as error:
            raise QualificationError("pinned lease procfd reference is unavailable") from error
        try:
            descriptor_stat = os.fstat(descriptor)
            require_private_regular_file(pathname_stat, "lease procfd", None)
            require_private_regular_file(descriptor_stat, "lease procfd", None)
            if self.leaf_identity is None or self._identity(pathname_stat) != self.leaf_identity or self._identity(descriptor_stat) != self.leaf_identity:
                raise QualificationError("pinned lease procfd identity changed")
        finally:
            os.close(descriptor)
        return reference

    def revalidate(self) -> None:
        self._revalidate_parent()
        try:
            os.stat(self.path.name, dir_fd=self.parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            if self.leaf_descriptor is not None:
                raise QualificationError("pinned lease leaf disappeared")
            self._revalidate_parent()
            return
        except OSError as error:
            raise QualificationError("lease cannot be statted") from error
        if self.leaf_descriptor is None:
            raise QualificationError("lease leaf appeared before wrapper pinning")
        self._revalidate_open_leaf()
        self._revalidate_parent()

    def open_for_child(self) -> None:
        """Pin one regular lease inode before target/evidence mutation or spawn."""
        self._revalidate_parent()
        if self.leaf_descriptor is not None:
            self.revalidate()
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path.name, flags, 0o600, dir_fd=self.parent_descriptor)
        except FileExistsError as error:
            raise QualificationError("lease leaf appeared before wrapper pinning") from error
        try:
            descriptor_stat = os.fstat(descriptor)
            require_private_regular_file(descriptor_stat, "lease", None)
            self.leaf_descriptor = descriptor
            self.leaf_identity = self._identity(descriptor_stat)
            self.revalidate()
        except BaseException:
            os.close(descriptor)
            self.leaf_descriptor = None
            self.leaf_identity = None
            raise

    def environment_contract(self) -> dict[str, str]:
        self.revalidate()
        if self.leaf_identity is None:
            raise QualificationError("lease descriptor is not pinned")
        reference = self._revalidate_procfd_reference()
        device, inode, mode, uid = self.leaf_identity
        parent_device, parent_inode = self.parent_identity
        return {
            "OPC_QUAL_LEASE": str(self.path),
            "OPC_QUAL_LEASE_PIN_DOMAIN": LEASE_PIN_DOMAIN,
            # The direct child opens this procfd path into its own CLOEXEC File;
            # the retained descriptor is never inherited or RawFd-adopted.
            "OPC_QUAL_LEASE_PIN_WRAPPER_PID": str(os.getpid()),
            "OPC_QUAL_LEASE_PIN_WRAPPER_FD": str(self.leaf_descriptor),
            "OPC_QUAL_LEASE_PIN_PROCFD": str(reference),
            "OPC_QUAL_LEASE_PIN_PARENT": str(self.parent_path),
            "OPC_QUAL_LEASE_PIN_NAME": self.path.name,
            "OPC_QUAL_LEASE_PIN_PARENT_DEVICE": str(parent_device),
            "OPC_QUAL_LEASE_PIN_PARENT_INODE": str(parent_inode),
            "OPC_QUAL_LEASE_PIN_DEVICE": str(device),
            "OPC_QUAL_LEASE_PIN_INODE": str(inode),
            "OPC_QUAL_LEASE_PIN_MODE": format(mode, "04o"),
            "OPC_QUAL_LEASE_PIN_UID": str(uid),
        }


def pin_lease_leaf(value: str) -> PinnedLeaseLeaf:
    path = canonical_direct_leaf(value, "lease", must_exist=False)
    parent_descriptor, parent_identity = open_private_parent(path.parent, "lease parent")
    lease = PinnedLeaseLeaf(path, path.parent, parent_descriptor, parent_identity, None, None)
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            lease.revalidate()
        else:
            descriptor_stat = os.fstat(descriptor)
            lease.leaf_descriptor = descriptor
            lease.leaf_identity = lease._identity(descriptor_stat)
            require_private_regular_file(descriptor_stat, "lease", None)
            lease.revalidate()
        return lease
    except BaseException:
        lease.close()
        raise


def verify_pinned_directory(path: pathlib.Path, descriptor: int, identity: tuple[int, ...], label: str) -> None:
    current = os.fstat(descriptor)
    pathname = os.stat(path, follow_symlinks=False)
    require_private_directory(current, label)
    require_private_directory(pathname, label)
    if directory_identity(current) != identity[:2] or directory_identity(pathname) != identity[:2]:
        raise QualificationError(f"{label} identity changed")


def create_private_target(path: pathlib.Path) -> tuple[int, tuple[int, int, int]]:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        target_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            target_stat = os.fstat(target_fd)
            require_private_directory(target_stat, "fresh target namespace")
            identity = descriptor_identity(target_stat)
            return target_fd, identity
        except BaseException:
            os.close(target_fd)
            raise
    finally:
        os.close(parent_fd)


def open_private_absolute_directory(value: str, label: str) -> tuple[pathlib.Path, int, tuple[int, int]]:
    path = pathlib.Path(value)
    if (
        os.fsencode(value) != os.fsencode(str(path))
        or not path.is_absolute()
        or any(not isinstance(component, str) or component in ("", ".", "..") for component in path.parts[1:])
    ):
        raise QualificationError(f"{label} must be a canonical absolute directory")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        descriptor_stat = os.fstat(descriptor)
        require_private_directory(descriptor_stat, label)
        canonical = pathlib.Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        if canonical != path:
            raise QualificationError(f"{label} must be canonical")
        pathname_stat = os.stat(path, follow_symlinks=False)
        require_private_directory(pathname_stat, label)
        identity = directory_identity(descriptor_stat)
        if directory_identity(pathname_stat) != identity:
            raise QualificationError(f"{label} identity changed while opening")
        return canonical, descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def create_private_snapshot_namespace(
    snapshot_base: pathlib.Path,
    snapshot_base_descriptor: int,
    snapshot_base_identity: tuple[int, int],
    target: pathlib.Path,
) -> tuple[pathlib.Path, int, tuple[int, int]]:
    """Create a fresh fixed-name child below the explicit pinned snapshot base."""
    verify_pinned_directory(
        snapshot_base, snapshot_base_descriptor, snapshot_base_identity, "fs-verity snapshot root"
    )
    name = FS_VERITY_SNAPSHOT_NAMESPACE_PREFIX + digest_bytes(os.fsencode(target))[:32]
    snapshot_root = snapshot_base / name
    try:
        os.mkdir(name, 0o700, dir_fd=snapshot_base_descriptor)
    except FileExistsError as error:
        raise QualificationError("fresh fs-verity snapshot namespace already exists") from error
    os.fsync(snapshot_base_descriptor)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=snapshot_base_descriptor,
        )
    except OSError as error:
        raise QualificationError("fresh target snapshot namespace cannot be opened") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        pathname_stat = os.stat(name, dir_fd=snapshot_base_descriptor, follow_symlinks=False)
        require_private_directory(descriptor_stat, "fresh fs-verity snapshot namespace")
        require_private_directory(pathname_stat, "fresh fs-verity snapshot namespace")
        identity = directory_identity(descriptor_stat)
        if directory_identity(pathname_stat) != identity:
            raise QualificationError("fresh fs-verity snapshot namespace identity changed")
        if snapshot_root.resolve(strict=True) != snapshot_root:
            raise QualificationError("fresh fs-verity snapshot namespace is not canonical")
        return snapshot_root, descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def verify_pinned_snapshot_namespace(
    snapshot_base: pathlib.Path,
    snapshot_base_descriptor: int,
    snapshot_base_identity: tuple[int, int],
    snapshot_root: pathlib.Path,
    snapshot_descriptor: int,
    snapshot_identity: tuple[int, int],
) -> None:
    verify_pinned_directory(
        snapshot_base, snapshot_base_descriptor, snapshot_base_identity, "fs-verity snapshot root"
    )
    if snapshot_root.parent != snapshot_base or not snapshot_root.name.startswith(FS_VERITY_SNAPSHOT_NAMESPACE_PREFIX):
        raise QualificationError("fresh fs-verity snapshot namespace is not the fixed direct child")
    current = os.fstat(snapshot_descriptor)
    pathname = os.stat(snapshot_root.name, dir_fd=snapshot_base_descriptor, follow_symlinks=False)
    require_private_directory(current, "fresh fs-verity snapshot namespace")
    require_private_directory(pathname, "fresh fs-verity snapshot namespace")
    if directory_identity(current) != snapshot_identity or directory_identity(pathname) != snapshot_identity:
        raise QualificationError("fresh fs-verity snapshot namespace identity changed")


def require_distinct_snapshot_filesystem(
    target_identity: tuple[int, int, int], snapshot_base_identity: tuple[int, int]
) -> None:
    if target_identity[0] == snapshot_base_identity[0]:
        raise QualificationError(
            "Cargo target/build namespace must not share the fs-verity snapshot filesystem"
        )


def canonical_directory(value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or not path.exists() or not path.is_dir():
        raise QualificationError(f"{label} must be an existing absolute directory")
    return path.resolve(strict=True)


def absent_namespace(value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or path.name in ("", ".", "..") or os.path.lexists(path):
        raise QualificationError(f"{label} must be an absent absolute direct namespace")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir() or path.parent != parent and not path.parent.exists():
        raise QualificationError(f"{label} parent must be a canonical directory")
    return parent / path.name


def overlaps(left: pathlib.Path, right: pathlib.Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        try:
            right.relative_to(left)
            return True
        except ValueError:
            return False


def require_pairwise_disjoint(paths: Iterable[pathlib.Path]) -> None:
    paths = list(paths)
    if any(overlaps(first, second) for index, first in enumerate(paths) for second in paths[index + 1 :]):
        raise QualificationError("qualification external paths are not mutually disjoint")


def require_external_disjoint_from_protected(protected: Iterable[pathlib.Path], external: Iterable[pathlib.Path]) -> None:
    protected = list(protected)
    external = list(external)
    require_pairwise_disjoint(external)
    if any(overlaps(candidate, boundary) for candidate in external for boundary in protected):
        raise QualificationError("qualification external path overlaps source or git metadata")


def require_process_loss_root_external_topology(
    protected: Iterable[pathlib.Path],
    producer_root: pathlib.Path,
    unrelated_namespaces: Iterable[pathlib.Path],
    unrelated_parents: Iterable[pathlib.Path],
) -> None:
    """Keep the producer's root/pair/leaves hierarchy separate from wrapper I/O.

    The pair leaves are deliberately nested below ``producer_root`` and must
    not enter the generic pairwise set.  Each actual unrelated wrapper path is
    rejected when it is an ancestor or descendant of that producer root.  Its
    canonical parent is an authority boundary checked against the protected
    source roots, not a namespace occupied by the wrapper: disjoint wrapper
    leaves may intentionally share one external parent with the producer.
    """
    protected = list(protected)
    unrelated_namespaces = list(unrelated_namespaces)
    unrelated = [*unrelated_namespaces, *unrelated_parents]
    if any(overlaps(producer_root, boundary) for boundary in protected):
        raise QualificationError("process-loss evidence root overlaps source or git metadata")
    if any(overlaps(candidate, boundary) for candidate in unrelated for boundary in protected):
        raise QualificationError("qualification external path overlaps source or git metadata")
    if any(overlaps(producer_root, candidate) for candidate in unrelated_namespaces):
        raise QualificationError("process-loss evidence root overlaps an unrelated external namespace")


def safe_git_environment() -> dict[str, str]:
    # Deliberately do not inherit GIT_*, loader, configuration, or path lookup
    # controls. The process image is an absolute canonical /usr/bin/git.
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "LANG": "C",
    }


def trusted_git_executable() -> pathlib.Path:
    executable = TRUSTED_GIT.resolve(strict=True)
    if executable != TRUSTED_GIT or not executable.is_file():
        raise QualificationError("absolute trusted git executable is unavailable")
    return executable


def terminate_owned_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the owned session even after its leader has exited.

    ``start_new_session`` makes the child PID the process-group ID.  Its leader
    may exit while a descendant still owns either output pipe, so cleanup must
    address that PGID directly rather than treating a reaped leader as proof
    that the owned group is gone.
    """
    pgid = process.pid

    def group_survives() -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    term_deadline = time.monotonic() + PROCESS_TERM_GRACE_SECONDS
    while group_survives() and time.monotonic() < term_deadline:
        time.sleep(max(0.0, min(0.05, term_deadline - time.monotonic())))
    if group_survives():
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        kill_deadline = time.monotonic() + PROCESS_KILL_REAP_SECONDS
        while group_survives() and time.monotonic() < kill_deadline:
            time.sleep(max(0.0, min(0.05, kill_deadline - time.monotonic())))
    # Never turn cleanup into an unbounded wait.  The leader is our direct
    # child; descendants are reparented after the group signal above.
    try:
        process.wait(timeout=PROCESS_KILL_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    if group_survives():
        raise QualificationError("owned process group survived bounded cleanup")


def bounded_run(arguments: list[str], *, cwd: pathlib.Path, env: dict[str, str], timeout_seconds: int, stdout_limit: int = MAX_OUTPUT, stderr_limit: int = MAX_DIAGNOSTICS, pass_fds: tuple[int, ...] = ()) -> tuple[int, bytes, bytes]:
    if timeout_seconds <= 0:
        raise QualificationError("trusted command timeout is invalid")
    process = subprocess.Popen(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds, start_new_session=True)
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_limit))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_limit))
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_owned_process_group(process)
                raise QualificationError("trusted command exceeded its fixed wall-clock deadline")
            for key, _ in selector.select(timeout=remaining):
                name, limit = key.data
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                if len(captured[name]) + len(block) > limit:
                    overflow = True
                else:
                    captured[name].extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            terminate_owned_process_group(process)
            raise QualificationError("trusted command exceeded its fixed wall-clock deadline")
        status = process.wait(timeout=remaining)
    except BaseException:
        terminate_owned_process_group(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if overflow:
        raise QualificationError("trusted command output exceeded its bounded limit")
    return status, bytes(captured["stdout"]), bytes(captured["stderr"])


def git(repo: pathlib.Path, *arguments: str, gitdir: pathlib.Path | None = None) -> bytes:
    executable = trusted_git_executable()
    bound = [] if gitdir is None else ["--work-tree", str(repo), "--git-dir", str(gitdir)]
    status, output, diagnostics = bounded_run(
        [str(executable), "--no-pager", "-c", "core.fsmonitor=false", *bound, *arguments],
        cwd=repo,
        env=safe_git_environment(),
        timeout_seconds=GIT_TIMEOUT_SECONDS,
    )
    if status != 0 or diagnostics:
        raise QualificationError("trusted git command failed")
    return output


def one_git_line(repo: pathlib.Path, *arguments: str, gitdir: pathlib.Path | None = None) -> str:
    value = git(repo, *arguments, gitdir=gitdir)
    if not value.endswith(b"\n") or b"\n" in value[:-1] or b"\r" in value or b"\0" in value:
        raise QualificationError("trusted git provenance is not one canonical line")
    try:
        return value[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise QualificationError("trusted git provenance is not ASCII") from error


def source_snapshot(repo: pathlib.Path, gitdir: pathlib.Path) -> dict[str, str]:
    revision = one_git_line(repo, "rev-parse", "HEAD", gitdir=gitdir)
    tree = one_git_line(repo, "rev-parse", f"{revision}^{{tree}}", gitdir=gitdir)
    if len(revision) != 40 or len(tree) != 40 or any(character not in "0123456789abcdef" for character in revision + tree):
        raise QualificationError("trusted git object identity is not exact lowercase sha1")
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all", "--ignored", "--ignore-submodules=none", gitdir=gitdir):
        raise QualificationError("release source is not clean including untracked and ignored files")
    status, output, diagnostics = bounded_run(
        [str(trusted_git_executable()), "--no-pager", "--work-tree", str(repo), "--git-dir", str(gitdir), "rev-parse", "-q", "--verify", "MERGE_HEAD"],
        cwd=repo,
        env=safe_git_environment(),
        timeout_seconds=GIT_TIMEOUT_SECONDS,
    )
    if status != 1 or output or diagnostics:
        raise QualificationError("release source has merge state or unreadable merge state")
    submodules = git(repo, "submodule", "status", "--recursive", gitdir=gitdir)
    if any(line[:1] in (b"-", b"+", b"U") for line in submodules.splitlines()):
        raise QualificationError("release source submodule is absent, dirty, or conflicted")
    stages = git(repo, "ls-files", "--cached", "--stage", "-z", gitdir=gitdir)
    worktree = hashlib.sha256(b"sdk702-clean-worktree-index-stage-v1\0" + revision.encode() + b"\0" + tree.encode() + b"\0" + stages).hexdigest()
    lock = digest_bytes(read_bounded_regular_file(repo / "Cargo.lock", 4 * 1024 * 1024))
    schema = digest_bytes(read_bounded_regular_file(repo / "crates/opc-session-store/qualification/v1/fenced-transition-v2-release-evidence.schema.json", 64 * 1024))
    wrapper = digest_bytes(read_bounded_regular_file(repo / "ci/sdk702-release-attest.py", 64 * 1024))
    if one_git_line(repo, "rev-parse", "HEAD", gitdir=gitdir) != revision:
        raise QualificationError("release source HEAD changed during trusted snapshot")
    return {"revision": revision, "tree": tree, "worktree": worktree, "lock": lock, "schema": schema, "wrapper": wrapper}


def trusted_cargo_executable(value: str) -> pathlib.Path:
    cargo = pathlib.Path(value)
    if not cargo.is_absolute() or not cargo.is_file():
        raise QualificationError("wrapper requires an absolute trusted cargo executable")
    # Keep the absolute `cargo` link spelling as argv[0]. On rustup systems a
    # canonicalized link becomes the generic `rustup` binary and no longer
    # dispatches the Cargo subcommand, while `resolve()` still proves the
    # selected backing object is a regular file.
    if not cargo.resolve(strict=True).is_file():
        raise QualificationError("trusted cargo executable backing object is invalid")
    return cargo


def cargo_environment(cargo: pathlib.Path, target: pathlib.Path, snapshot: dict[str, str]) -> dict[str, str]:
    # The explicit absolute Cargo image avoids selecting a caller-controlled
    # PATH executable. The resulting test binary is separately descriptor
    # hashed and checked by the test at runtime.
    home = os.environ.get("HOME")
    if not home or not pathlib.Path(home).is_absolute() or not pathlib.Path(home).is_dir():
        raise QualificationError("wrapper requires an absolute existing Cargo home root")
    home_path = pathlib.Path(home).resolve(strict=True)
    cargo_home = pathlib.Path(os.environ.get("CARGO_HOME", str(home_path / ".cargo")))
    rustup_home = pathlib.Path(os.environ.get("RUSTUP_HOME", str(home_path / ".rustup")))
    if not cargo_home.is_absolute() or not cargo_home.is_dir() or not rustup_home.is_absolute() or not rustup_home.is_dir():
        raise QualificationError("wrapper requires absolute existing Cargo and rustup homes")
    environment = {key: value for key, value in os.environ.items() if key in {"SSL_CERT_FILE", "SSL_CERT_DIR", "TERM"}}
    environment.update(
        {
            "PATH": "/usr/bin:/bin",
            "CARGO": str(cargo),
            "HOME": str(home_path),
            "CARGO_HOME": str(cargo_home.resolve(strict=True)),
            "RUSTUP_HOME": str(rustup_home.resolve(strict=True)),
            "CARGO_TARGET_DIR": str(target),
            "OPC_QUAL_SOURCE_REVISION": snapshot["revision"],
            "OPC_QUAL_SOURCE_TREE": snapshot["tree"],
            "OPC_QUAL_SOURCE_WORKTREE_SHA256": snapshot["worktree"],
            "OPC_QUAL_RELEASE_SCHEMA_SHA256": snapshot["schema"],
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def build_exact_test(repo: pathlib.Path, cargo: pathlib.Path, target: pathlib.Path, snapshot: dict[str, str]) -> pathlib.Path:
    environment = cargo_environment(cargo, target, snapshot)
    status, output, diagnostics = bounded_run(
        [cargo, "test", "--locked", "--release", "--no-run", "--message-format=json", "-p", "opc-session-store", "--test", "fenced_transition_v2_qualification"],
        cwd=repo,
        env=environment,
        timeout_seconds=BUILD_TIMEOUT_SECONDS,
    )
    if status != 0:
        raise QualificationError("exact locked release no-run build failed")
    executable: list[pathlib.Path] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise QualificationError("cargo machine output was not JSON") from error
        target_info = event.get("target", {})
        if event.get("reason") == "compiler-artifact" and target_info.get("name") == "fenced_transition_v2_qualification" and target_info.get("kind") == ["test"]:
            value = event.get("executable")
            if not isinstance(value, str):
                raise QualificationError("exact test artifact had no executable")
            executable.append(pathlib.Path(value))
    if len(executable) != 1:
        raise QualificationError("exact locked build did not emit exactly one test executable")
    candidate = executable[0]
    if not candidate.is_absolute() or not overlaps(candidate.resolve(strict=True), target):
        raise QualificationError("exact test executable is not inside isolated target")
    return candidate


def write_attestation(namespace: pathlib.Path, document: dict[str, object]) -> pathlib.Path:
    parent = namespace.parent
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        parent_before = os.fstat(parent_fd)
        os.mkdir(namespace.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        namespace_fd = os.open(namespace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            namespace_identity = os.fstat(namespace_fd)
            # Rust's closed serde struct order is the canonical attestation
            # order. The insertion order below deliberately matches it.
            encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(ATTESTATION_LEAF, flags, 0o600, dir_fd=namespace_fd)
            try:
                written = 0
                while written < len(encoded):
                    count = os.write(descriptor, encoded[written:])
                    if count <= 0:
                        raise QualificationError("write trusted release attestation")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if (namespace_identity.st_dev, namespace_identity.st_ino) != (os.fstat(namespace_fd).st_dev, os.fstat(namespace_fd).st_ino):
                raise QualificationError("private attestation namespace identity changed")
            os.fsync(namespace_fd)
        finally:
            os.close(namespace_fd)
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
            raise QualificationError("attestation external parent identity changed")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return namespace / ATTESTATION_LEAF


def release_arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--snapshot-root", required=True)
    parser.add_argument("--attestation-namespace", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--process-loss-evidence", required=True)
    parser.add_argument("--lease", required=True)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str]) -> int:
    arguments = release_arguments().parse_args(argv)
    repo = pathlib.Path(__file__).resolve(strict=True).parents[1]
    if pathlib.Path(__file__).resolve(strict=True) != repo / "ci/sdk702-release-attest.py":
        raise QualificationError("wrapper must execute its canonical checked-in path")
    cargo = trusted_cargo_executable(arguments.cargo)
    target = absent_namespace(arguments.target_dir, "target directory")
    snapshot_base, snapshot_base_fd, snapshot_base_identity = open_private_absolute_directory(
        arguments.snapshot_root, "fs-verity snapshot root"
    )
    if os.environ.get(FS_VERITY_QUALIFICATION_ENV) != "required":
        os.close(snapshot_base_fd)
        raise QualificationError("wrapper requires the fixed fs-verity qualification marker")
    supplied_snapshot_base = os.environ.get(FS_VERITY_SNAPSHOT_ROOT_ENV)
    if supplied_snapshot_base is None or os.fsencode(supplied_snapshot_base) != os.fsencode(str(snapshot_base)):
        os.close(snapshot_base_fd)
        raise QualificationError("wrapper fs-verity snapshot root environment does not bind the canonical argument")
    try:
        attestation_namespace = absent_namespace(arguments.attestation_namespace, "attestation namespace")
        evidence_namespace = absent_namespace(arguments.evidence, "evidence namespace")
        process_loss_pair = pin_process_loss_pair(arguments.process_loss_evidence)
    except BaseException:
        os.close(snapshot_base_fd)
        raise
    try:
        lease = pin_lease_leaf(arguments.lease)
    except BaseException:
        process_loss_pair.close()
        os.close(snapshot_base_fd)
        raise
    try:
        gitdir = pathlib.Path(one_git_line(repo, "rev-parse", "--absolute-git-dir")).resolve(strict=True)
        common_value = pathlib.Path(one_git_line(repo, "rev-parse", "--git-common-dir"))
        common_gitdir = (common_value if common_value.is_absolute() else repo / common_value).resolve(strict=True)
        protected = [repo, gitdir, common_gitdir]
        require_external_disjoint_from_protected(
            protected,
            [target, snapshot_base, attestation_namespace, evidence_namespace, lease.path],
        )
        require_process_loss_root_external_topology(
            protected,
            process_loss_pair.evidence_root_path,
            [target, snapshot_base, attestation_namespace, evidence_namespace, lease.path],
            [target.parent, snapshot_base.parent, attestation_namespace.parent, evidence_namespace.parent, lease.parent_path],
        )
        snapshot = source_snapshot(repo, gitdir)
        if arguments.check:
            print("SDK702_RELEASE_ATTEST_CHECK ok")
            return 0
        lease.open_for_child()
        target_fd, target_identity = create_private_target(target)
        snapshot_fd: int | None = None
        try:
            snapshot_root, snapshot_fd, snapshot_identity = create_private_snapshot_namespace(
                snapshot_base, snapshot_base_fd, snapshot_base_identity, target
            )
            require_distinct_snapshot_filesystem(target_identity, snapshot_base_identity)
            verify_pinned_directory(target, target_fd, target_identity, "fresh target namespace")
            verify_pinned_snapshot_namespace(
                snapshot_base,
                snapshot_base_fd,
                snapshot_base_identity,
                snapshot_root,
                snapshot_fd,
                snapshot_identity,
            )
            executable = build_exact_test(repo, cargo, target, snapshot)
            verify_pinned_directory(target, target_fd, target_identity, "fresh target namespace")
            if source_snapshot(repo, gitdir) != snapshot:
                raise QualificationError("source changed after exact release build")
            (process_loss_bytes, process_loss_identity, process_loss_digest), (process_loss_v1_bytes, process_loss_v1_identity, process_loss_v1_digest) = process_loss_pair.read()
            del process_loss_bytes
            del process_loss_v1_bytes
            descriptor = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            try:
                executable_digest, identity = digest_file_descriptor(descriptor)
                attestation = {
                    "kind": ATTESTATION_KIND,
                    "source_revision": snapshot["revision"],
                    "source_tree": snapshot["tree"],
                    "source_worktree_sha256": snapshot["worktree"],
                    "cargo_lock_sha256": snapshot["lock"],
                    "release_schema_sha256": snapshot["schema"],
                    "cargo_target_dir_id": "sha256:" + digest_bytes(os.fsencode(target)),
                    "fs_verity_snapshot_base_id": "sha256:" + digest_bytes(os.fsencode(snapshot_base)),
                    "fs_verity_snapshot_root_id": "sha256:" + digest_bytes(os.fsencode(snapshot_root)),
                    "fs_verity_snapshot_root_device": snapshot_identity[0],
                    "fs_verity_snapshot_root_inode": snapshot_identity[1],
                    "executable_sha256": executable_digest,
                    "executable_device": identity.st_dev,
                    "executable_inode": identity.st_ino,
                    "wrapper_sha256": snapshot["wrapper"],
                    "observed_libtest_argv": list(LIBTEST_ARGS),
                    "required_reproduction_recipe": RECIPE,
                }
                attestation_path = write_attestation(attestation_namespace, attestation)
                environment = cargo_environment(cargo, target, snapshot)
                environment.update(
                    {
                        "OPC_QUAL_BUILD_ATTESTATION": str(attestation_path),
                        "OPC_QUAL_EVIDENCE": str(evidence_namespace),
                        "OPC_QUAL_PROCESS_LOSS_EVIDENCE": str(process_loss_pair.v9_path),
                        "OPC_QUAL_PROCESS_LOSS_EVIDENCE_SHA256": process_loss_digest,
                        "OPC_QUAL_PROCESS_LOSS_EVIDENCE_DEVICE": str(process_loss_identity.st_dev),
                        "OPC_QUAL_PROCESS_LOSS_EVIDENCE_INODE": str(process_loss_identity.st_ino),
                        "OPC_QUAL_PROCESS_LOSS_EVIDENCE_SIZE": str(process_loss_identity.st_size),
                        "OPC_QUAL_PROCESS_LOSS_V1_SHA256": process_loss_v1_digest,
                        "OPC_QUAL_PROCESS_LOSS_V1_DEVICE": str(process_loss_v1_identity.st_dev),
                        "OPC_QUAL_PROCESS_LOSS_V1_INODE": str(process_loss_v1_identity.st_ino),
                        "OPC_QUAL_PROCESS_LOSS_V1_SIZE": str(process_loss_v1_identity.st_size),
                        FS_VERITY_SNAPSHOT_ROOT_ENV: str(snapshot_root),
                        FS_VERITY_QUALIFICATION_ENV: "required",
                    }
                )
                verify_pinned_directory(target, target_fd, target_identity, "fresh target namespace")
                verify_pinned_snapshot_namespace(
                    snapshot_base,
                    snapshot_base_fd,
                    snapshot_base_identity,
                    snapshot_root,
                    snapshot_fd,
                    snapshot_identity,
                )
                # Re-read descriptor-pinned evidence and revalidate the leaf
                # paths immediately before the child is allowed to consume it.
                (final_process_loss, final_process_loss_identity, final_process_loss_digest), (final_process_loss_v1, final_process_loss_v1_identity, final_process_loss_v1_digest) = process_loss_pair.read()
                del final_process_loss
                del final_process_loss_v1
                if (
                    descriptor_identity(final_process_loss_identity) != descriptor_identity(process_loss_identity)
                    or final_process_loss_digest != process_loss_digest
                    or descriptor_identity(final_process_loss_v1_identity) != descriptor_identity(process_loss_v1_identity)
                    or final_process_loss_v1_digest != process_loss_v1_digest
                ):
                    raise QualificationError("process-loss pair changed before child execution")
                # cargo_environment is a scrubbed allowlist, and remove these
                # again defensively before installing the wrapper-owned pin.
                for key in tuple(environment):
                    if key == "OPC_QUAL_LEASE" or key.startswith("OPC_QUAL_LEASE_PIN_"):
                        del environment[key]
                environment.update(lease.environment_contract())
                if lease.leaf_descriptor is None:
                    raise QualificationError("lease descriptor is not pinned for child execution")
                # `/proc/self/fd/N` carries the exact already-hashed inode into the
                # child; it removes the final executable pathname replacement race.
                status, output, diagnostics = bounded_run(
                    [f"/proc/self/fd/{descriptor}", *LIBTEST_ARGS],
                    cwd=repo,
                    env=environment,
                    timeout_seconds=RELEASE_RUNTIME_TIMEOUT_SECONDS,
                    stdout_limit=MAX_OUTPUT,
                    stderr_limit=MAX_DIAGNOSTICS,
                    pass_fds=(descriptor,),
                )
                if status != 0:
                    raise QualificationError("exact pinned release test failed")
                verify_pinned_directory(target, target_fd, target_identity, "fresh target namespace")
                verify_pinned_snapshot_namespace(
                    snapshot_base,
                    snapshot_base_fd,
                    snapshot_base_identity,
                    snapshot_root,
                    snapshot_fd,
                    snapshot_identity,
                )
                sys.stdout.buffer.write(output)
                return 0
            finally:
                os.close(descriptor)
        finally:
            if snapshot_fd is not None:
                os.close(snapshot_fd)
            os.close(target_fd)
    finally:
        lease.close()
        process_loss_pair.close()
        os.close(snapshot_base_fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except QualificationError as error:
        print(f"SDK702_RELEASE_ATTEST failed: {error}", file=sys.stderr)
        raise SystemExit(2)
    except (OSError, UnicodeError):
        print("SDK702_RELEASE_ATTEST failed: private qualification I/O error", file=sys.stderr)
        raise SystemExit(2)

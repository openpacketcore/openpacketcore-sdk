#!/usr/bin/env python3
"""Focused environment tests for the SDK-702 trusted release wrapper."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER_PATH = ROOT / "ci" / "sdk702-release-attest.py"
SPEC = importlib.util.spec_from_file_location("sdk702_release_attest", WRAPPER_PATH)
assert SPEC is not None and SPEC.loader is not None
WRAPPER = importlib.util.module_from_spec(SPEC)
import sys

sys.modules[SPEC.name] = WRAPPER
SPEC.loader.exec_module(WRAPPER)

SNAPSHOT = {
    "revision": "a" * 40,
    "tree": "b" * 40,
    "worktree": "c" * 64,
    "lock": "d" * 64,
    "schema": "e" * 64,
    "wrapper": "f" * 64,
}


class FakeProcessLossPair:
    def __init__(self, root: pathlib.Path) -> None:
        self.evidence_root_path = root
        self.v9_path = root / "persistent-consumer-v9.json"
        self.v1_path = root / "batch-release-gate-v1.json"
        self.v9_path.write_bytes(b"v9")
        self.v1_path.write_bytes(b"v1")

    def read(self):
        v9_stat = self.v9_path.stat()
        v1_stat = self.v1_path.stat()
        return (
            (b"v9", v9_stat, WRAPPER.digest_bytes(b"v9")),
            (b"v1", v1_stat, WRAPPER.digest_bytes(b"v1")),
        )

    def close(self) -> None:
        pass


class FakeLease:
    leaf_descriptor = 1
    path = pathlib.Path("/external/lease")
    parent_path = pathlib.Path("/external")

    def open_for_child(self) -> None:
        pass

    def environment_contract(self) -> dict[str, str]:
        return {"OPC_QUAL_LEASE": "/external/lease"}

    def close(self) -> None:
        pass


class ReleaseAttestationEnvironmentTests(unittest.TestCase):
    def test_process_loss_readers_use_distinct_v9_and_frozen_v1_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "persistent-consumer-v9.json"
            formerly_oversized = b"v" * (64 * 1024 + 1)
            path.write_bytes(formerly_oversized)
            self.assertEqual(
                WRAPPER.read_bounded_regular_file(path, WRAPPER.MAX_PROCESS_LOSS_V9_EVIDENCE),
                formerly_oversized,
            )
            with self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.read_bounded_regular_file(path, WRAPPER.MAX_PROCESS_LOSS_V1_EVIDENCE)
            path.write_bytes(b"v" * (WRAPPER.MAX_PROCESS_LOSS_V9_EVIDENCE + 1))
            with self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.read_bounded_regular_file(path, WRAPPER.MAX_PROCESS_LOSS_V9_EVIDENCE)

    def private_homes(self, root: pathlib.Path) -> dict[str, str]:
        home = root / "home"
        cargo_home = home / ".cargo"
        rustup_home = home / ".rustup"
        for directory in (home, cargo_home, rustup_home):
            directory.mkdir(mode=0o700)
        return {
            "HOME": str(home),
            "CARGO_HOME": str(cargo_home),
            "RUSTUP_HOME": str(rustup_home),
            "TMPDIR": "/hostile/caller-tmp",
            "CARGO_TARGET_DIR": "/hostile/caller-target",
            "LD_PRELOAD": "/hostile/loader",
            "RUSTFLAGS": "--cfg hostile",
            "UNRELATED_HOSTILE_ENV": "must-not-survive",
        }

    def create_target(self, root: pathlib.Path) -> tuple[pathlib.Path, int, tuple[int, int, int]]:
        parent = root / "external-parent"
        parent.mkdir(mode=0o700)
        target = parent / "absent-wrapper-target"
        descriptor, identity = WRAPPER.create_private_target(target)
        return target, descriptor, identity

    def test_process_loss_topology_allows_disjoint_siblings_under_one_external_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            protected = [root / "worktree", root / "gitdir", root / "common-gitdir"]
            for boundary in protected:
                boundary.mkdir(mode=0o700)
            external = root / "external"
            external.mkdir(mode=0o700)
            producer_root = external / "testkit-v9-root"
            producer_root.mkdir(mode=0o700)
            unrelated = [
                external / "wrapper-target",
                external / "testkit-fsverity-snapshots",
                external / "attestation",
                external / "store-evidence",
                external / "lease" / "sdk702.lock",
            ]

            WRAPPER.require_process_loss_root_external_topology(
                protected,
                producer_root,
                unrelated,
                [candidate.parent for candidate in unrelated],
            )

    def test_process_loss_topology_rejects_actual_namespace_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            protected = [root / "worktree", root / "gitdir", root / "common-gitdir"]
            for boundary in protected:
                boundary.mkdir(mode=0o700)
            producer_root = root / "external" / "testkit-v9-root"
            producer_root.mkdir(parents=True, mode=0o700)

            for unrelated in (
                producer_root,
                producer_root / "wrapper-target",
                producer_root.parent,
            ):
                with self.assertRaises(WRAPPER.QualificationError):
                    WRAPPER.require_process_loss_root_external_topology(
                        protected,
                        producer_root,
                        [unrelated],
                        [unrelated.parent],
                    )

    def test_build_environment_drops_hostile_tmpdir_without_broad_inheritance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target, descriptor, identity = self.create_target(root)
            try:
                with mock.patch.dict(WRAPPER.os.environ, self.private_homes(root), clear=True):
                    environment = WRAPPER.cargo_environment(pathlib.Path("/usr/bin/true"), target, SNAPSHOT)
                self.assertEqual(environment["CARGO_TARGET_DIR"], str(target))
                self.assertNotIn("TMPDIR", environment)
                self.assertNotIn(WRAPPER.FS_VERITY_SNAPSHOT_ROOT_ENV, environment)
                self.assertNotIn(WRAPPER.FS_VERITY_QUALIFICATION_ENV, environment)
                self.assertNotIn("LD_PRELOAD", environment)
                self.assertNotIn("RUSTFLAGS", environment)
                self.assertNotIn("UNRELATED_HOSTILE_ENV", environment)
                self.assertEqual(
                    set(environment),
                    {
                        "PATH",
                        "CARGO",
                        "HOME",
                        "CARGO_HOME",
                        "RUSTUP_HOME",
                        "CARGO_TARGET_DIR",
                        "OPC_QUAL_SOURCE_REVISION",
                        "OPC_QUAL_SOURCE_TREE",
                        "OPC_QUAL_SOURCE_WORKTREE_SHA256",
                        "OPC_QUAL_RELEASE_SCHEMA_SHA256",
                        "LC_ALL",
                        "LANG",
                    },
                )
                target_stat = target.stat()
                self.assertEqual(target_stat.st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(target_stat.st_mode), 0o700)
                WRAPPER.verify_pinned_directory(target, descriptor, identity, "test target")
            finally:
                os.close(descriptor)

    def test_cargo_build_does_not_receive_snapshot_or_tmpdir_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target, descriptor, _ = self.create_target(root)
            try:
                executable = target / "release" / "deps" / "fenced_transition_v2_qualification"
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b"test executable")
                captured: list[dict[str, str]] = []

                def fake_bounded_run(arguments, *, cwd, env, timeout_seconds, **_):
                    captured.append(env)
                    event = {
                        "reason": "compiler-artifact",
                        "target": {"name": "fenced_transition_v2_qualification", "kind": ["test"]},
                        "executable": str(executable),
                    }
                    return 0, (WRAPPER.json.dumps(event) + "\n").encode(), b""

                with mock.patch.dict(WRAPPER.os.environ, self.private_homes(root), clear=True), mock.patch.object(
                    WRAPPER, "bounded_run", side_effect=fake_bounded_run
                ):
                    observed = WRAPPER.build_exact_test(ROOT, pathlib.Path("/usr/bin/true"), target, SNAPSHOT)
                self.assertEqual(observed, executable)
                self.assertEqual(len(captured), 1)
                self.assertEqual(captured[0]["CARGO_TARGET_DIR"], str(target))
                self.assertNotIn("TMPDIR", captured[0])
                self.assertNotIn(WRAPPER.FS_VERITY_SNAPSHOT_ROOT_ENV, captured[0])
                self.assertNotIn(WRAPPER.FS_VERITY_QUALIFICATION_ENV, captured[0])
            finally:
                os.close(descriptor)

    def test_pinned_release_child_receives_only_the_fixed_private_snapshot_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private_parent = root / "external-parent"
            private_parent.mkdir(mode=0o700)
            snapshot_base = root / "external-fs-verity-snapshots"
            snapshot_base.mkdir(mode=0o700)
            target = private_parent / "absent-wrapper-target"
            attestation = private_parent / "absent-attestation"
            evidence = private_parent / "absent-evidence"
            process_loss_root = root / "process-loss-root"
            process_loss_root.mkdir(mode=0o700)
            process_loss_pair = FakeProcessLossPair(process_loss_root)
            gitdir = root / "gitdir"
            gitdir.mkdir(mode=0o700)
            child_environments: list[dict[str, str]] = []
            real_create_private_target = WRAPPER.create_private_target

            def fake_build(_repo, _cargo, build_target, _snapshot):
                executable = build_target / "release" / "fenced_transition_v2_qualification"
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b"pinned test executable")
                return executable

            def fake_bounded_run(arguments, *, cwd, env, timeout_seconds, **_):
                self.assertTrue(str(arguments[0]).startswith("/proc/self/fd/"))
                child_environments.append(env)
                return 0, b"", b""

            def fake_create_private_target(path):
                descriptor, identity = real_create_private_target(path)
                # This injection test is intentionally host-portable. The
                # wrapper's real device topology is tested separately; use a
                # synthetic distinct target device only to reach the child-env
                # assertion without assuming a runner mount layout.
                return descriptor, (identity[0] + 1, identity[1], identity[2])

            arguments = [
                "--cargo",
                "/usr/bin/true",
                "--target-dir",
                str(target),
                "--snapshot-root",
                str(snapshot_base),
                "--attestation-namespace",
                str(attestation),
                "--evidence",
                str(evidence),
                "--process-loss-evidence",
                str(process_loss_pair.v9_path),
                "--lease",
                str(private_parent / "absent-lease"),
            ]
            environment = self.private_homes(root)
            environment.update(
                {
                    WRAPPER.FS_VERITY_QUALIFICATION_ENV: "required",
                    WRAPPER.FS_VERITY_SNAPSHOT_ROOT_ENV: str(snapshot_base),
                }
            )
            with mock.patch.dict(WRAPPER.os.environ, environment, clear=True), mock.patch.object(
                WRAPPER, "pin_process_loss_pair", return_value=process_loss_pair
            ), mock.patch.object(WRAPPER, "pin_lease_leaf", return_value=FakeLease()), mock.patch.object(
                WRAPPER, "one_git_line", return_value=str(gitdir)
            ), mock.patch.object(WRAPPER, "require_external_disjoint_from_protected"), mock.patch.object(
                WRAPPER, "require_process_loss_root_external_topology"
            ), mock.patch.object(WRAPPER, "source_snapshot", return_value=SNAPSHOT), mock.patch.object(
                WRAPPER, "build_exact_test", side_effect=fake_build
            ), mock.patch.object(WRAPPER, "write_attestation", return_value=attestation / WRAPPER.ATTESTATION_LEAF), mock.patch.object(
                WRAPPER, "bounded_run", side_effect=fake_bounded_run
            ), mock.patch.object(
                WRAPPER, "create_private_target", side_effect=fake_create_private_target
            ), mock.patch.object(
                WRAPPER, "verify_pinned_directory"
            ):
                self.assertEqual(WRAPPER.main(arguments), 0)

            self.assertEqual(len(child_environments), 1)
            self.assertEqual(child_environments[0]["CARGO_TARGET_DIR"], str(target))
            self.assertNotIn("TMPDIR", child_environments[0])
            snapshot_root = snapshot_base / (
                WRAPPER.FS_VERITY_SNAPSHOT_NAMESPACE_PREFIX
                + WRAPPER.digest_bytes(os.fsencode(target))[:32]
            )
            self.assertEqual(
                child_environments[0][WRAPPER.FS_VERITY_SNAPSHOT_ROOT_ENV], str(snapshot_root)
            )
            self.assertEqual(child_environments[0][WRAPPER.FS_VERITY_QUALIFICATION_ENV], "required")
            self.assertNotIn("LD_PRELOAD", child_environments[0])
            self.assertNotIn("RUSTFLAGS", child_environments[0])
            self.assertNotIn("UNRELATED_HOSTILE_ENV", child_environments[0])
            target_stat = target.stat()
            self.assertEqual(target_stat.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(target_stat.st_mode), 0o700)
            snapshot_stat = snapshot_root.stat()
            self.assertEqual(snapshot_stat.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(snapshot_stat.st_mode), 0o700)
            self.assertEqual(snapshot_root.parent, snapshot_base)

    def test_snapshot_namespace_pin_allows_child_content_but_rejects_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            snapshot_base = root / "snapshot-base"
            snapshot_base.mkdir(mode=0o700)
            canonical_base, base_descriptor, base_identity = WRAPPER.open_private_absolute_directory(
                str(snapshot_base), "test fs-verity root"
            )
            snapshot_descriptor = None
            try:
                snapshot_root, snapshot_descriptor, snapshot_identity = (
                    WRAPPER.create_private_snapshot_namespace(
                        canonical_base,
                        base_descriptor,
                        base_identity,
                        root / "absent-target",
                    )
                )
                (snapshot_root / "snapshots-0").mkdir(mode=0o700)
                WRAPPER.verify_pinned_snapshot_namespace(
                    canonical_base,
                    base_descriptor,
                    base_identity,
                    snapshot_root,
                    snapshot_descriptor,
                    snapshot_identity,
                )

                os.rename(snapshot_root, snapshot_base / "replaced-original")
                snapshot_root.mkdir(mode=0o700)
                with self.assertRaises(WRAPPER.QualificationError):
                    WRAPPER.verify_pinned_snapshot_namespace(
                        canonical_base,
                        base_descriptor,
                        base_identity,
                        snapshot_root,
                        snapshot_descriptor,
                        snapshot_identity,
                    )
            finally:
                if snapshot_descriptor is not None:
                    os.close(snapshot_descriptor)
                os.close(base_descriptor)

    def test_build_target_must_not_share_the_snapshot_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target, target_descriptor, target_identity = self.create_target(root)
            snapshot_base = root / "snapshot-base"
            snapshot_base.mkdir(mode=0o700)
            _, snapshot_descriptor, snapshot_identity = WRAPPER.open_private_absolute_directory(
                str(snapshot_base), "test fs-verity root"
            )
            try:
                self.assertEqual(target.stat().st_dev, snapshot_base.stat().st_dev)
                with self.assertRaisesRegex(
                    WRAPPER.QualificationError,
                    "must not share the fs-verity snapshot filesystem",
                ):
                    WRAPPER.require_distinct_snapshot_filesystem(
                        target_identity, snapshot_identity
                    )
            finally:
                os.close(snapshot_descriptor)
                os.close(target_descriptor)

    def test_private_snapshot_base_rejects_noncanonical_or_nonprivate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            canonical, descriptor, identity = WRAPPER.open_private_absolute_directory(
                str(private), "test fs-verity root"
            )
            try:
                self.assertEqual(canonical, private)
                WRAPPER.verify_pinned_directory(canonical, descriptor, identity, "test fs-verity root")
            finally:
                os.close(descriptor)
            with self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.open_private_absolute_directory(
                    f"{private}/.", "test fs-verity root"
                )
            with self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.open_private_absolute_directory(
                    f"{private}/", "test fs-verity root"
                )
            target_parent = root / "target-parent"
            target_parent.mkdir(mode=0o700)
            with mock.patch.dict(
                WRAPPER.os.environ,
                {
                    WRAPPER.FS_VERITY_QUALIFICATION_ENV: "required",
                    # The CLI is canonical, but the ambient spelling is not.
                    # The wrapper must reject it before opening any mutable
                    # release namespace.
                    WRAPPER.FS_VERITY_SNAPSHOT_ROOT_ENV: f"{private}/.",
                },
                clear=True,
            ), self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.main(
                    [
                        "--cargo",
                        "/usr/bin/true",
                        "--target-dir",
                        str(target_parent / "absent-target"),
                        "--snapshot-root",
                        str(private),
                        "--attestation-namespace",
                        str(target_parent / "absent-attestation"),
                        "--evidence",
                        str(target_parent / "absent-evidence"),
                        "--process-loss-evidence",
                        str(target_parent / "persistent-consumer-v9.json"),
                        "--lease",
                        str(target_parent / "absent-lease"),
                    ]
                )
            public = root / "public"
            public.mkdir(mode=0o755)
            with self.assertRaises(WRAPPER.QualificationError):
                WRAPPER.open_private_absolute_directory(str(public), "test fs-verity root")


if __name__ == "__main__":
    unittest.main()

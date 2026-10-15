#!/usr/bin/env python3
"""Exercise the hosted library split against exact selections and real Cargo."""

import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cargo_test_selection

try:
    import library_partition as PARTITION
except ModuleNotFoundError:
    PARTITION = None

ROOT = Path(__file__).resolve().parent.parent


class LibraryPartitionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(PARTITION, "ordinary library work needs a separate exact-name partition")
        self.base = ["cargo", "test", "--locked", "--workspace", "--all-features", "--quiet"]
        self.serial = ("module::serial_a", "module::serial_b")
        self.moved = "module::full_bound"
        skips = [arg for name in (*self.serial, self.moved) for arg in ("--skip", name)]
        self.phase = [self.base + ["--lib", "--", "--test-threads=1", "--exact", name]
                      for name in self.serial]
        self.phase.append(self.base + ["--lib", "--", "--test-threads=4", "--exact", *skips])
        self.rows = [
            {"package": "a", "target": "a", "kind": ["lib"], "name": name, "ignored": ignored}
            for name, ignored in [*((name, False) for name in (*self.serial, self.moved)),
                                  *((f"module::ordinary_{i}", i % 13 == 0) for i in range(120)),
                                  (self.moved + "_future", False)]
        ]
        self.rows.append(dict(self.rows[-1], package="b", target="b"))
        packages = [{"id": name, "name": name, "version": "0.1.0",
                     "targets": [{"name": name, "kind": ["lib"], "test": True}]}
                    for name in ("a", "b")]
        self.metadata = {"workspace_root": str(ROOT), "packages": packages,
                         "workspace_members": ["a", "b"], "workspace_default_members": ["a"]}

    def plans(self):
        return {shard: PARTITION.commands(self.phase, 2, self.rows, shard)
                for shard in PARTITION.SHARDS}

    def test_all_names_including_ignored_duplicates_and_future_siblings_keep_one_owner(self):
        plans = self.plans()
        original = [cargo_test_selection.resolve(argv, self.metadata) for argv in self.phase]
        selections = {shard: [cargo_test_selection.resolve(argv, self.metadata) for argv in commands]
                      for shard, commands in plans.items()}
        for row in self.rows:
            identity = (row["package"], row["target"], tuple(row["kind"]), row["name"])
            before = sum(selection.selects(*identity) for selection in original)
            owners = [shard for shard, commands in selections.items()
                      for selection in commands if selection.selects(*identity)]
            with self.subTest(identity=identity):
                self.assertEqual(len(owners), before)
                if row["name"] in self.serial:
                    self.assertEqual(owners, [0])
                elif row["name"] != self.moved:
                    self.assertEqual(owners, [PARTITION.owner(row["name"])])
        self.assertEqual(plans[0][:2], self.phase[:2])
        self.assertEqual(len(plans[1]), 1)
        for commands in plans.values():
            for command in commands:
                self.assertEqual(command[:len(self.base)], self.base)
                self.assertNotIn("--ignored", command)
        PARTITION.verify(self.phase, 2, self.rows, plans, self.metadata)

    def test_missing_overlap_profile_or_selector_mutation_is_rejected(self):
        for mutation in ("missing-shard", "missing-command", "overlap", "profile", "threads", "prefix", "package"):
            plans = self.plans()
            if mutation == "missing-shard":
                del plans[1]
            elif mutation == "missing-command":
                plans[0].pop(0)
            elif mutation == "overlap":
                plans[1].append(list(self.phase[0]))
            elif mutation == "profile":
                plans[1][0] = ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1", *plans[1][0]]
            elif mutation == "threads":
                index = plans[1][0].index("--test-threads=4")
                plans[1][0][index] = "--test-threads=1"
            elif mutation == "prefix":
                plans[1][0].remove("--exact")
            else:
                plans[1][0].remove("--workspace")
                plans[1][0][2:2] = ["-p", "a"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                PARTITION.verify(self.phase, 2, self.rows, plans, self.metadata)

    def test_inventory_rejects_missing_ignored_and_ambiguous_serial_contracts(self):
        for mutation in ("missing", "ignored", "ambiguous", "duplicate", "empty", "kind"):
            rows = copy.deepcopy(self.rows)
            if mutation == "missing":
                rows.pop(0)
            elif mutation == "ignored":
                rows[0]["ignored"] = True
            elif mutation == "ambiguous":
                rows.append(dict(rows[0], package="b", target="b"))
            elif mutation == "duplicate":
                rows.append(dict(rows[0]))
            elif mutation == "kind":
                rows[0]["kind"] = ["test"]
            else:
                rows = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                PARTITION.validate_rows(rows, self.serial)


class CompiledInventoryTests(unittest.TestCase):
    def test_missing_duplicate_or_unexpected_library_cannot_make_a_green_partition(self):
        import json
        metadata = {"workspace_root": str(ROOT), "workspace_members": ["a", "b"],
                    "workspace_default_members": ["a"], "packages": [
                        {"id": name, "name": name, "version": "0.1.0", "manifest_path": str(ROOT / name / "Cargo.toml"),
                         "targets": [{"name": name, "kind": ["lib"], "test": True}]}
                        for name in ("a", "b")]}
        artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                    "package_id": "a", "target": {"name": "a", "kind": ["lib"]}, "executable": "/unused/a"}
        for mutation in ("missing", "duplicate", "unexpected"):
            artifacts = [artifact]
            if mutation == "duplicate":
                artifacts.append(artifact)
            elif mutation == "unexpected":
                artifacts.append(dict(artifact, package_id="outside-workspace"))
            replies = [subprocess.CompletedProcess([], 0, stdout=json.dumps(metadata)),
                       subprocess.CompletedProcess([], 0, stdout="\n".join(map(json.dumps, artifacts)))]
            with self.subTest(mutation=mutation), patch.object(PARTITION.subprocess, "run", side_effect=replies) as execute, self.assertRaises(ValueError):
                PARTITION.inventory(["cargo", "test", "--locked", "--workspace", "--all-features"], ROOT)
            self.assertEqual(execute.call_count, 2)


class RealCargoPartitionTests(unittest.TestCase):
    def test_compiled_inventory_and_partition_run_every_new_test_once(self):
        self.assertIsNotNone(PARTITION, "ordinary library work needs a separate exact-name partition")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["a", "b"]\nresolver = "2"\n')
            expected = []
            for package in ("a", "b"):
                source = root / package / "src"
                source.mkdir(parents=True)
                # Explicit --lib includes test=false; this must not disappear
                # from the metadata/compiled-binary equality check.
                (source.parent / "Cargo.toml").write_text(
                    f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n'
                    + ('[lib]\ntest = false\n' if package == "b" else ''))
                tests = []
                for name in ("same_name", "newly_added", "isolated_future", "ignored_case"):
                    ignored = name == "ignored_case"
                    if not ignored:
                        expected.append(f"executed:{package}:{name}")
                    tests.append(f'#[test] {"#[ignore]" if ignored else ""}\nfn {name}() {{ println!("executed:{package}:{name}"); }}')
                (source / "lib.rs").write_text('\n'.join(tests))
            env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target/library-partition-fixture"))
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, env=env, check=True, capture_output=True)
            base = ["cargo", "test", "--locked", "--offline", "--workspace", "--all-features", "--quiet"]
            rows, metadata = PARTITION.inventory(base, root, env=env)
            self.assertEqual(len(rows), 8)
            self.assertEqual(sum(row["ignored"] for row in rows), 2)
            phase = [base + ["--lib", "--", "--test-threads=4", "--exact", "--nocapture"]]
            plans = {shard: PARTITION.commands(phase, 0, rows, shard) for shard in PARTITION.SHARDS}
            PARTITION.verify(phase, 0, rows, plans, metadata)
            observed = []
            for commands in plans.values():
                for argv in commands:
                    result = subprocess.run(argv, cwd=root, env=env, check=True, text=True, capture_output=True)
                    observed.extend(line[line.index("executed:"):] for line in result.stdout.splitlines() if "executed:" in line)
            self.assertCountEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()

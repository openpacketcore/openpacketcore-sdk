#!/usr/bin/env python3
"""Dependency-trigger regressions; run with python3 -I."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("egress-fence-changes.py")
SPEC = importlib.util.spec_from_file_location("egress_fence_changes", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHANGES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHANGES
SPEC.loader.exec_module(CHANGES)


def metadata(root: str = "/base") -> dict:
    """A hand-written Cargo graph: fence -> dependency; unrelated is not used."""
    return {
        "packages": [
            {"id": "fence", "name": "fence", "version": "1.0.0", "source": None,
             "manifest_path": f"{root}/crates/fence/Cargo.toml"},
            {"id": "dep", "name": "dependency", "version": "2.0.0",
             "source": "registry+https://example.invalid/index",
             "manifest_path": "/cargo/registry/dependency/Cargo.toml"},
            {"id": "other", "name": "unrelated", "version": "3.0.0", "source": None,
             "manifest_path": f"{root}/crates/unrelated/Cargo.toml"},
        ],
        "resolve": {"nodes": [
            {"id": "fence", "features": [], "dependencies": ["dep"]},
            {"id": "dep", "features": ["default"], "dependencies": []},
            {"id": "other", "features": [], "dependencies": []},
        ]},
    }


def snapshot(value: dict | None = None, root: str = "/base") -> dict:
    return {
        "repository_root": root,
        "settings": {},
        "profiles": {"host": {
            "metadata": metadata(root) if value is None else value,
            "roots": ["fence"],
        }},
    }


class DecisionTests(unittest.TestCase):
    def test_unrelated_dependency_bump_skips(self):
        before = snapshot()
        after = copy.deepcopy(before)
        after["profiles"]["host"]["metadata"]["packages"][2]["version"] = "3.1.0"
        self.assertFalse(CHANGES.decide(before, after, ["Cargo.lock"]).run)

    def test_checkout_location_and_package_order_do_not_trigger(self):
        before = snapshot()
        after = snapshot(root="/head")
        after["profiles"]["host"]["metadata"]["packages"].reverse()
        self.assertFalse(CHANGES.decide(before, after, ["README.md"]).run)

    def test_closure_version_source_and_features_each_trigger(self):
        for field, value in [("version", "2.1.0"), ("source", "git+https://example.invalid/dep#abc")]:
            with self.subTest(field=field):
                before = snapshot()
                after = copy.deepcopy(before)
                after["profiles"]["host"]["metadata"]["packages"][1][field] = value
                self.assertTrue(CHANGES.decide(before, after, ["Cargo.lock"]).run)
        before = snapshot()
        after = copy.deepcopy(before)
        after["profiles"]["host"]["metadata"]["resolve"]["nodes"][1]["features"].append("extra")
        self.assertTrue(CHANGES.decide(before, after, ["Cargo.toml"]).run)

    def test_dependency_added_or_removed_triggers(self):
        before = snapshot()
        after = copy.deepcopy(before)
        after["profiles"]["host"]["metadata"]["resolve"]["nodes"][0]["dependencies"].append("other")
        self.assertTrue(CHANGES.decide(before, after, ["Cargo.lock"]).run)
        self.assertTrue(CHANGES.decide(after, before, ["Cargo.lock"]).run)

    def test_transitive_path_dependency_source_triggers(self):
        before = snapshot()
        packages = before["profiles"]["host"]["metadata"]["packages"]
        packages[1]["source"] = None
        packages[1]["manifest_path"] = "/base/crates/dependency/Cargo.toml"
        self.assertTrue(CHANGES.decide(before, before, ["crates/dependency/src/lib.rs"]).run)
        self.assertFalse(CHANGES.decide(before, before, ["crates/dependency-extra/src/lib.rs"]).run)

    def test_fence_workflow_fixture_and_detector_paths_trigger(self):
        for path in [
            "crates/opc-egress-fence/src/linux_backend.rs",
            "crates/opc-egress-fence-common/src/lib.rs",
            "crates/opc-egress-fence-ebpf/oracle/src/main.rs",
            ".github/workflows/egress-fence.yml",
            "ci/setup-fsverity-tmp.sh",
            "scripts/build-egress-fence-ebpf.sh",
            "scripts/publish-order.py",
            "crates/opc-session-testkit/qualification/v6/session-ha-profile.json",
            "crates/opc-session-testkit/qualification/v6/session-ha-profile.schema.json",
            "crates/opc-session-testkit/tests/qualification_profile.rs",
            "ci/egress-fence-changes.py",
            "ci/test-egress-fence-changes.py",
            "ci/egress-fence-tests.py",
            "ci/test-egress-fence-tests.py",
            "ci/egress-fence-tools.sh",
            "ci/egress-fence-kernel.sh",
            "ci/egress-fence-cleanup.sh",
            ".cargo/config.toml",
            "rust-toolchain.toml",
            "crates/.cargo/config.toml",
            "rustfmt.toml",
            ".rustfmt.toml",
            "crates/opc-alarm/rustfmt.toml",
            "clippy.toml",
            "crates/.clippy.toml",
        ]:
            with self.subTest(path=path):
                self.assertTrue(CHANGES.decide(snapshot(), snapshot(), [path]).run)

    def test_malformed_or_incomplete_metadata_runs(self):
        for value in [None, {}, {"profiles": {}}, snapshot({"packages": [], "resolve": None})]:
            with self.subTest(value=value):
                self.assertTrue(CHANGES.decide(snapshot(), value, ["Cargo.lock"]).run)
        broken = snapshot()
        broken["profiles"]["host"]["metadata"]["resolve"]["nodes"].pop(1)
        self.assertTrue(CHANGES.decide(snapshot(), broken, ["Cargo.lock"]).run)

    def test_path_dependency_outside_checkout_runs(self):
        broken = snapshot()
        broken["profiles"]["host"]["metadata"]["packages"][0]["manifest_path"] = "/external/Cargo.toml"
        self.assertTrue(CHANGES.decide(broken, broken, ["README.md"]).run)

    def test_profile_feature_changes_are_not_hidden_by_the_union(self):
        before = snapshot()
        before["profiles"]["production"] = copy.deepcopy(before["profiles"]["host"])
        after = copy.deepcopy(before)
        after["profiles"]["production"]["metadata"]["resolve"]["nodes"][1]["features"] = []
        self.assertTrue(CHANGES.decide(before, after, ["Cargo.toml"]).run)

    def test_global_build_settings_trigger(self):
        before = snapshot()
        after = copy.deepcopy(before)
        after["settings"] = {"profile": {"release": {"lto": True}}}
        self.assertTrue(CHANGES.decide(before, after, ["Cargo.toml"]).run)

    def test_unused_workspace_dependency_and_membership_edits_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "Cargo.toml"
            manifest.write_text('[workspace]\nmembers = ["crates/fence"]\nresolver = "2"\n')
            before = snapshot()
            before["settings"] = CHANGES.shared_settings(root)
            manifest.write_text(
                '[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n'
                '[workspace.dependencies]\nunrelated = "3.1.0"\n'
            )
            after = snapshot()
            after["settings"] = CHANGES.shared_settings(root)
            self.assertFalse(CHANGES.decide(before, after, ["Cargo.toml"]).run)
            with manifest.open("a") as stream:
                stream.write('[profile.release]\nlto = true\n')
            after["settings"] = CHANGES.shared_settings(root)
            self.assertTrue(CHANGES.decide(before, after, ["Cargo.toml"]).run)


class CargoProjectionTests(unittest.TestCase):
    def test_selected_tree_excludes_unrelated_workspace_features(self):
        raw = metadata()
        raw["resolve"]["nodes"][1]["features"].append("unrelated-feature")
        tree = "0fence v1.0.0 (/base/crates/fence)|\n1dependency v2.0.0|default\n"
        actual = CHANGES.project_tree(raw, tree, ("fence",))
        nodes = {node["id"]: node for node in actual["metadata"]["resolve"]["nodes"]}
        self.assertEqual(actual["roots"], ["fence"])
        self.assertEqual(set(nodes), {"fence", "dep"})
        self.assertEqual(nodes["dep"]["features"], ["default"])
        self.assertEqual(nodes["fence"]["dependencies"], ["dep"])

    def test_duplicate_nodes_keep_their_transitive_edges(self):
        raw = metadata()
        tree = ("0fence v1.0.0 (/base/crates/fence)|\n"
                "1dependency v2.0.0 (proc-macro)|default\n"
                "2unrelated v3.0.0 (/base/crates/unrelated)|\n"
                "1dependency v2.0.0 (proc-macro)|default (*)\n")
        actual = CHANGES.project_tree(raw, tree, ("fence",))
        nodes = {node["id"]: node for node in actual["metadata"]["resolve"]["nodes"]}
        self.assertEqual(nodes["dep"]["dependencies"], ["other"])

    def test_feature_moving_between_build_contexts_triggers(self):
        # dependency is built once for the target and once for a proc-macro.
        def project(host_features):
            tree = ("0fence v1.0.0 (/base/crates/fence)|\n"
                    "1dependency v2.0.0|default,std\n"
                    "1unrelated v3.0.0 (proc-macro)|\n"
                    f"2dependency v2.0.0|{host_features}\n")
            before = snapshot()
            before["profiles"]["host"] = CHANGES.project_tree(metadata(), tree, ("fence",))
            return before

        self.assertTrue(CHANGES.decide(project("default"), project("default,std"), ["Cargo.toml"]).run)
        self.assertFalse(CHANGES.decide(project("default"), project("default"), ["Cargo.toml"]).run)

    def test_unknown_or_ambiguous_tree_is_not_accepted(self):
        for tree in ["", "unexpected output", "1fence v1.0.0|", "0missing v1.0.0|"]:
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                CHANGES.project_tree(metadata(), tree, ("fence",))
        raw = metadata()
        duplicate = copy.deepcopy(raw["packages"][1])
        duplicate["id"] = "ambiguous"
        duplicate["source"] = "git+https://example.invalid/dependency#abc"
        raw["packages"].append(duplicate)
        with self.assertRaises(ValueError):
            CHANGES.project_tree(raw, "0fence v1.0.0|\n1dependency v2.0.0|", ("fence",))

    def test_wrong_root_cannot_produce_a_skip(self):
        with self.assertRaises(ValueError):
            CHANGES.project_tree(metadata(), "0unrelated v3.0.0|", ("fence",))


class CargoIntegrationTests(unittest.TestCase):
    def test_isolated_store_feature_change_cannot_hide_in_combined_host_features(self):
        # Every dependency is local. Only Cargo resolution runs; nothing builds
        # or downloads. Runtime enables extra independently, masking the store
        # change when both packages are selected together.
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            names = (
                "opc-egress-fence", "opc-egress-fence-common", "opc-linux-gtpu-sys",
                "opc-linux-xfrm-sys", "opc-runtime", "opc-session-store", "trigger-shared",
            )

            def package(name, relative):
                directory = repo / relative
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").write_text("")
                manifest = directory / "Cargo.toml"
                manifest.write_text(
                    f'[package]\nname = "{name}"\nversion = "1.0.0"\nedition = "2021"\n'
                )
                return manifest

            for name in names:
                manifest = package(name, "crates/" + name)
                with manifest.open("a") as stream:
                    if name == "opc-runtime":
                        stream.write('[dependencies]\ntrigger-shared = '
                                     '{ path = "../trigger-shared", features = ["extra"] }\n')
                    elif name == "opc-session-store":
                        stream.write('[dependencies]\ntrigger-shared.workspace = true\n')
                    elif name == "trigger-shared":
                        stream.write('[features]\nextra = []\n')
            ebpf = package("opc-egress-fence-ebpf", "crates/opc-egress-fence-ebpf")
            with ebpf.open("a") as stream:
                stream.write('[workspace]\nmembers = ["oracle"]\nresolver = "2"\n'
                             '[features]\nfault-inject-delete = []\n'
                             'mutation-bypass-deadline = []\nmutation-bypass-gate = []\n')
            package("opc-egress-fence-object-oracle", "crates/opc-egress-fence-ebpf/oracle")
            manifest = repo / "Cargo.toml"
            manifest.write_text(
                '[workspace]\nresolver = "2"\nmembers = '
                + json.dumps(["crates/" + name for name in names])
                + '\nexclude = ["crates/opc-egress-fence-ebpf"]\n'
                + '[workspace.dependencies.trigger-shared]\npath = "crates/trigger-shared"\n'
            )
            # Lock the all-local fixtures once, then exercise the actual --locked
            # snapshot path used by CI for both sides of the manifest edit.
            for path in (manifest, ebpf):
                subprocess.run(["cargo", "generate-lockfile", "--manifest-path", str(path)],
                               cwd=repo, check=True, capture_output=True)
            before = CHANGES.snapshot(repo)
            with manifest.open("a") as stream:
                stream.write('features = ["extra"]\n')
            after = CHANGES.snapshot(repo)
            self.assertEqual(
                CHANGES.closure(before["profiles"]["host-gates"], str(repo)),
                CHANGES.closure(after["profiles"]["host-gates"], str(repo)),
            )
            decision = CHANGES.decide(before, after, ["Cargo.toml"])
            self.assertTrue(decision.run, decision.reason)


class EventTests(unittest.TestCase):
    def invoke(self, arguments: list[str], event: dict | None = None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps(event or {}))
            env = dict(os.environ, GITHUB_OUTPUT=str(output), GITHUB_EVENT_PATH=str(event_path))
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), *arguments],
                                    env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            decision = json.loads(result.stdout)
            self.assertEqual(output.read_text(), f"run={str(decision['run']).lower()}\n")
            return decision

    def test_nightly_and_manual_always_run_without_metadata(self):
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                result = self.invoke(["--event", event, "--repo", "/missing-checkout"])
                self.assertTrue(result["run"])

    def test_unknown_base_and_zero_push_base_run(self):
        for base in ("missing-revision", "0" * 40):
            with self.subTest(base=base):
                self.assertTrue(self.invoke(["--event", "push", "--base", base, "--head", "HEAD"])["run"])

    def test_cargo_metadata_process_failure_requests_full_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", tmp], check=True)
            for key, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid")):
                subprocess.run(["git", "-C", tmp, "config", key, value], check=True)
            # This is deliberately invalid TOML: Cargo must fail before network access.
            (repo / "Cargo.toml").write_text("[invalid\n")
            subprocess.run(["git", "-C", tmp, "add", "Cargo.toml"], check=True)
            subprocess.run(["git", "-C", tmp, "commit", "-qm", "invalid metadata fixture"], check=True)
            head = subprocess.check_output(["git", "-C", tmp, "rev-parse", "HEAD"], text=True).strip()
            result = self.invoke(["--event", "push", "--repo", tmp, "--base", head, "--head", head])
            self.assertTrue(result["run"])
            self.assertIn("unable to resolve inputs: CalledProcessError", result["reason"])

    def test_event_payloads_supply_the_compared_revisions(self):
        # CI passes no --base/--head: the decision reads the event file.
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args):
                return subprocess.check_output(["git", "-C", tmp, *args], text=True).strip()

            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            (repo / "README.md").write_text("base\n")
            git("add", "README.md")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            source = repo / "crates/opc-egress-fence/src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("\n")
            git("add", "crates")
            git("commit", "-qm", "fence change")
            head = git("rev-parse", "HEAD")
            for event, payload in (
                ("pull_request", {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}),
                ("push", {"before": base, "after": head}),
            ):
                with self.subTest(event=event):
                    result = self.invoke(["--event", event, "--repo", tmp], payload)
                    self.assertTrue(result["run"])
                    self.assertEqual((result["base"], result["head"]), (base, head))
                    self.assertEqual(
                        result["reason"],
                        "explicit qualification input: crates/opc-egress-fence/src/lib.rs",
                    )

    def test_malformed_event_payload_runs(self):
        for event, payload in (
            ("pull_request", {}),
            ("pull_request", {"pull_request": {"base": {}, "head": {"sha": "0" * 40}}}),
            ("push", {"after": "0" * 40}),
        ):
            with self.subTest(event=event, payload=payload):
                result = self.invoke(["--event", event, "--repo", "/missing-checkout"], payload)
                self.assertTrue(result["run"])
                self.assertTrue(result["reason"].startswith("unavailable event data: "),
                                result["reason"])

    def test_pull_request_uses_merge_base_and_push_uses_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args):
                return subprocess.check_output(["git", "-C", tmp, *args], text=True).strip()

            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")

            def commit(name):
                (repo / name).write_text(name)
                git("add", name)
                git("commit", "-qm", name)
                return git("rev-parse", "HEAD")

            ancestor = commit("shared")
            base = commit("main-only")
            git("checkout", "-q", "--detach", ancestor)
            head = commit("pr-only")
            self.assertEqual(CHANGES.comparison_base(repo, "pull_request", base, head), ancestor)
            self.assertEqual(CHANGES.comparison_base(repo, "push", base, head), base)


if __name__ == "__main__":
    unittest.main()

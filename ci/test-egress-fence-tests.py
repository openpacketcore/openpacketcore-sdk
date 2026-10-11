#!/usr/bin/env python3
"""Coverage, profile and required-check regressions for the egress job split."""

import copy
import importlib.util
from pathlib import Path
import re
import unittest


SPEC = importlib.util.spec_from_file_location(
    "egress_fence_tests", Path(__file__).with_name("egress-fence-tests.py"))
assert SPEC is not None and SPEC.loader is not None
FENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FENCE)


def fixture():
    rows = []
    for name in FENCE.SPECIAL:
        integration = name in FENCE.ISOLATED_INTEGRATION
        rows.append({"package": "opc-session-store",
                     "target": "consensus_openraft" if integration else "opc_session_store",
                     "kind": ["test"] if integration else ["lib"],
                     "name": name, "ignored": False, "shard": FENCE.owner(name)})
    for number in range(300):
        name = f"module::ordinary_{number}"
        rows.append({"package": "opc-session-store", "target": "opc_session_store",
                     "kind": ["lib"], "name": name, "ignored": number % 11 == 0,
                     "shard": FENCE.owner(name)})
    # A duplicate name in a different harness is valid. Both must use the
    # same shard because Cargo passes the harness exclusions to every binary.
    row = dict(rows[-1], package="opc-runtime", target="opc_runtime")
    rows.append(row)
    # A sibling of an isolated name must not be swallowed by a prefix skip.
    name = FENCE.OPTIMIZED_LIB[0] + "_new_sibling"
    rows.append(dict(rows[-1], name=name, shard=FENCE.owner(name), ignored=False))
    return rows


def skips(command):
    argv = command["argv"]
    return {argv[i + 1] for i, value in enumerate(argv) if value == "--skip"}


class PartitionTests(unittest.TestCase):
    def test_every_old_harness_test_runs_on_exactly_one_shard(self):
        rows = fixture()
        plans = {shard: FENCE.plans(rows, shard) for shard in FENCE.SHARDS}
        for row in rows:
            with self.subTest(name=row["name"], target=row["target"]):
                ordinary = [i for i in FENCE.ORDINARY_SHARDS if row["name"] not in skips(plans[i][0])]
                isolated = [i for i, plan in plans.items()
                            if any(c["name"] == row["name"] for c in plan)]
                self.assertEqual(ordinary + isolated, [row["shard"]])

    def test_new_tests_and_same_prefix_siblings_are_included(self):
        rows = fixture()
        for prefix in [FENCE.OPTIMIZED_LIB[0], "new_module"]:
            name = prefix + "::new_test"
            row = dict(rows[-1], name=name, shard=FENCE.owner(name))
            rows.append(row)
            self.assertNotIn(name, skips(FENCE.plans(rows, row["shard"])[0]))
            for shard in set(FENCE.ORDINARY_SHARDS) - {row["shard"]}:
                self.assertIn(name, skips(FENCE.plans(rows, shard)[0]))

    def test_every_ordinary_shard_keeps_feature_unification_and_exact_skips(self):
        for shard in FENCE.ORDINARY_SHARDS:
            command = FENCE.plans(fixture(), shard)[0]
            argv = command["argv"]
            self.assertEqual(argv[:2 + len(FENCE.SELECTION)], ["cargo", "test", *FENCE.SELECTION])
            self.assertIn("--tests", argv)
            self.assertIn("--test-threads=4", argv)
            self.assertIn("--exact", argv)
            self.assertNotIn("--ignored", argv)
            self.assertEqual(command["env"], {})
            self.assertTrue(set(FENCE.SPECIAL).issubset(skips(command)))

    def test_existing_isolation_and_optimized_profile_are_retained(self):
        commands = [c for shard in FENCE.SHARDS for c in FENCE.plans(fixture(), shard)]
        exact = [c for c in commands if c["name"] in FENCE.SPECIAL]
        self.assertEqual({c["name"] for c in exact}, set(FENCE.SPECIAL))
        self.assertEqual(len(exact), 14)
        self.assertEqual(FENCE.plans(fixture(), FENCE.PROOF_SHARD), exact)
        self.assertTrue(all(FENCE.owner(c["name"]) == FENCE.PROOF_SHARD for c in exact))
        for command in exact:
            argv = command["argv"]
            self.assertEqual(argv[argv.index("-p") + 1], "opc-session-store")
            self.assertEqual(argv.count("-p"), 1)
            self.assertIn("--all-features", argv)
            self.assertEqual(argv[-3:], ["--test-threads=1", "--exact", command["name"]])
            optimized = command["name"] in FENCE.OPTIMIZED_LIB
            self.assertEqual(command["env"], {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"} if optimized else {})
            if command["name"] in FENCE.ISOLATED_INTEGRATION:
                self.assertEqual(argv[argv.index("--test") + 1], "consensus_openraft")
            else:
                self.assertIn("--lib", argv)

    def test_examples_doctests_and_qualification_each_have_one_owner(self):
        all_commands = [c for shard in FENCE.SHARDS for c in FENCE.plans(fixture(), shard)]
        for name in ["examples", "doctests", "qualification-profile"]:
            self.assertEqual(sum(c["name"] == name for c in all_commands), 1)
            self.assertIn(name, {c["name"] for c in FENCE.plans(fixture(), 1)})
        examples = next(c for c in all_commands if c["name"] == "examples")
        self.assertEqual(examples["argv"], ["cargo", "build", *FENCE.SELECTION, "--quiet", "--examples"])
        docs = next(c for c in all_commands if c["name"] == "doctests")
        self.assertIn("--doc", docs["argv"])
        self.assertEqual(skips(docs), set(FENCE.SPECIAL))
        qualification = next(c for c in all_commands if c["name"] == "qualification-profile")
        self.assertEqual(qualification["argv"], [
            "cargo", "test", "--locked", "-p", "opc-session-testkit", "--test",
            "qualification_profile", "--quiet", "--", "--test-threads=1"])

    def test_missing_renamed_ignored_or_ambiguous_isolated_test_fails(self):
        for mutation in ["missing", "renamed", "ignored", "ambiguous", "target", "kind", "package"]:
            rows = fixture()
            if mutation == "missing":
                rows.pop(0)
            elif mutation == "renamed":
                rows[0]["name"] += "_renamed"
            elif mutation == "ignored":
                rows[0]["ignored"] = True
            elif mutation == "ambiguous":
                rows.append(dict(rows[0], target="other"))
            elif mutation == "kind":
                rows[0]["kind"] = ["test"]
            else:
                rows[0][mutation] = "other"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                FENCE.verify(rows)

    def test_missing_duplicate_or_wrongly_assigned_inventory_fails(self):
        rows = fixture()
        for broken in [[], rows + [rows[0]], [dict(r, shard=99) for r in rows]]:
            with self.assertRaises(ValueError):
                FENCE.verify(broken)
        with self.assertRaises(ValueError):
            FENCE.plans(rows, 4)

    def test_libtest_inventory_rejects_unrecognized_and_duplicate_output(self):
        self.assertEqual(FENCE.listing("alpha: test\nbeta: test\n\n2 tests, 0 benchmarks\n"), ["alpha", "beta"])
        self.assertEqual(FENCE.listing("0 tests, 0 benchmarks\n"), [])
        for output in ["alpha: test\nalpha: test\n", "custom harness ran successfully\n", "alpha: benchmark\n"]:
            with self.assertRaises(ValueError):
                FENCE.listing(output)


class RequiredCheckTests(unittest.TestCase):
    def needs(self, result="success", decision="true", qualification="success"):
        return {"changes": {"result": result, "outputs": {"run": decision}},
                **{name: {"result": qualification} for name in FENCE.REQUIRED_JOBS}}

    def test_every_new_job_failure_cancellation_skip_or_missing_result_blocks(self):
        for job in FENCE.REQUIRED_JOBS:
            for result in ["failure", "cancelled", "skipped", None, ""]:
                needs = self.needs()
                needs[job]["result"] = result
                with self.subTest(job=job, result=result), self.assertRaises(ValueError):
                    FENCE.require_jobs(needs)

    def test_only_successful_explicit_skip_accepts_skipped_jobs(self):
        FENCE.require_jobs(self.needs(decision="false", qualification="skipped"))
        for result in ["failure", "cancelled", "skipped", ""]:
            with self.assertRaises(ValueError):
                FENCE.require_jobs(self.needs(result=result, decision="false", qualification="skipped"))
        for decision in [None, "", False, "False", "true"]:
            with self.assertRaises(ValueError):
                FENCE.require_jobs(self.needs(decision=decision, qualification="skipped"))

    def test_failed_or_missing_decision_requires_full_success(self):
        for result in ["success", "failure", "cancelled", "skipped"]:
            for decision in [None, "", "true"]:
                FENCE.require_jobs(self.needs(result=result, decision=decision))
        needs = self.needs()
        del needs["changes"]["outputs"]
        FENCE.require_jobs(needs)

    def test_skip_decision_cannot_mask_a_qualification_failure(self):
        needs = self.needs(decision="false", qualification="skipped")
        needs["oracles"]["result"] = "failure"
        with self.assertRaises(ValueError):
            FENCE.require_jobs(needs)

    def test_aggregate_rejects_a_missing_or_unaccounted_job(self):
        needs = self.needs()
        FENCE.require_jobs(needs)
        for key in needs:
            broken = copy.deepcopy(needs)
            del broken[key]
            with self.assertRaises(ValueError):
                FENCE.require_jobs(broken)
        with self.assertRaises(ValueError):
            FENCE.require_jobs(dict(needs, forgotten={"result": "success"}))


class WorkflowTests(unittest.TestCase):
    def test_cache_targets_match_each_jobs_actual_compilation_directories(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        parts = re.split(r"^  ([a-z][a-z-]+):\n", workflow.split("\njobs:\n", 1)[1],
                         flags=re.MULTILINE)
        jobs = dict(zip(parts[1::2], parts[2::2]))
        for name in FENCE.REQUIRED_JOBS:
            with self.subTest(job=name):
                # rust-cache joins target paths onto each workspace root.
                # Absolute runner.temp paths would be joined incorrectly.
                caches = set()
                for mapping in re.findall(r"workspaces: ([^\n]+)", jobs[name]):
                    workspace, target = mapping.split(" -> ")
                    self.assertFalse(Path(target).is_absolute())
                    caches.add((FENCE.ROOT / workspace / target).resolve())
                builds = {FENCE.ROOT / relative for relative in re.findall(
                    r'export CARGO_TARGET_DIR="\$\{GITHUB_WORKSPACE\}/([^"\n]+)"', jobs[name])}
                self.assertTrue(builds)
                self.assertEqual(caches, builds)
                self.assertTrue(all(p.is_relative_to(FENCE.ROOT) for p in caches))
        self.assertIn("shared-key: egress-fence-tests-${{ matrix.shard }}\n", jobs["host-tests"])
        self.assertIn("shared-key: egress-fence-proofs\n", jobs["host-proofs"])
        for name in ["host-tests", "host-proofs"]:
            self.assertNotIn("shared-key: egress-fence-host\n", jobs[name])

    def test_both_artifact_uploads_allow_reruns_to_replace_existing_artifacts(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        uploads = [step for step in workflow.split("      - name: ")
                   if "uses: actions/upload-artifact@" in step]
        self.assertEqual(len(uploads), 2)
        for step in uploads:
            self.assertIn("          overwrite: true\n", step)

    def test_every_workload_blocks_the_existing_check_under_the_old_condition(self):
        # Keep this dependency-free: actionlint separately parses the YAML.
        # These checks bind the tested aggregate logic to the actual workflow.
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        parts = re.split(r"^  ([a-z][a-z-]+):\n", workflow.split("\njobs:\n", 1)[1],
                         flags=re.MULTILINE)
        jobs = dict(zip(parts[1::2], parts[2::2]))
        self.assertEqual(set(jobs), {"changes", "root-cgroup-egress", *FENCE.REQUIRED_JOBS})
        condition = "if: ${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.run != 'false') }}"
        for name in FENCE.REQUIRED_JOBS:
            with self.subTest(job=name):
                self.assertIn(condition, jobs[name])
                self.assertIn("timeout-minutes: 45\n", jobs[name])
                self.assertRegex(jobs[name], r"needs: (changes|\[changes, sources\])\n")
                self.assertIn("if: always()\n        run: bash ci/egress-fence-cleanup.sh", jobs[name])
        aggregate = jobs["root-cgroup-egress"]
        self.assertIn("name: Root-cgroup egress fence\n", aggregate)
        self.assertIn("if: always()\n", aggregate)
        dependencies = re.search(r"needs: \[([^]]+)\]", aggregate)
        self.assertIsNotNone(dependencies)
        self.assertEqual(set(dependencies[1].split(", ")), {"changes", *FENCE.REQUIRED_JOBS})
        self.assertIn("EGRESS_JOB_RESULTS: ${{ toJSON(needs) }}", aggregate)
        self.assertIn("run: python3 ci/egress-fence-tests.py --check-jobs", aggregate)
        host = jobs["host-tests"]
        self.assertIn("fail-fast: false\n", host)
        self.assertIn("shard: [0, 1, 2]\n", host)
        self.assertIn("run: ci/setup-fsverity-tmp.sh\n", host)
        self.assertIn("--shard '${{ matrix.shard }}'", host)
        proofs = jobs["host-proofs"]
        self.assertIn("run: ci/setup-fsverity-tmp.sh\n", proofs)
        self.assertIn(f"--shard {FENCE.PROOF_SHARD} \\\n", proofs)
        for name in ["oracles", "installer"]:
            self.assertIn("bash ci/egress-fence-kernel.sh", jobs[name])
        self.assertIn("python3 -I ci/test-egress-fence-tests.py", jobs["sources"])


if __name__ == "__main__":
    unittest.main()

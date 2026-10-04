#!/usr/bin/env python3
"""Exercise the workflow's real source-invariant step on offline fixtures."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
HELPER = Path("ci/check-vendored-dtls-source.sh")
STEP = "      - name: Enforce vendored RFC 6083 source invariants"
MESSAGES = (
    "vendored DTLS source must not panic on unreachable paths",
    "the DTLS 1.3 path must not reference RFC 6083",
    "Config must be constructed explicitly, never defaulted",
)


def workflow_command():
    lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
    start = lines.index(STEP) + 1
    for index in range(start, len(lines)):
        line = lines[index]
        if line.startswith("        run: "):
            value = line.removeprefix("        run: ")
            if value != "|":
                return value
            body = []
            for following in lines[index + 1:]:
                if not following.startswith("          "):
                    break
                body.append(following[10:])
            return "\n".join(body)
        if line.startswith("      - name:"):
            break
    raise RuntimeError("source-invariant workflow step has no run command")


class VendoredSourceInvariantTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="dtls-source-guard-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, content in {
            "vendor/dimpl/src/lib.rs": "// explicitly fallible construction\n",
            "vendor/dimpl/src/dtls12.rs": "// Rfc6083 belongs in DTLS 1.2\n",
            "vendor/dimpl/src/dtls13/mod.rs": "// DTLS 1.3\n",
            "vendor/dimpl/tests/config.rs": "let config = Config::new();\n",
            "vendor/dimpl/README.md": "# Audited DTLS\n",
        }.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        # The same tests characterize the original inline step before the
        # checked helper exists, and its workflow invocation after extraction.
        if (ROOT / HELPER).is_file():
            (root / HELPER).parent.mkdir(parents=True)
            shutil.copyfile(ROOT / HELPER, root / HELPER)
        return root

    def run_step(self, root, scanner="real"):
        commands = root / "commands"
        commands.mkdir()
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "behavioral tests require Bash")
        (commands / "bash").symlink_to(bash)
        if scanner == "real":
            rg = shutil.which("rg")
            self.assertIsNotNone(rg, "behavioral tests require ripgrep")
            (commands / "rg").symlink_to(rg)
        elif scanner != "missing":
            stub = commands / "rg"
            stub.write_text(
                "#!/bin/sh\necho 'controlled scan error' >&2\n"
                f"exit {scanner}\n"
            )
            stub.chmod(0o755)
        return subprocess.run(
            [bash, "-e", "-c", workflow_command()], cwd=root,
            env={"PATH": str(commands), "LANG": "C", "LC_ALL": "C"},
            capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_clean_fixture_passes_with_real_rg(self):
        result = self.run_step(self.fixture())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_panic_macro_is_rejected(self):
        for macro in ("unreachable!()", "unimplemented!()", "todo!()"):
            with self.subTest(macro=macro):
                root = self.fixture()
                (root / "vendor/dimpl/src/lib.rs").write_text(macro + "\n")
                result = self.run_step(root)
                self.assert_rejected(result)
                self.assertIn(MESSAGES[0], result.stdout + result.stderr)
                self.assertIn(":1:", result.stdout)

    def test_each_dtls13_reference_spelling_is_rejected(self):
        for spelling in ("Rfc6083", "rfc6083"):
            with self.subTest(spelling=spelling):
                root = self.fixture()
                (root / "vendor/dimpl/src/dtls13/mod.rs").write_text(spelling)
                result = self.run_step(root)
                self.assert_rejected(result)
                self.assertIn(MESSAGES[1], result.stdout + result.stderr)

    def test_each_config_default_is_rejected_in_every_searched_path(self):
        for name in ("src/lib.rs", "tests/config.rs", "README.md"):
            for source in ("impl Default for Config", "Config::default()"):
                with self.subTest(path=name, source=source):
                    root = self.fixture()
                    (root / "vendor/dimpl" / name).write_text(source)
                    result = self.run_step(root)
                    self.assert_rejected(result)
                    self.assertIn(MESSAGES[2], result.stdout + result.stderr)

    def test_all_independent_violations_are_reported(self):
        root = self.fixture()
        (root / "vendor/dimpl/src/lib.rs").write_text("unreachable!()")
        (root / "vendor/dimpl/src/dtls13/mod.rs").write_text("Rfc6083")
        (root / "vendor/dimpl/README.md").write_text("Config::default()")
        result = self.run_step(root)
        self.assert_rejected(result)
        for message in MESSAGES:
            self.assertIn(message, result.stdout + result.stderr)

    def test_missing_rg_fails_closed(self):
        result = self.run_step(self.fixture(), scanner="missing")
        self.assert_rejected(result)
        self.assertIn("rg", result.stderr)

    def test_scan_errors_fail_closed_and_all_checks_run(self):
        for status in (2, 3, 126, 127, 137):
            with self.subTest(status=status):
                result = self.run_step(self.fixture(), scanner=status)
                self.assert_rejected(result)
                self.assertEqual(result.stderr.count("controlled scan error"), 3)

    def test_missing_inputs_fail_closed(self):
        for name in ("src", "src/dtls13", "tests", "README.md"):
            with self.subTest(path=name):
                root = self.fixture()
                missing = root / "vendor/dimpl" / name
                if missing.is_dir():
                    shutil.rmtree(missing)
                else:
                    missing.unlink()
                result = self.run_step(root)
                self.assert_rejected(result)
                self.assertIn("No such file or directory", result.stderr)

    def test_real_rg_read_error_fails_closed(self):
        root = self.fixture()
        unreadable = root / "vendor/dimpl/README.md"
        unreadable.unlink()
        unreadable.symlink_to(unreadable.name)
        result = self.run_step(root)
        self.assert_rejected(result)
        self.assertIn("vendor/dimpl/README.md", result.stderr)
        self.assertIn("error", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

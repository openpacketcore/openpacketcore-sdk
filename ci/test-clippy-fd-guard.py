#!/usr/bin/env python3
"""Compile-check borrowed-descriptor lint rules; requires a Unix host and Clippy."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_LOCK = ROOT / "ci/fixtures/clippy-fd-guard/Cargo.lock"
PRELUDE = "use std::{fs::File, io, os::fd::{AsFd, BorrowedFd}};\n"


class BorrowedDescriptorGuardTests(unittest.TestCase):
    def compile(self, source, *, configured=True, dependencies=""):
        with tempfile.TemporaryDirectory(prefix="clippy-fd-guard-") as directory:
            fixture = Path(directory)
            (fixture / "src").mkdir()
            (fixture / "Cargo.toml").write_text(
                '[package]\nname = "borrowed-fd-guard-fixture"\n'
                'version = "0.0.0"\nedition = "2021"\n[workspace]\n'
                '[dependencies]\n' + dependencies
            )
            (fixture / "src/lib.rs").write_text(source)
            (fixture / "clippy.toml").write_text(
                (ROOT / "clippy.toml").read_text() if configured else ""
            )
            if dependencies:
                (fixture / "Cargo.lock").write_bytes(FIXTURE_LOCK.read_bytes())
            result = subprocess.run(
                ["cargo", "clippy", "--offline", *(["--locked"] if dependencies else []),
                 "--message-format=json", "--", "-D", "warnings"],
                cwd=fixture, text=True, capture_output=True,
                env=dict(os.environ, CLIPPY_CONF_DIR=str(fixture),
                         CARGO_TARGET_DIR=str(ROOT / "target/clippy-fd-guard")),
            )
        messages = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        diagnostics = [message["message"] for message in messages
                       if message.get("reason") == "compiler-message"]
        return result, [message for message in diagnostics if message["level"] == "error"]

    def test_unconfigured_duplication_compiles(self):
        source = PRELUDE + """
pub fn duplicate(pin: &impl AsFd) -> io::Result<File> {
    Ok(File::from(BorrowedFd::try_clone_to_owned(&pin.as_fd())?))
}
"""
        result, errors = self.compile(source, configured=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(errors, [])

    def test_method_and_associated_duplication_are_rejected(self):
        for expression in ("borrowed.try_clone_to_owned()", "BorrowedFd::try_clone_to_owned(&borrowed)"):
            with self.subTest(expression=expression):
                source = PRELUDE + f"""
pub fn duplicate(pin: &impl AsFd) -> io::Result<File> {{
    let borrowed: BorrowedFd<'_> = pin.as_fd();
    Ok(File::from({expression}?))
}}
"""
                result, errors = self.compile(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([error["code"]["code"] for error in errors],
                                 ["clippy::disallowed_methods"], result.stdout + result.stderr)

    def test_borrow_and_local_directory_exception_compile(self):
        source = PRELUDE + """
pub fn borrow(pin: &impl AsFd) -> BorrowedFd<'_> {
    pin.as_fd()
}
pub fn retain_directory(directory: &File) -> io::Result<File> {
    #[expect(clippy::disallowed_methods, reason = "this descriptor is a directory")]
    let owned = directory.as_fd().try_clone_to_owned()?;
    Ok(File::from(owned))
}
"""
        result, errors = self.compile(source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(errors, [])

    def test_rustix_duplication_is_rejected(self):
        packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        identity = lambda package: tuple(package.get(key) for key in
                                         ("name", "version", "source", "checksum"))
        workspace_identities = {identity(package) for package in packages}
        for package in tomllib.loads(FIXTURE_LOCK.read_text())["package"]:
            if "source" in package:
                with self.subTest(package=package["name"]):
                    self.assertIn(identity(package), workspace_identities)
        version = next(package["version"] for package in packages if package["name"] == "rustix")
        dependencies = f'rustix = "={version}"\n'
        source = """
use std::{io, os::fd::{AsFd, OwnedFd}};
pub fn duplicate(pin: &impl AsFd) -> io::Result<OwnedFd> {
    Ok(rustix::io::fcntl_dupfd_cloexec(pin, 0)?)
}
"""
        result, errors = self.compile(source, configured=False, dependencies=dependencies)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(errors, [])
        result, errors = self.compile(source, dependencies=dependencies)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([error["code"]["code"] for error in errors],
                         ["clippy::disallowed_methods"], result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

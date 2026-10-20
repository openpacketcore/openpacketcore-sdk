#!/usr/bin/env python3
"""Compile-check borrowed-descriptor lint rules; requires a Unix host and Clippy."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
PRELUDE = "use std::{fs::File, io, os::fd::{AsFd, BorrowedFd}};\n"


class BorrowedDescriptorGuardTests(unittest.TestCase):
    def compile(self, source, *, configured=True):
        with tempfile.TemporaryDirectory(prefix="clippy-fd-guard-") as directory:
            fixture = Path(directory)
            (fixture / "src").mkdir()
            (fixture / "Cargo.toml").write_text(
                '[package]\nname = "borrowed-fd-guard-fixture"\n'
                'version = "0.0.0"\nedition = "2021"\n[workspace]\n'
            )
            (fixture / "src/lib.rs").write_text(source)
            (fixture / "clippy.toml").write_text(
                (ROOT / "clippy.toml").read_text() if configured else ""
            )
            result = subprocess.run(
                ["cargo", "clippy", "--offline", "--message-format=json", "--", "-D", "warnings"],
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


if __name__ == "__main__":
    unittest.main()

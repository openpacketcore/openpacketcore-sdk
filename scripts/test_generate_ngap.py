#!/usr/bin/env python3
"""Regression tests for scripts/generate-ngap.py."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-ngap.py")


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_ngap", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class GenerateNgapGuardsTests(unittest.TestCase):
    def setUp(self):
        self.generator = load_generator()
        self.name = self.generator.ASN_FILES[0]

    def test_asn_hash_mismatch_aborts(self):
        with self.assertRaises(SystemExit):
            self.generator.verify_asn(self.name, b"tampered\n")

    def test_missing_expected_hash_aborts(self):
        original_hash = self.generator.EXPECTED_ASN_SHA256.pop(self.name)
        try:
            with self.assertRaises(SystemExit):
                self.generator.verify_asn(self.name, b"anything\n")
        finally:
            self.generator.EXPECTED_ASN_SHA256[self.name] = original_hash

    def test_matching_asn_hash_passes(self):
        data = b"NGAP DEFINITIONS ::= BEGIN\nEND\n"
        original_hash = self.generator.EXPECTED_ASN_SHA256[self.name]
        self.generator.EXPECTED_ASN_SHA256[self.name] = hashlib.sha256(data).hexdigest()
        try:
            self.generator.verify_asn(self.name, data)
        finally:
            self.generator.EXPECTED_ASN_SHA256[self.name] = original_hash

    def test_generated_patch_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "generated.rs"
            source.write_text("pub mod generated {}\n")

            with self.assertRaises(SystemExit):
                self.generator.patch_generated(source)

    def test_generated_patch_applies_required_imports(self):
        raw = "\n".join(
            [
                "use super::ngap_common_data_types::{Criticality, Presence, ProtocolIEID};",
                "use super::ngap_common_data_types::{",
                "        Criticality, ProcedureCode, ProtocolIEID, TriggeringMessage,",
                "    };",
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "generated.rs"
            source.write_text(raw)

            patched = self.generator.patch_generated(source)

        self.assertIn("PrivateIEID", patched)
        self.assertIn("ProtocolExtensionID", patched)
        self.assertIn("#![allow(clippy::all, missing_docs)]", patched)


if __name__ == "__main__":
    unittest.main()

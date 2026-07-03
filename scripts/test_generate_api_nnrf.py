#!/usr/bin/env python3
"""Regression tests for scripts/generate-api-nnrf.py."""

import hashlib
import importlib.util
import tempfile
import unittest
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-api-nnrf.py")


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_api_nnrf", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self.data


class ApiNnrfCodegenHashTests(unittest.TestCase):
    def setUp(self):
        self.generator = load_generator()
        self.name = self.generator.FILES[0]

    def test_cache_hit_hash_mismatch_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            (cache_dir / self.name).write_bytes(b"tampered: true\n")

            with self.assertRaises(SystemExit):
                self.generator.fetch_yaml(self.name, cache_dir)

    def test_download_hash_mismatch_does_not_populate_cache(self):
        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = lambda *args, **kwargs: FakeResponse(b"tampered: true\n")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cache_dir = Path(tmp)
                with self.assertRaises(SystemExit):
                    self.generator.fetch_yaml(self.name, cache_dir)
                self.assertFalse((cache_dir / self.name).exists())
        finally:
            urllib.request.urlopen = original_urlopen

    def test_matching_cache_hash_parses(self):
        data = b"ok: true\n"
        original_hash = self.generator.EXPECTED_HASHES[self.name]
        self.generator.EXPECTED_HASHES[self.name] = hashlib.sha256(data).hexdigest()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cache_dir = Path(tmp)
                (cache_dir / self.name).write_bytes(data)

                self.assertEqual(self.generator.fetch_yaml(self.name, cache_dir), {"ok": True})
        finally:
            self.generator.EXPECTED_HASHES[self.name] = original_hash

    def test_missing_expected_hash_aborts(self):
        data = b"ok: true\n"
        original_hash = self.generator.EXPECTED_HASHES.pop(self.name)
        try:
            with self.assertRaises(SystemExit):
                self.generator.parse_verified_yaml(self.name, data)
        finally:
            self.generator.EXPECTED_HASHES[self.name] = original_hash


if __name__ == "__main__":
    unittest.main()

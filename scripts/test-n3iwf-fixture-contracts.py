#!/usr/bin/env python3
"""Independent regression tests for the fixture writer and wire claims."""

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import n3iwf_fixture_oracles as oracle
import n3iwf_key_reference as key_reference

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/opc-n3iwf-fixtures/fixtures"


def wire(subset, name):
    return bytes.fromhex((FIXTURES / subset / "wire" / (name + ".hex")).read_text())


class WireRegressions(unittest.TestCase):
    def test_n2_default_service_port_is_38412_in_both_metadata_orders(self):
        # IANA ng-control/sctp: 38412 decimal is 0x960c, independently of writer.
        for name, port_offset, ppid_offset, expected_ppid in (
            ("positive-ppid60-port", 4, 0, 60),
            ("unknown-ppid66", 4, 0, 66),
            ("ordering-port-before-ppid", 0, 2, 60),
            ("duplicate-association-tuple", 4, 0, 60),
        ):
            data = wire("n2-sctp", name)
            for offset in range(0, len(data), 6):
                with self.subTest(case=name, tuple_index=offset // 6):
                    self.assertEqual(
                        int.from_bytes(
                            data[offset + port_offset : offset + port_offset + 2], "big"
                        ),
                        38412,
                    )
                    self.assertEqual(
                        int.from_bytes(
                            data[offset + ppid_offset : offset + ppid_offset + 4], "big"
                        ),
                        expected_ppid,
                    )

    def test_key_reference_rejects_non_octet_known_answers(self):
        reference = key_reference.read_json(key_reference.REFERENCE)
        for value in (False, 0.0, "0", -1, 256):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                changed = json.loads(json.dumps(reference))
                # False and 0.0 compare equal to the expected zero, but neither
                # is a JSON integer octet. Reject before converting or comparing.
                changed["expected_octets"]["auth_initiator"][1] = value
                source = Path(directory) / "reference.json"
                source.write_text(json.dumps(changed))
                with mock.patch.object(
                    key_reference, "REFERENCE", source
                ), mock.patch.object(sys, "argv", ["reference"]), mock.patch(
                    "sys.stderr", new=io.StringIO()
                ) as errors:
                    self.assertEqual(key_reference.main(), 1)
                    self.assertIn("answer-octet", errors.getvalue())

    def test_key_reference_rejects_undeclared_negative_input_recipes(self):
        reference = key_reference.read_json(key_reference.REFERENCE)
        for field in ("dh_shared", "initiator_nonce", "identity_payload_body"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                changed = json.loads(json.dumps(reference))
                # A negative AUTH result alone cannot establish synthetic provenance.
                changed["cases"][1]["inputs"][field] = "77" * 32
                source = root / "reference.json"
                source.write_text(json.dumps(changed))
                fixture_root = root / "fixtures"
                shutil.copytree(
                    FIXTURES / "protocol-key", fixture_root / "protocol-key"
                )
                manifest_path = (
                    fixture_root
                    / "protocol-key"
                    / (changed["cases"][1]["name"] + ".json")
                )
                manifest = json.loads(manifest_path.read_text())
                manifest["context"]["inputs"] = changed["cases"][1]["inputs"]
                manifest_path.write_text(json.dumps(manifest))
                with mock.patch.object(
                    key_reference, "REFERENCE", source
                ), mock.patch.object(
                    key_reference, "FIXTURES", fixture_root
                ), mock.patch.object(
                    sys, "argv", ["reference"]
                ), mock.patch(
                    "sys.stderr", new=io.StringIO()
                ) as errors:
                    self.assertEqual(key_reference.main(), 1)
                    self.assertIn("synthetic-case-recipe", errors.getvalue())

    def test_key_known_answer_rejects_stale_claims_and_custody_promotion(self):
        path = FIXTURES / "protocol-key/auth-initiator-known-answer.json"
        original = json.loads(path.read_text())
        data = wire("protocol-key", "auth-initiator-known-answer")
        for field in ("assertions", "custody", "encoding", "outcome"):
            with self.subTest(field=field):
                manifest = json.loads(json.dumps(original))
                if field == "assertions":
                    manifest["semantic_assertions"][0] = "AUTH_method=3"
                elif field == "custody":
                    manifest["context"]["sdk_custody_validation"] = True
                elif field == "encoding":
                    manifest["encoding"] = "scenario-label"
                else:
                    manifest["expected_outcome"] = "constructed"
                with self.assertRaises(key_reference.Invalid):
                    key_reference.validate(manifest, data)

    def test_reference_download_identifies_the_client_and_bounds_the_read(self):
        spec = importlib.util.spec_from_file_location(
            "reference_gate", ROOT / "scripts/check-n3iwf-ngap-reference.py"
        )
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.url = gate.SPEC_URL
        response.read.return_value = b"synthetic-publication"
        with mock.patch.object(
            gate.urllib.request, "urlopen", return_value=response
        ) as fetch:
            self.assertEqual(gate.read_spec(None), b"synthetic-publication")
            request = fetch.call_args.args[0]
            self.assertIsInstance(request, gate.urllib.request.Request)
            self.assertEqual(request.full_url, gate.SPEC_URL)
            self.assertEqual(
                request.get_header("User-agent"), "OpenPacketCore-SDK-reference/1.0"
            )
            self.assertEqual(fetch.call_args.kwargs, {"timeout": 30})
            response.read.assert_called_once_with(gate.MAX_SPEC_BYTES + 1)
            response.url = "http://example.invalid/spec.pdf"
            response.read.reset_mock()
            with self.assertRaisesRegex(gate.Invalid, "^spec-transport$"):
                gate.read_spec(None)
            response.read.assert_not_called()

    def test_ngap_release18_presence_and_ie_set(self):
        matrix = json.loads(
            (FIXTURES / "ngap/matrices/ng-setup-request.json").read_text()
        )
        rows = {row["id"]: row for row in matrix["ies"]}
        self.assertEqual(set(rows), {27, 82, 102, 21, 147, 204, 273})
        self.assertEqual(rows[27]["presence"], "mandatory")
        self.assertEqual(rows[82]["presence"], "optional")

    def test_gre_header_shaped_payload_is_opaque(self):
        manifest = json.loads(
            (FIXTURES / "gre-qfi/duplicate-key-header.json").read_text()
        )
        self.assertEqual(manifest["expected_outcome"], "receive")

    def test_nas_overflow_exceeds_inclusive_caller_bound(self):
        data = wire("nas-tcp", "bounded-length-overflow")
        self.assertGreater(int.from_bytes(data[:2], "big"), 256)

    def test_ike_overflow_targets_spi_size(self):
        data = wire("nwu-ike", "bounded-spi-size-overflow")
        self.assertEqual(data[4], 0)
        self.assertEqual(data[5], 255)

    def test_ike_notify_chains_do_not_terminate_early(self):
        for name in (
            "create-child-sa",
            "modify-child-sa",
            "duplicate-nas-ip4",
            "ordering-tcp-before-ip4",
        ):
            with self.subTest(case=name):
                data = wire("nwu-ike", name)
                while data:
                    length = int.from_bytes(data[2:4], "big")
                    self.assertGreaterEqual(length, 8)
                    self.assertLessEqual(length, len(data))
                    self.assertEqual(data[0], 41 if length < len(data) else 0)
                    data = data[length:]

    def test_end_marker_length_and_extension_chain(self):
        data = wire("n3-gtpu", "ordering-end-marker-psc-first")
        self.assertEqual(int.from_bytes(data[2:4], "big"), len(data) - 8)
        kind, pos = data[11], 12
        while kind:
            size = data[pos] * 4
            self.assertGreaterEqual(size, 4)
            self.assertLessEqual(pos + size, len(data))
            kind = data[pos + size - 1]
            pos += size
        self.assertEqual(pos, len(data))

    def test_positive_sctp_data_contains_user_data(self):
        for subset, name in (
            ("n2-sctp", "positive-data-chunk"),
            ("n2-dtls", "reliable-delivery-data"),
        ):
            with self.subTest(subset=subset):
                data = wire(subset, name)
                length = int.from_bytes(data[2:4], "big")
                self.assertGreater(
                    length, 16, "RFC 4960 DATA cannot have empty user data"
                )
                self.assertEqual(len(data), (length + 3) & ~3)

    def test_positive_dtls_handshake_is_a_valid_body(self):
        data = wire("n2-dtls", "positive-handshake-header")
        self.assertEqual(len(data), 13 + int.from_bytes(data[11:13], "big"))
        message = data[13:]
        self.assertEqual(len(message), 12 + int.from_bytes(message[9:12], "big"))
        if message[0] == 1:
            self.assertGreaterEqual(
                len(message[12:]), 42, "ClientHello requires version/random/vectors"
            )
        else:
            self.assertIn(
                message[0], (0, 14), "only empty HelloRequest/ServerHelloDone are valid"
            )

    def test_dtls_overflow_targets_record_length(self):
        data = wire("n2-dtls", "bounded-record-overflow")
        self.assertGreaterEqual(len(data), 13)
        self.assertEqual(int.from_bytes(data[11:13], "big"), 65535)

    def test_synthetic_ngap_does_not_publish_operator_plmns(self):
        for path in (FIXTURES / "ngap/wire").glob("*.hex"):
            data = bytes.fromhex(path.read_text())
            self.assertNotIn(
                bytes.fromhex("02 f8 98"), data, "fixture uses operator PLMN"
            )
            self.assertNotIn(
                bytes.fromhex("02 f8 39"), data, "fixture uses operator PLMN"
            )


class SemanticMutations(unittest.TestCase):
    def test_n2_named_fields_cannot_diverge_from_wire_or_disappear(self):
        for name, fields in (
            ("positive-ppid60-port", ("ppid", "port")),
            ("unknown-ppid66", ("ppid", "port")),
            ("ordering-port-before-ppid", ("ppid", "port")),
            ("duplicate-association-tuple", ("ppid", "port")),
            ("positive-data-chunk", ("ppid", "user_data_len", "chunk")),
        ):
            path = FIXTURES / "n2-sctp" / (name + ".json")
            original = json.loads(path.read_text())
            data = wire("n2-sctp", name)
            for field in fields:
                for remove in (False, True):
                    with self.subTest(case=name, field=field, remove=remove):
                        changed = json.loads(json.dumps(original))
                        changed["semantic_assertions"] = [
                            claim
                            for claim in changed["semantic_assertions"]
                            if not claim.startswith(field + "=")
                        ]
                        if not remove:
                            changed["semantic_assertions"].append(field + "=999")
                        with self.assertRaisesRegex(oracle.Invalid, "^field-claim$"):
                            oracle.validate(changed, data)

    def test_n2_every_tuple_claim_is_checked_even_when_disposition_stays_duplicate(
        self,
    ):
        manifest = json.loads(
            (FIXTURES / "n2-sctp/duplicate-association-tuple.json").read_text()
        )
        manifest["semantic_assertions"] = [
            "ppid=60",
            "port=38412",
            "tuple_count=3",
            "duplicate_tuple=true",
        ]
        good = (60).to_bytes(4, "big") + (38412).to_bytes(2, "big")
        altered = (60).to_bytes(4, "big") + (38413).to_bytes(2, "big")
        data = good + altered + good
        manifest["wire"]["digest_sha256"] = hashlib.sha256(data).hexdigest()
        self.assertEqual(oracle.observe(manifest, data), ("caller-policy", None))
        with self.assertRaisesRegex(oracle.Invalid, "^field-claim$"):
            oracle.validate(manifest, data)

    def test_n2_contradictory_repeated_claim_cannot_hide_behind_the_last_value(self):
        original = json.loads(
            (FIXTURES / "n2-sctp/positive-ppid60-port.json").read_text()
        )
        data = wire("n2-sctp", "positive-ppid60-port")
        for field in ("port", "ppid"):
            changed = json.loads(json.dumps(original))
            changed["semantic_assertions"].insert(0, field + "=999")
            with self.subTest(field=field), self.assertRaisesRegex(
                oracle.Invalid, "^field-claim$"
            ):
                oracle.validate(changed, data)

    def test_n2_port_mutation_with_refreshed_digest_fails_semantic_gate(self):
        original = json.loads(
            (FIXTURES / "n2-sctp/positive-ppid60-port.json").read_text()
        )
        for port in (38411, 38413, 38428):
            changed = json.loads(json.dumps(original))
            data = bytearray(wire("n2-sctp", "positive-ppid60-port"))
            data[4:6] = port.to_bytes(2, "big")
            changed["wire"]["digest_sha256"] = hashlib.sha256(data).hexdigest()
            with self.subTest(candidate=port), self.assertRaisesRegex(
                oracle.Invalid, "^field-claim$"
            ):
                oracle.validate(changed, data)

    def fixture(self, subset, name):
        return json.loads((FIXTURES / subset / (name + ".json")).read_text()), wire(
            subset, name
        )

    def test_positive_wire_mutations_change_the_verdict_without_a_digest_gate(self):
        cases = [
            ("eap5g", "positive-start", 12, 127, "message-id"),
            ("nwu-ike", "create-child-sa", 0, 0, "trailing-payload"),
            ("gre-qfi", "positive-uplink", 0, 0, "flags"),
            ("nas-tcp", "positive-envelope", 1, 0, "length-bound"),
            ("n2-sctp", "positive-data-chunk", 3, 16, "data-header"),
            ("n2-dtls", "positive-handshake-header", 13, 1, "handshake-body"),
            ("xfrm-roster", "positive-single-pair", 0, 0, "version"),
        ]
        for subset, name, offset, value, reason in cases:
            with self.subTest(subset=subset):
                manifest, data = self.fixture(subset, name)
                changed = bytearray(data)
                changed[offset] = value
                manifest["wire"]["digest_sha256"] = hashlib.sha256(changed).hexdigest()
                self.assertEqual(
                    oracle.observe(manifest, bytes(changed)), ("reject", reason)
                )
                with self.assertRaises(oracle.Invalid):
                    oracle.validate(manifest, bytes(changed))

    def test_lifecycle_preconditions_are_executable(self):
        cases = [
            (
                "protocol-key",
                "positive-generation-1",
                "requested_generation",
                2,
                "generation",
            ),
            (
                "protocol-key",
                "positive-generation-1",
                "actions",
                ["bind", "consume", "consume"],
                "reuse",
            ),
            (
                "protocol-key",
                "positive-generation-1",
                "actions",
                ["bind", "cancel", "consume"],
                "cancelled",
            ),
            ("n2-dtls", "sctp-auth-length", "exporter_length", 63, "exporter-length"),
            (
                "n2-dtls",
                "positive-identity-label",
                "identity_verified",
                False,
                "identity",
            ),
            (
                "n2-dtls",
                "rekey-generation-2",
                "switch_auth_key_before_finished",
                False,
                "key-order",
            ),
            (
                "n2-dtls",
                "rotation-generation-3",
                "retire_old_key_after_ack",
                False,
                "key-order",
            ),
            (
                "n2-dtls",
                "reliable-delivery-data",
                "delivery_policy",
                "partially-reliable",
                "delivery-policy",
            ),
            (
                "xfrm-roster",
                "relocation",
                "relocation_authorized",
                False,
                "relocation-authority",
            ),
            (
                "xfrm-roster",
                "positive-single-pair",
                "old_pair_retained",
                True,
                "overlap",
            ),
        ]
        for subset, name, field, value, reason in cases:
            with self.subTest(case=name, field=field):
                manifest, data = self.fixture(subset, name)
                manifest["context"][field] = value
                self.assertEqual(oracle.observe(manifest, data), ("reject", reason))

    def test_receive_boundaries_and_opaque_payloads(self):
        manifest, _ = self.fixture("nas-tcp", "positive-envelope")
        for length in (1, 256):
            self.assertEqual(
                oracle.observe(manifest, length.to_bytes(2, "big") + bytes(length)),
                ("accept", None),
            )
        self.assertEqual(
            oracle.observe(manifest, b"\x01\x01"), ("reject", "length-bound")
        )
        manifest, data = self.fixture("n2-dtls", "rekey-generation-2")
        manifest["context"].update(old_auth_key_id=65535, new_auth_key_id=1)
        self.assertEqual(oracle.observe(manifest, data), ("accept", None))
        manifest, data = self.fixture("xfrm-roster", "positive-single-pair")
        # Equal numeric SPIs in opposite receiver namespaces are permitted.
        self.assertEqual(
            oracle.observe(manifest, data[:8] + data[4:8]), ("accept", None)
        )

    def test_valid_but_different_wire_cannot_keep_stale_field_claims(self):
        for subset, name, offset, value in [
            ("gre-qfi", "positive-uplink", 4, 10),
            ("eap5g", "positive-start", 0, 2),
            ("nwu-ike", "positive-5g-qos-info", 11, 10),
        ]:
            with self.subTest(subset=subset):
                manifest, data = self.fixture(subset, name)
                changed = bytearray(data)
                changed[offset] = value
                self.assertEqual(oracle.observe(manifest, changed), ("accept", None))
                with self.assertRaises(oracle.Invalid):
                    oracle.validate(manifest, changed)


class PublicationRegressions(unittest.TestCase):
    def test_stamp_requires_matching_content_and_real_history(self):
        spec = importlib.util.spec_from_file_location(
            "gate", ROOT / "scripts/check-n3iwf-fixture-contracts.py"
        )
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory() as directory:
            gate.ROOT = Path(directory)
            gate.FIXTURE_ROOT = gate.ROOT / "crates/opc-n3iwf-fixtures/fixtures"
            gate.FIXTURE_ROOT.mkdir(parents=True)

            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=gate.ROOT, stderr=subprocess.DEVNULL, text=True
                ).strip()

            git("init", "--quiet")
            git("config", "user.name", "Fixture Test")
            git("config", "user.email", "fixture@example.invalid")
            data = gate.FIXTURE_ROOT / "case.hex"
            data.write_text("00\n")
            stamp = gate.FIXTURE_ROOT / "PUBLIC_SDK.json"
            stamp.write_text("{}\n")
            git("add", ".")
            git(
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "test: synthetic content",
            )
            head = git("rev-parse", "HEAD")
            prefix = "crates/opc-n3iwf-fixtures/fixtures"
            publication = {
                "base": head,
                "head": head,
                "tree": git("rev-parse", head + ":" + prefix),
                "tree_path": prefix,
            }
            stamp.write_text(json.dumps(publication))
            self.assertTrue(gate.publication_matches_content())
            data.write_text("ff\n")
            self.assertFalse(gate.publication_matches_content())
            data.write_text("00\n")
            extra = gate.FIXTURE_ROOT / "extra"
            extra.mkdir()
            (extra / "PUBLIC_SDK.json").write_text("{}")
            self.assertFalse(gate.publication_matches_content())
            shutil.rmtree(extra)
            publication["tree"] = "0" * 40
            stamp.write_text(json.dumps(publication))
            self.assertFalse(gate.publication_matches_content())
            publication["head"] = "0" * 40
            stamp.write_text(json.dumps(publication))
            with self.assertRaises(subprocess.CalledProcessError):
                gate.publication_matches_content()


class GeneratorRegressions(unittest.TestCase):
    def test_key_reference_rejects_unsafe_paths_duplicates_and_stale_digests(self):
        spec = importlib.util.spec_from_file_location(
            "writer", ROOT / "scripts/generate-n3iwf-fixtures.py"
        )
        writer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(writer)
        reference_path = Path("crates/opc-n3iwf-fixtures/oracles/ike-auth-sha256.json")
        original = (ROOT / reference_path).read_text()
        for mutation in ("escape", "duplicate", "digest", "oversize", "symlink"):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reference = json.loads(original)
                if mutation == "escape":
                    reference["cases"][0]["name"] = "../../escaped"
                elif mutation == "duplicate":
                    reference["cases"][1]["name"] = reference["cases"][0]["name"]
                elif mutation == "digest":
                    reference["cases"][0]["wire_sha256"] = "0" * 64
                source = root / reference_path
                source.parent.mkdir(parents=True)
                source.write_text(json.dumps(reference))
                if mutation == "oversize":
                    source.write_bytes(b" " * (256 * 1024 + 1))
                elif mutation == "symlink":
                    source.unlink()
                    source.symlink_to(ROOT / reference_path)
                writer.ROOT = root
                with mock.patch.object(writer, "dump_manifest") as publish:
                    with self.assertRaises(ValueError):
                        writer.protocol_key_known_answers(root / "output")
                    publish.assert_not_called()

    def test_ngap_reference_cannot_escape_or_overwrite_an_output(self):
        spec = importlib.util.spec_from_file_location(
            "writer", ROOT / "scripts/generate-n3iwf-fixtures.py"
        )
        writer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(writer)
        reference_path = Path(
            "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
        )
        original = (ROOT / reference_path).read_text()
        for mutation in ("escape", "duplicate", "digest"):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reference = json.loads(original)
                if mutation == "escape":
                    reference["cases"][0]["name"] = "../../escaped"
                elif mutation == "duplicate":
                    reference["cases"][1]["name"] = reference["cases"][0]["name"]
                else:
                    reference["cases"][0]["wire_sha256"] = "0" * 64
                (root / reference_path).parent.mkdir(parents=True)
                (root / reference_path).write_text(json.dumps(reference))
                writer.ROOT = root
                destination = root / "output/ngap"
                destination.mkdir(parents=True)
                # Keep the test safe even when the path guard is removed.
                with mock.patch.object(writer, "dump_manifest") as publish:
                    with self.assertRaises(ValueError):
                        writer.ngap_complete_messages(destination)
                    publish.assert_not_called()

    def test_check_is_read_only_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "scripts", root / "scripts")
            fixtures = root / "crates/opc-n3iwf-fixtures/fixtures"
            shutil.copytree(ROOT / "crates/opc-n3iwf-fixtures", fixtures.parent)
            changed = fixtures / "eap5g/wire/positive-start.hex"
            changed.write_text("ff\n")
            before = {
                p.relative_to(fixtures): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in fixtures.rglob("*")
                if p.is_file()
            }
            results = [
                subprocess.run(
                    [
                        sys.executable,
                        str(root / "scripts/generate-n3iwf-fixtures.py"),
                        mode,
                    ],
                    capture_output=True,
                    check=False,
                )
                for mode in ("--check", "--self-test")
            ]
            after = {
                p.relative_to(fixtures): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in fixtures.rglob("*")
                if p.is_file()
            }
            self.assertTrue(
                all(result.returncode != 0 for result in results),
                "read-only gate repaired drift instead of rejecting it",
            )
            self.assertEqual(before, after, "check mutated the input tree")


if __name__ == "__main__":
    unittest.main()

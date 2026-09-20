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
import n3iwf_gtpu_reference as gtpu_reference
import n3iwf_key_lifecycle_reference as key_lifecycle
import n3iwf_roster_lifecycle_reference as roster_lifecycle
import n3iwf_dtls_lifecycle_reference as dtls_lifecycle
import n3iwf_dtls_profile_reference as dtls_profiles

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/opc-n3iwf-fixtures/fixtures"


def wire(subset, name):
    return bytes.fromhex((FIXTURES / subset / "wire" / (name + ".hex")).read_text())


class WireRegressions(unittest.TestCase):
    def test_dtls_profiles_cannot_replace_source_rows_or_claim_execution(self):
        original = json.loads((FIXTURES / "n2-dtls/profile-rekey-hello.json").read_text())
        data = wire("n2-dtls", "profile-rekey-hello")
        dtls_profiles.validate(original, data)
        for mutation, reason in (
            ("path", "dtls-profile-path"), ("digest", "dtls-profile-digest"),
            ("family", "dtls-profile-family"), ("wire-row", "dtls-profile-wire"),
            ("wire-outcome", "dtls-profile-wire"), ("wire-truncated", "dtls-profile-wire"),
            ("wire-source", "dtls-profile-wire"), ("wire-secret", "dtls-profile-wire"),
            ("count", "dtls-profile-context"), ("execution_claim", "dtls-profile-context"),
            ("requires_separate_runtime_qualification", "dtls-profile-context"),
            ("external_interoperability", "dtls-profile-context"), ("bool-type", "dtls-profile-context"),
            ("scope", "dtls-profile-scope"), ("claims", "dtls-profile-claims"),
            ("authority", "dtls-profile-authority"), ("direction", "dtls-profile-direction"),
            ("provenance", "dtls-profile-provenance"), ("outcome", "dtls-profile-outcome"),
            ("runtime_claim", "dtls-profile-outcome"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(original))
                payload = data
                source = changed["context"]["source_vector"]
                if mutation == "path": source["path"] = "../outside.json"
                elif mutation == "digest": source["sha256"] = "0" * 64
                elif mutation == "family": source["case"] = "server-name"
                elif mutation.startswith("wire-"):
                    value = json.loads(data)
                    if mutation == "wire-row": value["cases"][0]["row"] = 2
                    elif mutation == "wire-outcome": value["cases"][0]["expected"] = "reject"
                    elif mutation == "wire-source": value["reference"]["sha256"] = "0" * 64
                    elif mutation == "wire-secret": value["cases"][0]["record_hex"] = "00"
                    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    if mutation == "wire-truncated": payload = payload[:-1]
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "count": changed["context"]["cases"] -= 1
                elif mutation in ("execution_claim", "external_interoperability"): changed["context"][mutation] = True
                elif mutation == "requires_separate_runtime_qualification": changed["context"][mutation] = False
                elif mutation == "bool-type": changed["context"]["execution_claim"] = 0
                elif mutation == "scope": changed["validation_scope"] = "dtls-record"
                elif mutation == "claims": changed["semantic_assertions"][-1] = "external_interoperability=true"
                elif mutation == "authority": changed["source"]["clauses"][-1] = "RFC mandatory stream count 16"
                elif mutation == "direction": changed["direction"] = "ue-to-n3iwf"
                elif mutation == "provenance": changed["provenance"]["independent_capture"] = True
                elif mutation == "outcome": changed["expected_outcome"] = "receive"
                else: changed["runtime_claim"] = True
                with self.assertRaisesRegex(dtls_profiles.Invalid, "^" + reason + "$"):
                    dtls_profiles.validate(changed, payload)

    def test_dtls_profile_sources_and_redaction_are_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, digest, _, _ = dtls_profiles.VECTORS["rekey-hello"]
            target = root / source
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / source).read_bytes() + b"\n")
            with mock.patch.object(dtls_profiles, "ROOT", root):
                with self.assertRaisesRegex(dtls_profiles.Invalid, "^dtls-profile-source-digest$"):
                    dtls_profiles.projected_vectors("rekey-hello")
        for family in dtls_profiles.FAMILIES:
            payload = dtls_profiles.wire(family)
            for forbidden in (b"pkcs8", b"leaf_der", b"crl_der", b"record_hex", b"spiffe:", b"amf."):
                self.assertNotIn(forbidden, payload)

    def test_dtls_catalog_cannot_rewrite_obligations_or_promote_scope(self):
        original = json.loads((FIXTURES / "n2-dtls/lifecycle-cancellation.json").read_text())
        data = wire("n2-dtls", "lifecycle-cancellation")
        dtls_lifecycle.validate(original, data)
        for mutation, reason in (
            ("path", "dtls-reference-path"), ("digest", "dtls-reference-digest"),
            ("family", "dtls-reference-family"), ("wire-order", "dtls-reference-wire"),
            ("wire-effect", "dtls-reference-wire"), ("wire-truncated", "dtls-reference-wire"),
            ("count", "dtls-reference-context"), ("carrier", "dtls-reference-context"),
            ("protected_ppid", "dtls-reference-context"), ("ordered_stream", "dtls-reference-context"),
            ("kernel_validation", "dtls-reference-context"), ("in_place_rekey", "dtls-reference-context"),
            ("revocation", "dtls-reference-context"), ("external_interoperability", "dtls-reference-context"),
            ("bool-type", "dtls-reference-context"), ("scope", "dtls-reference-scope"),
            ("authority", "dtls-reference-authority"), ("claims", "dtls-reference-claims"),
            ("direction", "dtls-reference-direction"), ("provenance", "dtls-reference-provenance"),
            ("outcome", "dtls-reference-outcome"), ("runtime_claim", "dtls-reference-outcome"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(original))
                payload = data
                source = changed["context"]["source_vector"]
                if mutation == "path": source["path"] = "../outside.json"
                elif mutation == "digest": source["sha256"] = "0" * 64
                elif mutation == "family": source["case"] = "records"
                elif mutation in ("wire-order", "wire-effect"):
                    schedule = json.loads(data)
                    if mutation == "wire-order": schedule["cases"].reverse()
                    else: schedule["cases"][0]["expected"] = "rfc6083_connection_closed"
                    payload = (json.dumps(schedule, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "wire-truncated":
                    payload = payload[:-1]
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "count": changed["context"]["schedules"] -= 1
                elif mutation == "carrier": changed["context"]["carrier"] = "linux"
                elif mutation == "protected_ppid": changed["context"][mutation] = 60
                elif mutation == "ordered_stream": changed["context"][mutation] = 1
                elif mutation in ("kernel_validation", "in_place_rekey", "revocation", "external_interoperability"):
                    changed["context"][mutation] = True
                elif mutation == "bool-type": changed["context"]["sdk_transport_validation"] = 1
                elif mutation == "scope": changed["validation_scope"] = "lifecycle-label"
                elif mutation == "authority": changed["source"]["clauses"][-1] = "RFC application maximum 16347"
                elif mutation == "claims": changed["semantic_assertions"][-1] = "external_interoperability=true"
                elif mutation == "direction": changed["direction"] = "ue-to-n3iwf"
                elif mutation == "provenance": changed["provenance"]["independent_capture"] = True
                elif mutation == "outcome": changed["expected_outcome"] = "receive"
                else: changed["runtime_claim"] = True
                with self.assertRaisesRegex(dtls_lifecycle.Invalid, "^" + reason + "$"):
                    dtls_lifecycle.validate(changed, payload)

    def test_roster_catalog_cannot_rewrite_schedules_or_promote_authority(self):
        original = json.loads((FIXTURES / "xfrm-roster/lifecycle-install-failure.json").read_text())
        data = wire("xfrm-roster", "lifecycle-install-failure")
        roster_lifecycle.validate(original, data)
        for mutation, reason in (
            ("path", "roster-reference-path"), ("digest", "roster-reference-digest"),
            ("family", "roster-reference-family"), ("wire-order", "roster-reference-wire"),
            ("wire-effect", "roster-reference-wire"), ("wire-truncated", "roster-reference-wire"),
            ("count", "roster-reference-context"), ("backend", "roster-reference-context"),
            ("kernel_validation", "roster-reference-context"), ("packet_provenance", "roster-reference-context"),
            ("complete_roster_relocation", "roster-reference-context"), ("bool-type", "roster-reference-context"),
            ("scope", "roster-reference-scope"), ("authority", "roster-reference-authority"),
            ("claims", "roster-reference-claims"), ("direction", "roster-reference-direction"),
            ("provenance", "roster-reference-provenance"), ("outcome", "roster-reference-outcome"),
            ("runtime_claim", "roster-reference-outcome"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(original))
                payload = data
                source = changed["context"]["source_vector"]
                if mutation == "path": source["path"] = "../outside.json"
                elif mutation == "digest": source["sha256"] = "0" * 64
                elif mutation == "family": source["case"] = "finalize"
                elif mutation in ("wire-order", "wire-effect"):
                    schedule = json.loads(data)
                    if mutation == "wire-order": schedule["cases"].reverse()
                    else: schedule["cases"][0]["final_present"][0] = 1
                    payload = (json.dumps(schedule, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "wire-truncated":
                    payload = payload[:-1]
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "count": changed["context"]["schedules"] -= 1
                elif mutation == "backend": changed["context"]["backend"] = "linux"
                elif mutation in ("kernel_validation", "packet_provenance", "complete_roster_relocation"):
                    changed["context"][mutation] = True
                elif mutation == "bool-type": changed["context"]["sdk_store_validation"] = 1
                elif mutation == "scope": changed["validation_scope"] = "lifecycle-label"
                elif mutation == "authority": changed["source"]["clauses"][-1] = "RFC wire maximum eight members"
                elif mutation == "claims": changed["semantic_assertions"][-1] = "complete_roster_relocation=true"
                elif mutation == "direction": changed["direction"] = "ue-to-n3iwf"
                elif mutation == "provenance": changed["provenance"]["independent_capture"] = True
                elif mutation == "outcome": changed["expected_outcome"] = "receive"
                else: changed["runtime_claim"] = True
                with self.assertRaisesRegex(roster_lifecycle.Invalid, "^" + reason + "$"):
                    roster_lifecycle.validate(changed, payload)

    def test_custody_catalog_cannot_rewrite_the_authored_schedule(self):
        original = json.loads((FIXTURES / "protocol-key/custody-consume-once.json").read_text())
        data = wire("protocol-key", "custody-consume-once")
        key_lifecycle.validate(original, data)
        for mutation, reason in (
            ("path", "custody-reference-path"), ("digest", "custody-reference-digest"),
            ("case", "custody-reference-case"), ("wire", "custody-reference-wire"),
            ("key_recipe", "custody-reference-context"), ("sdk_custody_validation", "custody-reference-context"),
            ("sdk_bool_type", "custody-reference-context"), ("live_peer_validation", "custody-reference-context"),
            ("public_memory_erasure_observation", "custody-reference-context"),
            ("scope", "custody-reference-scope"), ("authority", "custody-reference-authority"),
            ("claims", "custody-reference-claims"), ("direction", "custody-reference-direction"),
            ("provenance", "custody-reference-provenance"), ("outcome", "custody-reference-outcome"),
            ("runtime_claim", "custody-reference-outcome"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(original))
                payload = data
                source = changed["context"]["source_vector"]
                if mutation == "path": source["path"] = "../outside.json"
                elif mutation == "digest": source["sha256"] = "0" * 64
                elif mutation == "case": source["case"] = "release"
                elif mutation == "wire":
                    schedule = json.loads(data)
                    schedule["steps"][-1]["expect"] = "ok"
                    payload = key_lifecycle.wire(schedule)
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation == "key_recipe": changed["context"][mutation] = "caller-key"
                elif mutation == "sdk_custody_validation": changed["context"][mutation] = False
                elif mutation == "sdk_bool_type": changed["context"]["sdk_custody_validation"] = 1
                elif mutation in ("live_peer_validation", "public_memory_erasure_observation"):
                    changed["context"][mutation] = True
                elif mutation == "scope": changed["validation_scope"] = "handle-lifecycle-contract"
                elif mutation == "authority": changed["source"]["clauses"][-1] = "RFC wire generation policy"
                elif mutation == "claims": changed["semantic_assertions"][-1] = "public_memory_erasure_observation=true"
                elif mutation == "direction": changed["direction"] = "ue-to-n3iwf"
                elif mutation == "provenance": changed["provenance"]["independent_capture"] = True
                elif mutation == "outcome": changed["expected_outcome"] = "receive"
                else: changed["runtime_claim"] = True
                with self.assertRaisesRegex(key_lifecycle.Invalid, "^" + reason + "$"):
                    key_lifecycle.validate(changed, payload)

    def test_psc_catalog_cannot_replace_independent_source_evidence(self):
        original = json.loads((FIXTURES / "n3-gtpu/reference-dl-9-1-7.json").read_text())
        data = wire("n3-gtpu", "reference-dl-9-1-7")
        rows = gtpu_reference.reference_rows()
        gtpu_reference.validate(original, data, rows)
        for mutation, reason in (
            ("path", "psc-reference-path"), ("digest", "psc-reference-digest"),
            ("case", "psc-reference-case"), ("wire", "psc-reference-wire"),
            ("rqi", "psc-reference-fields"), ("ppi", "psc-reference-fields"),
            ("qfi", "psc-reference-fields"), ("pdu_type", "psc-reference-fields"),
            ("rqi_type", "psc-reference-fields"), ("ppi_type", "psc-reference-fields"),
            ("direction", "psc-reference-direction"),
            ("claims", "psc-reference-claims"), ("authority", "psc-reference-authority"),
            ("provenance", "psc-reference-provenance"), ("outcome", "psc-reference-outcome"),
            ("runtime_claim", "psc-runtime-claim"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(original))
                payload = data
                source = changed["context"]["source_vector"]
                if mutation == "path": source["path"] = "../outside.tsv"
                elif mutation == "digest": source["sha256"] = "0" * 64
                elif mutation == "case": source["case"] = "dl-63-1-7"
                elif mutation == "wire":
                    payload = data[:14] + bytes([data[14] ^ 0x40]) + data[15:]
                    changed["wire"]["digest_sha256"] = hashlib.sha256(payload).hexdigest()
                elif mutation in ("qfi", "ppi"):
                    changed["context"]["psc"][mutation] = 0
                elif mutation == "rqi": changed["context"]["psc"]["rqi"] = False
                elif mutation == "pdu_type": changed["context"]["psc"]["pdu_type"] = 1
                elif mutation == "rqi_type": changed["context"]["psc"]["rqi"] = 1
                elif mutation == "ppi_type": changed["context"]["psc"]["ppi"] = True
                elif mutation == "direction": changed["direction"] = "n3-uplink"
                elif mutation == "claims": changed["semantic_assertions"][3] = "rqi=0"
                elif mutation == "authority": changed["source"]["release"] = "V17.0.0"
                elif mutation == "provenance": changed["provenance"]["independent_capture"] = True
                elif mutation == "runtime_claim": changed["runtime_claim"] = True
                else: changed["expected_outcome"] = "constructed"
                with self.assertRaisesRegex(gtpu_reference.Invalid, "^" + reason + "$"):
                    gtpu_reference.validate(changed, payload, rows)


    def test_ngap_reuse_remains_bound_to_its_independent_source(self):
        spec = importlib.util.spec_from_file_location(
            "ngap_reference_gate", ROOT / "scripts/check-n3iwf-ngap-reference.py"
        )
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        reference = json.loads(
            (
                ROOT / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
            ).read_text()
        )
        cases = [case for case in reference["cases"] if "source_vector" in case]
        self.assertEqual(gate.check_reused_vectors(cases), 16)
        for mutation, reason in (
            ("path", "reused-vector-path"),
            ("digest", "reused-vector-source-digest"),
            ("case", "reused-vector-case"),
            ("wire", "reused-vector-result"),
            ("result", "reused-vector-result"),
            ("field", "reused-vector-fields"),
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(cases[0]))
                source = changed["source_vector"]
                if mutation == "path":
                    source["path"] = "../outside.json"
                elif mutation == "digest":
                    source["sha256"] = "0" * 64
                elif mutation == "case":
                    source["case"] = "nonexistent"
                elif mutation == "wire":
                    # Refreshing the copied digest cannot invent source provenance.
                    wire = bytearray.fromhex(changed["wire_hex"])
                    wire[-1] ^= 1
                    changed["wire_hex"] = wire.hex()
                    changed["wire_sha256"] = hashlib.sha256(wire).hexdigest()
                elif mutation == "result":
                    changed["reference_error"] = "missing-mandatory-ie"
                else:
                    changed["encoded_ies"][0]["criticality"] = "ignore"
                with self.assertRaisesRegex(gate.Invalid, "^" + reason + "$"):
                    gate.check_reused_vectors([changed])

    def test_gre_rejects_unsupported_legacy_flags(self):
        manifest = json.loads((FIXTURES / "gre-qfi/positive-uplink.json").read_text())
        original = wire("gre-qfi", "positive-uplink")
        # RFC 2784 bit numbering starts at the most significant bit. K (2)
        # is allowed by RFC 2890; routing (1), strict source (4), recursion
        # (5), checksum (0), sequence (3), and version bits are not NWu.
        for bit in [0, 1, 3, 4, 5, 13, 14, 15]:
            data = bytearray(original)
            data[bit // 8] |= 1 << (7 - bit % 8)
            with self.subTest(bit=bit):
                self.assertEqual(oracle.observe(manifest, data), ("reject", "flags"))

    def test_gre_rqi_requires_downlink_direction(self):
        manifest = json.loads((FIXTURES / "gre-qfi/positive-uplink.json").read_text())
        data = wire("gre-qfi", "positive-downlink-rqi")
        self.assertEqual(oracle.observe(manifest, data), ("reject", "uplink-rqi"))
        manifest["direction"] = "n3iwf-to-ue"
        self.assertEqual(oracle.observe(manifest, data), ("accept", None))

    def test_gre_receives_reserved0_ignore_bits(self):
        manifest = json.loads((FIXTURES / "gre-qfi/positive-uplink.json").read_text())
        original = wire("gre-qfi", "positive-uplink")
        for bit in range(6, 13):
            data = bytearray(original)
            data[bit // 8] |= 1 << (7 - bit % 8)
            with self.subTest(bit=bit):
                self.assertEqual(oracle.observe(manifest, data), ("accept", None))

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

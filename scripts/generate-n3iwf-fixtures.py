#!/usr/bin/env python3
"""Author synthetic N3IWF fixture manifests from public specifications.

This script is the deterministic writer for crates/opc-n3iwf-fixtures/fixtures.
It emits spec-authored hex, SHA-256 digests, completion records, and subset
README octet tables. It never copies production captures or key material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "crates" / "opc-n3iwf-fixtures" / "fixtures"
PUBLIC_BASE = "3194cf3c06ab0f6aeed3f39b00f1055702c75f09"
ISSUE = 784

# Existing public SDK vectors reused by digest (issues 341/493).
NGSETUP_EXTERNAL = (
    "00 15 40 4a 00 00 04 00 1b 00 08 40 02 f8 98 00 00 00 00 00 52 40 0f "
    "06 00 4d 79 20 6c 69 74 74 6c 65 20 67 4e 42 00 66 00 1f 01 00 00 00 "
    "00 00 02 f8 98 00 01 00 08 00 80 00 00 01 00 02 f8 39 00 01 00 18 81 "
    "c0 00 13 88 00 15 40 01 40"
)
GTPU_ECHO_REQUEST = "32 01 00 04 00 00 00 00 12 34 00 00"
GTPU_ECHO_RESPONSE = "32 02 00 06 00 00 00 00 12 34 00 00 0e 00"
GTPU_DL_PSC = "36 ff 00 08 11 22 33 44 00 05 00 85 01 00 09 00"


def hex_bytes(text: str) -> bytes:
    return bytes(int(token, 16) for token in text.split())


def digest_of(text: str) -> str:
    return hashlib.sha256(hex_bytes(text)).hexdigest()


def write_hex(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def manifest(
    *,
    subset: str,
    name: str,
    case_class: str,
    document: str,
    release: str,
    clauses: list[str],
    direction: str,
    role: str,
    prerequisite: str,
    provenance_class: str,
    notes: str,
    referenced: str | None,
    sanitized: list[dict[str, str]],
    wire_name: str,
    wire_hex: str,
    assertions: list[str],
    outcome: str,
) -> dict:
    return {
        "sdk_fixture_id": f"opc.n3iwf.{subset}.v1.{name}",
        "subset": subset,
        "case_class": case_class,
        "source": {
            "document": document,
            "release": release,
            "clauses": clauses,
        },
        "direction": direction,
        "role": role,
        "prerequisite": prerequisite,
        "provenance": {
            "class": provenance_class,
            "synthetic": True,
            "independent_capture": False,
            "referenced_public_vector": referenced,
            "notes": notes,
        },
        "sanitized_fields": sanitized,
        "wire": {
            "path": f"wire/{wire_name}.hex",
            "digest_sha256": digest_of(wire_hex),
        },
        "semantic_assertions": assertions,
        "expected_outcome": outcome,
        "runtime_claim": False,
    }


def dump_manifest(subset_dir: Path, data: dict, wire_hex: str) -> None:
    stem = data["sdk_fixture_id"].split(".")[-1]
    write_hex(subset_dir / data["wire"]["path"], wire_hex)
    (subset_dir / f"{stem}.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )


def completion(
    subset: str,
    fixtures: list[dict],
    constructed: list[str],
    receive: list[str],
    unsupported: list[str],
) -> dict:
    classes = sorted({item["case_class"] for item in fixtures})
    return {
        "subset": subset,
        "status": "complete",
        "issue": ISSUE,
        "runtime_claim": False,
        "consumers_may_depend": True,
        "case_classes": classes,
        "fixture_ids": [item["sdk_fixture_id"] for item in fixtures],
        "constructed": constructed,
        "receive": receive,
        "unsupported": unsupported,
    }


def write_completion(subset_dir: Path, record: dict) -> None:
    (subset_dir / "COMPLETION.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )


def write_readme(subset_dir: Path, title: str, body: str) -> None:
    (subset_dir / "README.md").write_text(f"# {title}\n\n{body}\n", encoding="utf-8")


SYN_ID = [
    {
        "name": "identifiers",
        "treatment": "documentation-range-or-reserved-test",
        "value_class": "synthetic",
    }
]
NO_KEY = [
    {
        "name": "key-material",
        "treatment": "never-published",
        "value_class": "absent",
    }
]
NAS_OPAQUE = [
    {
        "name": "nas-pdu",
        "treatment": "opaque-placeholder-header-only",
        "value_class": "non-subscriber",
    }
]


def eap5g(subset_dir: Path) -> list[dict]:
    start = "01 01 00 0e fe 00 28 af 00 00 00 03 01 00"
    nas = (
        "02 02 00 1d fe 00 28 af 00 00 00 03 02 00 00 08 02 03 00 f1 10 "
        "04 01 03 00 03 7e 00 41"
    )
    unknown = (
        "02 02 00 20 fe 00 28 af 00 00 00 03 02 00 00 0b 02 03 00 f1 10 "
        "20 01 00 04 01 03 00 03 7e 00 41"
    )
    ordered = (
        "02 02 00 1d fe 00 28 af 00 00 00 03 02 00 00 08 04 01 03 "
        "02 03 00 f1 10 00 03 7e 00 41"
    )
    duplicate = (
        "02 02 00 22 fe 00 28 af 00 00 00 03 02 00 00 0d 02 03 00 f1 10 "
        "02 03 00 f1 10 04 01 03 00 03 7e 00 41"
    )
    malformed = "01 01 00 10 fe 00 28 af 00 00 00 03 01 00"
    unknown_critical = "01 01 00 0e fe 00 28 af 00 00 00 03 7f 00"
    truncated = "01 01 00 0e fe 00 28 af 00 00 00 03 01"
    overflow = (
        "02 02 00 12 fe 00 28 af 00 00 00 03 02 00 00 08 02 ff 00"
    )
    fixtures = [
        manifest(
            subset="eap5g",
            name="positive-start",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["7.3", "9.3.2.2.1"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="IKE_AUTH request without AUTH; EAP-5G session not started",
            provenance_class="spec-authored",
            notes="Hand-authored from TS 24.502 V18.8.0 figure 9.3.2.2.1-1",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-start",
            wire_hex=start,
            assertions=[
                "eap_code=request",
                "expanded_type=254",
                "vendor_id=10415",
                "vendor_type=3",
                "message_id=1",
            ],
            outcome="constructed",
        ),
        manifest(
            subset="eap5g",
            name="positive-nas-response",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["7.3", "9.3.2.2.2"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="EAP-Request/5G-Start already sent",
            provenance_class="spec-authored",
            notes="Selected PLMN 001/01 and mo-Signalling cause; NAS body opaque",
            referenced=None,
            sanitized=SYN_ID + NAS_OPAQUE,
            wire_name="positive-nas-response",
            wire_hex=nas,
            assertions=[
                "message_id=2",
                "an_parameter.selected_plmn=001-01",
                "an_parameter.establishment_cause=mo-Signalling",
                "nas_pdu_opaque=true",
            ],
            outcome="receive",
        ),
        manifest(
            subset="eap5g",
            name="unknown-parameter-ignored",
            case_class="unknown-critical",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.2"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="Same as positive NAS response",
            provenance_class="synthetic-negative",
            notes="Spare AN-parameter type 20H must be ignored on receive",
            referenced=None,
            sanitized=SYN_ID + NAS_OPAQUE,
            wire_name="unknown-parameter-ignored",
            wire_hex=unknown,
            assertions=[
                "spare_an_parameter_type=0x20",
                "receiver_disposition=ignore",
                "not_caller_duplicate_policy",
            ],
            outcome="ignore",
        ),
        manifest(
            subset="eap5g",
            name="ordering-an-parameters",
            case_class="ordering",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.2"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="Same as positive NAS response",
            provenance_class="spec-authored",
            notes="Establishment cause precedes selected PLMN; order is not significant",
            referenced=None,
            sanitized=SYN_ID + NAS_OPAQUE,
            wire_name="ordering-an-parameters",
            wire_hex=ordered,
            assertions=["an_parameter_order=cause-then-plmn", "receive=permitted"],
            outcome="receive",
        ),
        manifest(
            subset="eap5g",
            name="duplicate-selected-plmn",
            case_class="duplicate",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.2"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="Caller selects duplicate-singleton policy separately",
            provenance_class="synthetic-negative",
            notes="Duplicate selected-PLMN is caller policy, not unknown-parameter ignore",
            referenced=None,
            sanitized=SYN_ID + NAS_OPAQUE,
            wire_name="duplicate-selected-plmn",
            wire_hex=duplicate,
            assertions=[
                "duplicate_singleton=selected-plmn",
                "disposition=caller-duplicate-singleton-policy",
            ],
            outcome="caller-policy",
        ),
        manifest(
            subset="eap5g",
            name="malformed-length",
            case_class="malformed",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.1", "IETF RFC 3748 4.1"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="EAP Length claims 16 octets over a 14-octet Start body",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-length",
            wire_hex=malformed,
            assertions=["eap_length_mismatch=true"],
            outcome="reject",
        ),
        manifest(
            subset="eap5g",
            name="unknown-message-id",
            case_class="unknown-critical",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.1"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Message-Id 0x7F is not a defined EAP-5G message",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="unknown-message-id",
            wire_hex=unknown_critical,
            assertions=["message_id=0x7f", "unknown_critical=true"],
            outcome="reject",
        ),
        manifest(
            subset="eap5g",
            name="truncated-start",
            case_class="truncation",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.1"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Start missing the spare octet",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-start",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="eap5g",
            name="bounded-an-parameter-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.2.2.2"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="Caller-selected AN-parameter bound",
            provenance_class="synthetic-negative",
            notes="AN-parameter length 0xFF overflows the declared AN-parameters region",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-an-parameter-overflow",
            wire_hex=overflow,
            assertions=["an_parameter_length_overflow=true"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(
        fixtures,
        [start, nas, unknown, ordered, duplicate, malformed, unknown_critical, truncated, overflow],
        strict=True,
    ):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "EAP-5G fixture subset",
        """Hand-authored from TS 24.502 V18.8.0 clauses 7.3 and 9.3.2.

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `01` | EAP Code Request (RFC 3748 §4.1) |
| 1 | `01` | Synthetic identifier |
| 2..3 | `00 0e` | EAP Length 14 |
| 4 | `fe` | Expanded Type 254 |
| 5..7 | `00 28 af` | Vendor-Id 10415 |
| 8..11 | `00 00 00 03` | Vendor-Type EAP-5G |
| 12 | `01` | 5G-Start-Id |
| 13 | `00` | Spare |

Unknown spare AN-parameters are ignored. Duplicate selected-PLMN is a caller
duplicate-singleton policy, not the spare-parameter ignore rule. NAS remains
opaque. `runtime_claim=false`.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "eap5g",
            fixtures,
            constructed=["EAP-Request/5G-Start envelope"],
            receive=["EAP-Response/5G-NAS with selected PLMN and opaque NAS"],
            unsupported=[
                "subscriber authentication decision",
                "SUCI deconcealment",
                "EAP method key derivation",
            ],
        ),
    )
    return fixtures


def nwu_ike(subset_dir: Path) -> list[dict]:
    nas_ip4 = "00 00 00 0c 00 00 d8 ce c0 00 02 0a"
    nas_tcp = "00 00 00 0a 00 00 d8 d2 4e 20"
    qos = "00 00 00 0d 00 00 d8 cd 04 05 01 09 00"
    up_ip4 = "00 00 00 0c 00 00 d8 d4 c0 00 02 0b"
    delete = "00 00 00 0c 03 04 00 01 0a 0b 0c 0d"
    mobike = "00 00 00 0c 00 00 40 0d c0 00 02 0a"
    unknown_crit = "00 80 00 08 7f 00 00 00"
    duplicate = "00 00 00 0c 00 00 d8 ce c0 00 02 0a 00 00 00 0c 00 00 d8 ce c0 00 02 0b"
    ordered = "00 00 00 0a 00 00 d8 d2 4e 20 00 00 00 0c 00 00 d8 ce c0 00 02 0a"
    malformed = "00 00 00 0c 00 04 d8 ce c0 00 02"
    truncated = "00 00 00 0c 00 00 d8 ce c0"
    overflow = "00 00 00 08 ff 00 d8 ce"
    wires = [
        nas_ip4,
        nas_tcp,
        qos,
        up_ip4,
        delete,
        mobike,
        unknown_crit,
        duplicate,
        ordered,
        malformed,
        truncated,
        overflow,
    ]
    fixtures = [
        manifest(
            subset="nwu-ike",
            name="positive-nas-ip4",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2", "9.3.1.2"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="IKE SA authenticated; configuration notify phase",
            provenance_class="spec-authored",
            notes="NAS_IP4_ADDRESS 55502 with documentation IPv4 192.0.2.10",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-nas-ip4",
            wire_hex=nas_ip4,
            assertions=["notify_type=55502", "protocol_id=0", "spi_size=0"],
            outcome="constructed",
        ),
        manifest(
            subset="nwu-ike",
            name="positive-nas-tcp-port",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2", "9.3.1.6"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="NAS_IP4_ADDRESS already selected",
            provenance_class="spec-authored",
            notes="NAS_TCP_PORT 55506 value 20000 is a synthetic test port",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-nas-tcp-port",
            wire_hex=nas_tcp,
            assertions=["notify_type=55506", "port=20000"],
            outcome="constructed",
        ),
        manifest(
            subset="nwu-ike",
            name="positive-5g-qos-info",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.3", "9.3.1.1"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="CREATE_CHILD_SA for one PDU session",
            provenance_class="spec-authored",
            notes="5G_QOS_INFO 55501 with PDU session 5 and QFI 9",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-5g-qos-info",
            wire_hex=qos,
            assertions=["notify_type=55501", "pdu_session=5", "qfi=9"],
            outcome="constructed",
        ),
        manifest(
            subset="nwu-ike",
            name="positive-up-ip4",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["7.5.2", "9.3.1.8"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="CREATE_CHILD_SA selected; XFRM roster is a separate subset",
            provenance_class="spec-authored",
            notes="UP_IP4_ADDRESS 55508 with documentation IPv4 192.0.2.11",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-up-ip4",
            wire_hex=up_ip4,
            assertions=["notify_type=55508", "address=192.0.2.11", "spi_size=0"],
            outcome="constructed",
        ),
        manifest(
            subset="nwu-ike",
            name="delete-esp",
            case_class="positive",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["1.4.1", "3.11"],
            direction="either",
            role="ike-endpoint",
            prerequisite="Child SA exists; roster relocation is a separate subset",
            provenance_class="spec-authored",
            notes="Delete payload names synthetic ESP SPI only",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="delete-esp",
            wire_hex=delete,
            assertions=["protocol=ESP", "spi_count=1", "backend_roster=out-of-scope"],
            outcome="constructed",
        ),
        manifest(
            subset="nwu-ike",
            name="mobility-additional-addresses",
            case_class="positive",
            document="IETF RFC 4555",
            release="RFC 4555",
            clauses=["3.2"],
            direction="either",
            role="ike-endpoint",
            prerequisite="MOBIKE enabled by caller policy",
            provenance_class="spec-authored",
            notes="ADDITIONAL_IP4_ADDRESS notify type 16397 with documentation IPv4 192.0.2.10",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="mobility-additional-addresses",
            wire_hex=mobike,
            assertions=["notify_type=16397", "address=192.0.2.10", "mobility_wire_only=true"],
            outcome="receive",
        ),
        manifest(
            subset="nwu-ike",
            name="unknown-critical-payload",
            case_class="unknown-critical",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.5"],
            direction="peer-to-local",
            role="ike-endpoint",
            prerequisite="Generic IKEv2 payload-chain decoder from opc-proto-ikev2",
            provenance_class="synthetic-negative",
            notes="Critical bit set on unknown payload type 127",
            referenced="crates/opc-proto-ikev2/tests/unknown_critical_rejection.rs",
            sanitized=SYN_ID,
            wire_name="unknown-critical-payload",
            wire_hex=unknown_crit,
            assertions=["critical=true", "unknown_payload_type=127"],
            outcome="reject",
        ),
        manifest(
            subset="nwu-ike",
            name="duplicate-nas-ip4",
            case_class="duplicate",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.1.2"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="Caller duplicate-notify policy",
            provenance_class="synthetic-negative",
            notes="Two NAS_IP4_ADDRESS notifies; singleton policy is caller-owned",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-nas-ip4",
            wire_hex=duplicate,
            assertions=["duplicate_notify=55502"],
            outcome="caller-policy",
        ),
        manifest(
            subset="nwu-ike",
            name="ordering-tcp-before-ip4",
            case_class="ordering",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2", "9.3.1.2", "9.3.1.6"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="Both notifies present",
            provenance_class="spec-authored",
            notes="NAS_TCP_PORT before NAS_IP4_ADDRESS is wire-legal",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="ordering-tcp-before-ip4",
            wire_hex=ordered,
            assertions=["notify_order=tcp-then-ip4"],
            outcome="receive",
        ),
        manifest(
            subset="nwu-ike",
            name="malformed-spi-size",
            case_class="malformed",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.1.2"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="NAS_IP4_ADDRESS with SPI Size 4 but incomplete SPI/address",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-spi-size",
            wire_hex=malformed,
            assertions=["spi_size_inconsistent=true"],
            outcome="reject",
        ),
        manifest(
            subset="nwu-ike",
            name="truncated-nas-ip4",
            case_class="truncation",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.1.2"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Address truncated after first octet",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-nas-ip4",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="nwu-ike",
            name="bounded-spi-size-overflow",
            case_class="bounded-overflow",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["3.10"],
            direction="peer-to-local",
            role="ike-endpoint",
            prerequisite="Caller SPI-size bound",
            provenance_class="synthetic-negative",
            notes="SPI Size 255 on a four-octet notify header",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-spi-size-overflow",
            wire_hex=overflow,
            assertions=["spi_size=255"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "NWu IKE fixture subset",
        """Wire notifies and Delete/MOBIKE payloads only. Backend overlap, SPI
provenance, rekey, and roster relocation belong to `xfrm-roster`.

| Notify | Type | Synthetic value |
| --- | --- | --- |
| NAS_IP4_ADDRESS | 55502 | 192.0.2.10 |
| NAS_TCP_PORT | 55506 | 20000 |
| 5G_QOS_INFO | 55501 | PDU session 5, QFI 9 |
| UP_IP4_ADDRESS | 55508 | 192.0.2.11 |
| ADDITIONAL_IP4_ADDRESS | 16397 | 192.0.2.10 |
| Delete ESP | RFC 7296 §3.11 | one synthetic SPI |
""",
    )
    write_completion(
        subset_dir,
        completion(
            "nwu-ike",
            fixtures,
            constructed=["NAS_IP4_ADDRESS", "NAS_TCP_PORT", "5G_QOS_INFO", "UP_IP4_ADDRESS", "Delete ESP"],
            receive=["MOBIKE additional-address notify", "notify reordering"],
            unsupported=[
                "XFRM install",
                "SPI allocation",
                "authentication decision",
                "suite allowlist",
            ],
        ),
    )
    return fixtures


def ngap(subset_dir: Path) -> list[dict]:
    empty_setup = "00 15 00 03 00 00 00"
    unknown_crit = (
        "00 15 40 4a 00 00 04 00 ff 00 08 40 02 f8 98 00 00 00 00 00 52 40 0f "
        "06 00 4d 79 20 6c 69 74 74 6c 65 20 67 4e 42 00 66 00 1f 01 00 00 00 "
        "00 00 02 f8 98 00 01 00 08 00 80 00 00 01 00 02 f8 39 00 01 00 18 81 "
        "c0 00 13 88 00 15 40 01 40"
    )
    duplicate = (
        "00 15 00 0d 00 00 02 00 1b 00 01 00 00 1b 00 01 00"
    )
    ordered = "00 15 00 03 00 00 00"
    malformed = "00 15 00 01 00"
    truncated = "00 15"
    overflow = "00 15 00 03 00 ff ff"
    wires = [
        NGSETUP_EXTERNAL,
        empty_setup,
        unknown_crit,
        duplicate,
        ordered,
        malformed,
        truncated,
        overflow,
    ]
    fixtures = [
        manifest(
            subset="ngap",
            name="positive-ngsetup-external",
            case_class="positive",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2.6.1"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Existing opc-proto-ngap DecodeContext policy from issue 493",
            provenance_class="referenced-public-vector",
            notes="78-byte independent libngap NGSetupRequest already proven in opc-proto-ngap",
            referenced="crates/opc-proto-ngap/src/lib.rs::ngsetup_request_fixture",
            sanitized=SYN_ID,
            wire_name="positive-ngsetup-external",
            wire_hex=NGSETUP_EXTERNAL,
            assertions=[
                "procedure=21",
                "outcome=initiating",
                "ie_ids=27,82,102,21",
                "canonical_typed_encode=unsupported",
            ],
            outcome="receive",
        ),
        manifest(
            subset="ngap",
            name="positive-empty-setup-wrapper",
            case_class="positive",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2", "X.691"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Issue 493 empty-IE wrapper helper",
            provenance_class="spec-authored",
            notes="Initiating procedure 21 with empty ProtocolIE-Container",
            referenced="crates/opc-proto-ngap/src/lib.rs::empty_ie_pdu",
            sanitized=SYN_ID,
            wire_name="positive-empty-setup-wrapper",
            wire_hex=empty_setup,
            assertions=["procedure=21", "ie_count=0", "constructed_typed_encode=unsupported"],
            outcome="receive",
        ),
        manifest(
            subset="ngap",
            name="unknown-critical-ie",
            case_class="unknown-critical",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2.6.1"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="DecodeContext unknown_ie_policy=Reject and conservative profile",
            provenance_class="synthetic-negative",
            notes="First IE identifier mutated from 27 to 0x00ff retaining reject criticality",
            referenced="crates/opc-proto-ngap/src/policy.rs::NG_SETUP_REQUEST",
            sanitized=SYN_ID,
            wire_name="unknown-critical-ie",
            wire_hex=unknown_crit,
            assertions=["unknown_ie=255", "criticality=reject", "code=UnknownCriticalIe"],
            outcome="reject",
        ),
        manifest(
            subset="ngap",
            name="duplicate-global-ran-node-id",
            case_class="duplicate",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2.6.1"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="DuplicateIePolicy::Reject from issue 493",
            provenance_class="synthetic-negative",
            notes="Two singleton id-GlobalRANNodeID entries",
            referenced="crates/opc-proto-ngap/src/policy.rs::NG_SETUP_REQUEST",
            sanitized=SYN_ID,
            wire_name="duplicate-global-ran-node-id",
            wire_hex=duplicate,
            assertions=["duplicate_ie=27", "cardinality=singleton"],
            outcome="reject",
        ),
        manifest(
            subset="ngap",
            name="ordering-empty-container",
            case_class="ordering",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="IE order is insignificant for empty containers",
            provenance_class="spec-authored",
            notes="Empty container has no IE order; documents that wire order is not a send claim",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="ordering-empty-container",
            wire_hex=ordered,
            assertions=["ie_order=empty", "constructed_send=unsupported"],
            outcome="unsupported",
        ),
        manifest(
            subset="ngap",
            name="malformed-open-type",
            case_class="malformed",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Open-type length 1 cannot hold a ProtocolIE-Container prefix",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-open-type",
            wire_hex=malformed,
            assertions=["open_type_length=1"],
            outcome="reject",
        ),
        manifest(
            subset="ngap",
            name="truncated-wrapper",
            case_class="truncation",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Only the PDU choice and procedure code are present",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-wrapper",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="ngap",
            name="bounded-ie-count-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 38.413",
            release="R18",
            clauses=["9.2"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="DecodeContext::max_ies preflight from issue 493",
            provenance_class="synthetic-negative",
            notes="Container count 65535 before rasn materialization",
            referenced="crates/opc-proto-ngap/src/policy.rs::preflight_ie_count",
            sanitized=SYN_ID,
            wire_name="bounded-ie-count-overflow",
            wire_hex=overflow,
            assertions=["ie_count=65535", "pre_materialization_bound=true"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "NGAP N3IWF fixture subset",
        """Reuses the issue 493 DecodeContext / IE cardinality contract and the
public 78-byte NGSetupRequest vector. Canonical typed encode remains
unsupported. Release 18 identifier/criticality/cardinality matrices for the
typed procedures live in `crates/opc-proto-ngap/src/policy.rs` and are
cited by path. The 78-byte vector is copied by digest and locked to that
source file by `tests/contracts.rs`.

Admitted send/receive outcomes in this subset: receive NGSetupRequest and
empty wrappers. Constructed N3IWF encode is unsupported until issue 787.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "ngap",
            fixtures,
            constructed=[],
            receive=["NGSetupRequest external vector", "empty initiating wrapper"],
            unsupported=[
                "canonical typed encode",
                "constructed N3IWF send",
                "semantic IE-value validation",
            ],
        ),
    )
    return fixtures


def n2_sctp(subset_dir: Path) -> list[dict]:
    positive = "00 00 00 3c 96 1c"
    data = "00 03 00 10 00 00 00 01 00 00 00 00 00 00 00 3c"
    unknown = "00 00 00 42 96 1c"
    duplicate = "00 00 00 3c 96 1c 00 00 00 3c 96 1c"
    ordered = "96 1c 00 00 00 3c"
    malformed = "00 00 00 3c"
    truncated = "00 00 00"
    overflow = "00 00 00 3c ff ff"
    wires = [positive, data, unknown, duplicate, ordered, malformed, truncated, overflow]
    fixtures = [
        manifest(
            subset="n2-sctp",
            name="positive-ppid60-port",
            case_class="positive",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Reuse opc-sctp SctpAssociation and NGAP_PPID=60",
            provenance_class="spec-authored",
            notes="PPID 60 and default service port 38412; not a security claim",
            referenced="crates/opc-sctp/src/lib.rs::NGAP_PPID",
            sanitized=SYN_ID,
            wire_name="positive-ppid60-port",
            wire_hex=positive,
            assertions=["ppid=60", "port=38412", "protection=unprotected"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-sctp",
            name="positive-data-chunk",
            case_class="positive",
            document="IETF RFC 4960",
            release="RFC 4960",
            clauses=["3.3.1"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Ordinary SCTP DATA chunk; NGAP bytes are out of band",
            provenance_class="spec-authored",
            notes="DATA chunk header with PPID 60 and empty user data",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-data-chunk",
            wire_hex=data,
            assertions=["chunk=DATA", "ppid=60", "user_data_len=0"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-sctp",
            name="unknown-ppid66",
            case_class="unknown-critical",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Non-DTLS N2 profile",
            provenance_class="synthetic-negative",
            notes="PPID 66 is reserved for the DTLS subset and is unsupported here",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="unknown-ppid66",
            wire_hex=unknown,
            assertions=["ppid=66", "non_dtls_profile=unsupported"],
            outcome="unsupported",
        ),
        manifest(
            subset="n2-sctp",
            name="duplicate-association-tuple",
            case_class="duplicate",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Caller association-generation uniqueness",
            provenance_class="synthetic-negative",
            notes="Repeated PPID/port tuple; generation collision is caller policy",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-association-tuple",
            wire_hex=duplicate,
            assertions=["duplicate_tuple=true"],
            outcome="caller-policy",
        ),
        manifest(
            subset="n2-sctp",
            name="ordering-port-before-ppid",
            case_class="ordering",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Metadata encoding order is not on-wire SCTP",
            provenance_class="spec-authored",
            notes="Port then PPID documents that metadata order is not a chunk order claim",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="ordering-port-before-ppid",
            wire_hex=ordered,
            assertions=["metadata_order=port-then-ppid"],
            outcome="receive",
        ),
        manifest(
            subset="n2-sctp",
            name="malformed-missing-port",
            case_class="malformed",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="PPID without the required two-octet port",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-missing-port",
            wire_hex=malformed,
            assertions=["port_absent=true"],
            outcome="reject",
        ),
        manifest(
            subset="n2-sctp",
            name="truncated-ppid",
            case_class="truncation",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="PPID truncated to three octets",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-ppid",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="n2-sctp",
            name="bounded-port-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 38.412",
            release="V18.1.0",
            clauses=["7"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Caller port-width bound",
            provenance_class="synthetic-negative",
            notes="Port field encoded as 0xffff after PPID; still a 16-bit value, used as overflow sentinel for a 15-bit caller bound",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-port-overflow",
            wire_hex=overflow,
            assertions=["port=65535", "caller_bound_exceeded=true"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "N2 SCTP fixture subset",
        """Non-DTLS N2 profile: PPID 60 and port 38412. Ordinary SCTP metadata is
not cryptographic protection. PPID 66 is reserved for `n2-dtls`.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "n2-sctp",
            fixtures,
            constructed=["PPID 60 / port 38412 association metadata", "DATA chunk header"],
            receive=["metadata order variants"],
            unsupported=["PPID 66 on this profile", "DTLS", "NGAP procedure state"],
        ),
    )
    return fixtures


def gre_qfi(subset_dir: Path) -> list[dict]:
    pos_dl = "20 00 00 00 09 00 00 80 00"
    pos_ul = "20 00 00 00 09 00 00 00 00"
    nonzero = "20 00 08 00 09 00 00 00 00"
    duplicate = "20 00 00 00 09 00 00 00 20 00 00 00 0a 00 00 00"
    ordered = "20 00 00 00 09 00 00 80 00"
    malformed = "00 00 00 00 09 00 00 00"
    truncated = "20 00 00 00 09"
    overflow = "20 00 00 00 4f 00 00 00"
    wires = [pos_dl, pos_ul, nonzero, duplicate, ordered, malformed, truncated, overflow]
    fixtures = [
        manifest(
            subset="gre-qfi",
            name="positive-downlink-rqi",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.3.2", "9.3.3"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="Child SA selected; QFI mapping is caller-owned",
            provenance_class="spec-authored",
            notes="C=0 K=1 S=0 Protocol Type 0, QFI 9, RQI indicated",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-downlink-rqi",
            wire_hex=pos_dl,
            assertions=["c=0", "k=1", "s=0", "protocol_type=0", "qfi=9", "rqi=1"],
            outcome="constructed",
        ),
        manifest(
            subset="gre-qfi",
            name="positive-uplink",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.3.2", "9.3.3"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="Same GRE profile",
            provenance_class="spec-authored",
            notes="Uplink RQI must be not-indicated",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="positive-uplink",
            wire_hex=pos_ul,
            assertions=["qfi=9", "rqi=0"],
            outcome="receive",
        ),
        manifest(
            subset="gre-qfi",
            name="receive-nonzero-protocol-type",
            case_class="unknown-critical",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.3.2", "9.3.3"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="NWu GRE profile ignore rule",
            provenance_class="synthetic-negative",
            notes="Received Protocol Type 0x0800 must be ignored, not rejected",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="receive-nonzero-protocol-type",
            wire_hex=nonzero,
            assertions=["protocol_type=0x0800", "receiver_disposition=ignore"],
            outcome="ignore",
        ),
        manifest(
            subset="gre-qfi",
            name="duplicate-key-header",
            case_class="duplicate",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.3"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="One GRE header per packet",
            provenance_class="synthetic-negative",
            notes="Two concatenated GRE headers",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-key-header",
            wire_hex=duplicate,
            assertions=["duplicate_gre_header=true"],
            outcome="reject",
        ),
        manifest(
            subset="gre-qfi",
            name="ordering-key-then-payload",
            case_class="ordering",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.3"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="RFC 2890 key field precedes payload",
            provenance_class="spec-authored",
            notes="Canonical header-then-payload order",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="ordering-key-then-payload",
            wire_hex=ordered,
            assertions=["header_before_payload=true"],
            outcome="constructed",
        ),
        manifest(
            subset="gre-qfi",
            name="malformed-missing-key",
            case_class="malformed",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.3"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="NWu profile requires K=1",
            provenance_class="synthetic-negative",
            notes="K=0 so the QFI key field is absent",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-missing-key",
            wire_hex=malformed,
            assertions=["k=0"],
            outcome="reject",
        ),
        manifest(
            subset="gre-qfi",
            name="truncated-key",
            case_class="truncation",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.3"],
            direction="ue-to-n3iwf",
            role="ue",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Key field truncated after QFI octet",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-key",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="gre-qfi",
            name="bounded-qfi-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.3.3"],
            direction="n3iwf-to-ue",
            role="n3iwf",
            prerequisite="QFI 0-63 bound",
            provenance_class="synthetic-negative",
            notes="Octet 5 value 0x4f sets reserved bits plus a value that is not a 6-bit QFI-only encoding",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-qfi-overflow",
            wire_hex=overflow,
            assertions=["reserved_bits_or_qfi_bound=true"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "NWu GRE QFI fixture subset",
        """| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `20` | C=0 K=1 S=0 |
| 1 | `00` | Reserved/Ver 0 |
| 2..3 | `00 00` | Protocol Type 0 on send |
| 4 | `09` | QFI 9 |
| 5..6 | `00 00` | Spare |
| 7 | `80` or `00` | RQI downlink-only |
| 8 | `00` | Next-header / payload terminator used by these frames |

Received nonzero Protocol Type is ignored.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "gre-qfi",
            fixtures,
            constructed=["downlink QFI+RQI", "uplink QFI without RQI"],
            receive=["nonzero Protocol Type ignored"],
            unsupported=["XFRM install", "QFI allocation", "default-fallback policy"],
        ),
    )
    return fixtures


def n3_gtpu(subset_dir: Path) -> list[dict]:
    echo_nz = "32 02 00 06 00 00 00 00 12 34 00 00 0e a5"
    ul_psc = "36 ff 00 08 00 00 00 01 00 05 00 85 01 10 09 00"
    unknown = "36 ff 00 08 11 22 33 44 00 05 00 84 01 aa bb 00"
    duplicate = "32 02 00 08 00 00 00 00 12 34 00 00 0e 00 0e 00"
    ordered = "34 fe 00 10 de ad be ef 00 00 00 85 01 00 09 00 07 01 aa bb 06 01 cc dd 00"
    malformed = "32 01 00 04 00 00 00 00 12 34"
    truncated = "32 01 00 04"
    overflow = "32 01 00 ff 00 00 00 00"
    wires = [
        GTPU_ECHO_REQUEST,
        GTPU_ECHO_RESPONSE,
        echo_nz,
        GTPU_DL_PSC,
        ul_psc,
        unknown,
        duplicate,
        ordered,
        malformed,
        truncated,
        overflow,
    ]
    fixtures = [
        manifest(
            subset="n3-gtpu",
            name="positive-echo-request",
            case_class="positive",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["4.4", "7.2.1"],
            direction="either",
            role="gtpu-endpoint",
            prerequisite="Reuse opc-proto-gtpu typed control codec from issue 341",
            provenance_class="referenced-public-vector",
            notes="Canonical Echo Request already proven in opc-proto-gtpu",
            referenced="crates/opc-proto-gtpu/tests/control_messages.rs::ECHO_REQUEST",
            sanitized=SYN_ID,
            wire_name="positive-echo-request",
            wire_hex=GTPU_ECHO_REQUEST,
            assertions=["message=echo-request", "teid=0", "sequence=0x1234"],
            outcome="constructed",
        ),
        manifest(
            subset="n3-gtpu",
            name="positive-echo-response-recovery-zero",
            case_class="positive",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["7.2.2", "8.2"],
            direction="either",
            role="gtpu-endpoint",
            prerequisite="Issue 341 Recovery=0 canonicalization",
            provenance_class="referenced-public-vector",
            notes="14-byte Echo Response with Recovery zero",
            referenced="crates/opc-proto-gtpu/tests/control_messages.rs::ECHO_RESPONSE",
            sanitized=SYN_ID,
            wire_name="positive-echo-response-recovery-zero",
            wire_hex=GTPU_ECHO_RESPONSE,
            assertions=["recovery=0", "sequence_copied=true"],
            outcome="constructed",
        ),
        manifest(
            subset="n3-gtpu",
            name="receive-recovery-ignored",
            case_class="positive",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["8.2"],
            direction="peer-to-local",
            role="gtpu-endpoint",
            prerequisite="Received Recovery is ignored and canonicalized to zero",
            provenance_class="synthetic-negative",
            notes="Echo Response Recovery 0xa5 is ignored on receive",
            referenced="crates/opc-proto-gtpu/tests/control_messages.rs",
            sanitized=SYN_ID,
            wire_name="receive-recovery-ignored",
            wire_hex=echo_nz,
            assertions=["received_recovery_ignored=true", "canonical_recovery=0"],
            outcome="receive",
        ),
        manifest(
            subset="n3-gtpu",
            name="positive-dl-psc",
            case_class="positive",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.2.2.7"],
            direction="n3-downlink",
            role="upf-to-n3iwf",
            prerequisite="Issue 341/existing PduSessionContainer downlink subset",
            provenance_class="referenced-public-vector",
            notes="DL PDU Session Container QFI 9 without PPI/RQI",
            referenced="crates/opc-proto-gtpu/tests/gtpu_tests.rs",
            sanitized=SYN_ID,
            wire_name="positive-dl-psc",
            wire_hex=GTPU_DL_PSC,
            assertions=["direction=downlink", "pdu_type=0", "qfi=9", "rqi=0"],
            outcome="receive",
        ),
        manifest(
            subset="n3-gtpu",
            name="positive-ul-psc",
            case_class="positive",
            document="3GPP TS 38.415",
            release="V18.2.0",
            clauses=["5.5.3"],
            direction="n3-uplink",
            role="n3iwf-to-upf",
            prerequisite="Uplink PSC is QFI-only; PPI/RQI forbidden",
            provenance_class="spec-authored",
            notes="UL PDU type 1 QFI 9",
            referenced="crates/opc-proto-gtpu/src/lib.rs::PduSessionContainer::new_uplink",
            sanitized=SYN_ID,
            wire_name="positive-ul-psc",
            wire_hex=ul_psc,
            assertions=["direction=uplink", "pdu_type=1", "qfi=9"],
            outcome="constructed",
        ),
        manifest(
            subset="n3-gtpu",
            name="unknown-required-extension",
            case_class="unknown-critical",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.2.1"],
            direction="n3-downlink",
            role="n3iwf",
            prerequisite="UnknownIePolicy::Reject",
            provenance_class="referenced-public-vector",
            notes="Comprehension-required unknown extension 0x84",
            referenced="crates/opc-proto-gtpu/tests/gtpu_tests.rs",
            sanitized=SYN_ID,
            wire_name="unknown-required-extension",
            wire_hex=unknown,
            assertions=["ext_type=0x84", "code=UnknownCriticalIe"],
            outcome="reject",
        ),
        manifest(
            subset="n3-gtpu",
            name="duplicate-recovery",
            case_class="duplicate",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["8.2"],
            direction="peer-to-local",
            role="gtpu-endpoint",
            prerequisite="Recovery is a singleton IE",
            provenance_class="synthetic-negative",
            notes="Echo Response with two Recovery IEs",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-recovery",
            wire_hex=duplicate,
            assertions=["duplicate_ie=recovery"],
            outcome="reject",
        ),
        manifest(
            subset="n3-gtpu",
            name="ordering-end-marker-psc-first",
            case_class="ordering",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.2.1", "7.3.2"],
            direction="n3-downlink",
            role="gtpu-endpoint",
            prerequisite="Issue 341 End Marker extension order",
            provenance_class="referenced-public-vector",
            notes="PSC first then unknown optional extensions",
            referenced="crates/opc-proto-gtpu/fuzz/corpus/decode/control_end_marker_psc_order",
            sanitized=SYN_ID,
            wire_name="ordering-end-marker-psc-first",
            wire_hex=ordered,
            assertions=["psc_first=true"],
            outcome="receive",
        ),
        manifest(
            subset="n3-gtpu",
            name="malformed-echo-request",
            case_class="malformed",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.1"],
            direction="either",
            role="gtpu-endpoint",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Declared length 4 but optional header incomplete",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-echo-request",
            wire_hex=malformed,
            assertions=["length_inconsistent=true"],
            outcome="reject",
        ),
        manifest(
            subset="n3-gtpu",
            name="truncated-header",
            case_class="truncation",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.1"],
            direction="either",
            role="gtpu-endpoint",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Four-octet header only",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-header",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="n3-gtpu",
            name="bounded-length-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 29.281",
            release="V18.4.0",
            clauses=["5.1"],
            direction="either",
            role="gtpu-endpoint",
            prerequisite="Caller datagram bound",
            provenance_class="synthetic-negative",
            notes="Length 255 over an 8-octet datagram",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-length-overflow",
            wire_hex=overflow,
            assertions=["declared_length=255"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "N3 GTP-U fixture subset",
        """Reuses issue 341 typed Echo/Recovery/PSC vectors by digest. Downlink and
uplink PDU Session Containers are direction-specific. Received Recovery is
ignored and canonicalized to zero. Issue 644 checksum-offload behavior is
dataplane runtime and is not duplicated here.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "n3-gtpu",
            fixtures,
            constructed=["Echo Request", "Echo Response Recovery 0", "uplink PSC"],
            receive=["downlink PSC", "ignored nonzero Recovery", "End Marker PSC order"],
            unsupported=["backend control port", "eBPF offload", "Tunnel Status"],
        ),
    )
    return fixtures


def protocol_key(subset_dir: Path) -> list[dict]:
    # Label bytes only. Never a key.
    positive = " ".join(
        f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-generation-1"
    )
    wrong = " ".join(
        f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-generation-2"
    )
    reuse = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-reuse")
    drop = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-drop")
    cancel = " ".join(
        f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-cancel"
    )
    unknown = " ".join(
        f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-purpose-x"
    )
    ordered = " ".join(
        f"{byte:02x}" for byte in b"opc-n3iwf-protocol-key-kat-v1-generation-1"
    )
    malformed = "ff"
    truncated = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf")
    overflow = " ".join(f"{byte:02x}" for byte in (b"opc-n3iwf-protocol-key-kat-v1-" + b"A" * 200))
    wires = [positive, wrong, reuse, drop, cancel, unknown, ordered, malformed, truncated, overflow]
    fixtures = [
        manifest(
            subset="protocol-key",
            name="positive-generation-1",
            case_class="positive",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="amf-to-n3iwf-handoff",
            role="n3iwf",
            prerequisite="Association generation 1 and pending IKE operation",
            provenance_class="synthetic-kat",
            notes="Known-answer label only; no key bytes are published",
            referenced=None,
            sanitized=NO_KEY + SYN_ID,
            wire_name="positive-generation-1",
            wire_hex=positive,
            assertions=["purpose=K_N3IWF", "generation=1", "exportable=false"],
            outcome="constructed",
        ),
        manifest(
            subset="protocol-key",
            name="wrong-generation",
            case_class="malformed",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="amf-to-n3iwf-handoff",
            role="n3iwf",
            prerequisite="Handle bound to generation 1",
            provenance_class="synthetic-kat",
            notes="Generation 2 label must not consume a generation-1 handle",
            referenced=None,
            sanitized=NO_KEY + SYN_ID,
            wire_name="wrong-generation",
            wire_hex=wrong,
            assertions=["generation=2", "consume=reject"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="reuse-after-consume",
            case_class="duplicate",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="Handle already consumed once",
            provenance_class="synthetic-kat",
            notes="Second consume is reuse and must fail closed",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="reuse-after-consume",
            wire_hex=reuse,
            assertions=["reuse=true"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="drop-zeroize",
            case_class="positive",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="Handle dropped without consume",
            provenance_class="synthetic-kat",
            notes="Drop revokes custody; label only",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="drop-zeroize",
            wire_hex=drop,
            assertions=["drop=zeroize"],
            outcome="receive",
        ),
        manifest(
            subset="protocol-key",
            name="cancellation",
            case_class="ordering",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="Pending consume cancelled",
            provenance_class="synthetic-kat",
            notes="Cancellation before consume revokes the handle",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="cancellation",
            wire_hex=cancel,
            assertions=["cancel_before_consume=true"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="unknown-purpose",
            case_class="unknown-critical",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="amf-to-n3iwf-handoff",
            role="n3iwf",
            prerequisite="Purpose must be K_N3IWF",
            provenance_class="synthetic-kat",
            notes="Unknown purpose label is rejected",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="unknown-purpose",
            wire_hex=unknown,
            assertions=["purpose=unknown"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="ordering-bind-then-consume",
            case_class="ordering",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="Bind must precede consume",
            provenance_class="synthetic-kat",
            notes="Same generation-1 label documents bind-before-consume order",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="ordering-bind-then-consume",
            wire_hex=ordered,
            assertions=["order=bind-then-consume"],
            outcome="constructed",
        ),
        manifest(
            subset="protocol-key",
            name="malformed-label",
            case_class="malformed",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Single 0xff is not a labeled KAT",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="malformed-label",
            wire_hex=malformed,
            assertions=["label_malformed=true"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="truncated-label",
            case_class="truncation",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Prefix of the KAT label",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="truncated-label",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="protocol-key",
            name="bounded-label-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 33.501",
            release="V18.12.0",
            clauses=["7.2.1"],
            direction="local",
            role="n3iwf",
            prerequisite="Caller label-length bound",
            provenance_class="synthetic-negative",
            notes="Label exceeds the documented 64-octet bound",
            referenced=None,
            sanitized=NO_KEY,
            wire_name="bounded-label-overflow",
            wire_hex=overflow,
            assertions=["label_len>64"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "Protocol-key fixture subset",
        """Synthetic known-answer labels only. No key, MSK, or K_N3IWF bytes are
published. Wrong-generation, reuse, drop, and cancellation are semantic
outcomes for issue 791.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "protocol-key",
            fixtures,
            constructed=["generation-1 consume-once label"],
            receive=["drop zeroize"],
            unsupported=["byte export", "hierarchy derivation", "authentication decision"],
        ),
    )
    return fixtures


def nas_tcp(subset_dir: Path) -> list[dict]:
    positive = "00 03 7e 00 41"
    need_more = "00 05 7e 00"
    duplicate = "00 03 7e 00 41 00 03 7e 00 41"
    ordered = "00 03 7e 00 41 00 03 7e 00 5d"
    malformed = "00 00"
    truncated = "00"
    overflow = "01 00" + " 00" * 16
    unknown = "00 03 7f 00 00"
    wires = [positive, need_more, duplicate, ordered, malformed, truncated, overflow, unknown]
    fixtures = [
        manifest(
            subset="nas-tcp",
            name="positive-envelope",
            case_class="positive",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2.4", "9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="TCP connection already established; NAS remains opaque",
            provenance_class="spec-authored",
            notes="Two-octet length 3 plus opaque 5GMM header 7e 00 41",
            referenced=None,
            sanitized=SYN_ID + NAS_OPAQUE,
            wire_name="positive-envelope",
            wire_hex=positive,
            assertions=["length=3", "complete_frame=true"],
            outcome="constructed",
        ),
        manifest(
            subset="nas-tcp",
            name="partial-need-more-data",
            case_class="truncation",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2.4", "9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="Incremental decode with caller max",
            provenance_class="synthetic-negative",
            notes="Length 5 with only two body octets remains need-more-data",
            referenced=None,
            sanitized=NAS_OPAQUE,
            wire_name="partial-need-more-data",
            wire_hex=need_more,
            assertions=["need_more_data=true", "not_eof=true"],
            outcome="need-more-data",
        ),
        manifest(
            subset="nas-tcp",
            name="duplicate-complete-frames",
            case_class="duplicate",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="Stream may carry more than one envelope",
            provenance_class="spec-authored",
            notes="Two complete frames; first is valid and the second remains buffered",
            referenced=None,
            sanitized=NAS_OPAQUE,
            wire_name="duplicate-complete-frames",
            wire_hex=duplicate,
            assertions=["first_frame_complete=true", "trailing_frame_buffered=true"],
            outcome="receive",
        ),
        manifest(
            subset="nas-tcp",
            name="ordering-two-message-types",
            case_class="ordering",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["8.2.4", "9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="Stream order is the only order",
            provenance_class="spec-authored",
            notes="Registration-request-shaped then identity-request-shaped opaque headers",
            referenced=None,
            sanitized=NAS_OPAQUE,
            wire_name="ordering-two-message-types",
            wire_hex=ordered,
            assertions=["stream_order_preserved=true"],
            outcome="receive",
        ),
        manifest(
            subset="nas-tcp",
            name="malformed-zero-length",
            case_class="malformed",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Length zero is not a NAS message",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-zero-length",
            wire_hex=malformed,
            assertions=["length=0"],
            outcome="reject",
        ),
        manifest(
            subset="nas-tcp",
            name="truncated-length-octet",
            case_class="truncation",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="One length octet is still need-more-data, not a final reject",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-length-octet",
            wire_hex=truncated,
            assertions=["need_more_data=true"],
            outcome="need-more-data",
        ),
        manifest(
            subset="nas-tcp",
            name="bounded-length-overflow",
            case_class="bounded-overflow",
            document="3GPP TS 24.502",
            release="V18.8.0",
            clauses=["9.4"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="Caller-selected maximum 256",
            provenance_class="synthetic-negative",
            notes="Length 256 exceeds a 256-byte caller max that excludes the envelope header",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-length-overflow",
            wire_hex=overflow,
            assertions=["length=256", "caller_max=256", "finalization=reject"],
            outcome="reject",
        ),
        manifest(
            subset="nas-tcp",
            name="unknown-epd",
            case_class="unknown-critical",
            document="3GPP TS 24.501",
            release="R18",
            clauses=["9.1.1"],
            direction="either",
            role="nas-tcp-endpoint",
            prerequisite="Envelope is complete; inner NAS EPD is opaque to the framer",
            provenance_class="synthetic-negative",
            notes="EPD 0x7f is unknown to NAS; the TCP envelope itself is complete",
            referenced="crates/opc-proto-nas/CONFORMANCE.md",
            sanitized=NAS_OPAQUE,
            wire_name="unknown-epd",
            wire_hex=unknown,
            assertions=["envelope_complete=true", "inner_nas=opaque-or-reject-by-nas-codec"],
            outcome="receive",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "NAS-over-TCP fixture subset",
        """Two-octet length precedes an opaque NAS PDU. A partial prefix remains
need-more-data until a complete frame, EOF/loss, or bounded finalization.
A complete first frame plus a trailing partial or complete frame is valid
buffered input.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "nas-tcp",
            fixtures,
            constructed=["complete two-octet envelope"],
            receive=["two-frame stream", "unknown inner EPD left opaque"],
            unsupported=["TCP listen", "reconnect", "security termination", "UE lifecycle"],
        ),
    )
    return fixtures


def xfrm_roster(subset_dir: Path) -> list[dict]:
    positive = "01 00 00 01 0a 0b 0c 0d 0a 0b 0c 0e"
    overlap = "01 00 00 02 0a 0b 0c 0d 0a 0b 0c 0f"
    rekey = "01 00 00 03 0a 0b 0c 11 0a 0b 0c 12"
    relocate = "01 00 00 04 0a 0b 0c 0d 0a 0b 0c 0e"
    unknown = "01 00 00 01 ff 00 00 00 0a 0b 0c 0e"
    duplicate = "01 00 00 01 0a 0b 0c 0d 0a 0b 0c 0d"
    ordered = "01 00 00 01 0a 0b 0c 0d 0a 0b 0c 0e 02 00 00 02 0a 0b 0c 11 0a 0b 0c 12"
    malformed = "00 00 00 01 0a 0b 0c 0d"
    truncated = "01 00 00 01 0a 0b"
    overflow = "01 ff ff ff 0a 0b 0c 0d 0a 0b 0c 0e"
    wires = [
        positive,
        overlap,
        rekey,
        relocate,
        unknown,
        duplicate,
        ordered,
        malformed,
        truncated,
        overflow,
    ]
    fixtures = [
        manifest(
            subset="xfrm-roster",
            name="positive-single-pair",
            case_class="positive",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Reuse durable roster primitives; IKE notifies are in nwu-ike",
            provenance_class="synthetic-kat",
            notes="Generation 1 inbound/outbound synthetic SPI pair; no key material",
            referenced="crates/opc-ipsec-xfrm/src/durable_roster.rs",
            sanitized=SYN_ID + NO_KEY,
            wire_name="positive-single-pair",
            wire_hex=positive,
            assertions=["generation=1", "inbound_spi_label=0x0a0b0c0d", "overlap=false"],
            outcome="constructed",
        ),
        manifest(
            subset="xfrm-roster",
            name="overlap-rekey",
            case_class="positive",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Caller-selected overlapping Child SAs",
            provenance_class="synthetic-kat",
            notes="Generation 2 adds a second inbound SPI while generation 1 remains",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="overlap-rekey",
            wire_hex=overlap,
            assertions=["overlap=true", "ike_notify_parsing=out-of-scope"],
            outcome="constructed",
        ),
        manifest(
            subset="xfrm-roster",
            name="rekey-new-pair",
            case_class="ordering",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Old pair remains until caller retires it",
            provenance_class="synthetic-kat",
            notes="Generation 3 replacement pair",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="rekey-new-pair",
            wire_hex=rekey,
            assertions=["rekey=true", "order=install-new-then-retire-old"],
            outcome="constructed",
        ),
        manifest(
            subset="xfrm-roster",
            name="relocation",
            case_class="positive",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.23"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Authenticated relocation authority; source address is not authority",
            provenance_class="synthetic-kat",
            notes="Same SPI pair under generation 4 after roster relocation",
            referenced="crates/opc-ipsec-xfrm/tests/xfrm_sa_relocation_recovery_privileged.rs",
            sanitized=SYN_ID + NO_KEY,
            wire_name="relocation",
            wire_hex=relocate,
            assertions=["relocation=true", "source_address_observation=not-authority"],
            outcome="receive",
        ),
        manifest(
            subset="xfrm-roster",
            name="unknown-inbound-spi",
            case_class="unknown-critical",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Exact inbound SA provenance required",
            provenance_class="synthetic-negative",
            notes="Inbound SPI 0xff000000 is not in the roster",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="unknown-inbound-spi",
            wire_hex=unknown,
            assertions=["inbound_spi_unknown=true"],
            outcome="reject",
        ),
        manifest(
            subset="xfrm-roster",
            name="duplicate-spi",
            case_class="duplicate",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Inbound and outbound SPI must differ unless explicitly overlapped",
            provenance_class="synthetic-negative",
            notes="Inbound and outbound SPI labels are identical",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-spi",
            wire_hex=duplicate,
            assertions=["duplicate_spi=true"],
            outcome="reject",
        ),
        manifest(
            subset="xfrm-roster",
            name="ordering-old-then-new",
            case_class="ordering",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="One generation admits both pairs during overlap",
            provenance_class="synthetic-kat",
            notes="Generation 1 pair followed by generation 2 pair",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="ordering-old-then-new",
            wire_hex=ordered,
            assertions=["order=old-then-new"],
            outcome="receive",
        ),
        manifest(
            subset="xfrm-roster",
            name="malformed-version",
            case_class="malformed",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Version 0 is not the synthetic roster record version",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-version",
            wire_hex=malformed,
            assertions=["version=0"],
            outcome="reject",
        ),
        manifest(
            subset="xfrm-roster",
            name="truncated-record",
            case_class="truncation",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Record ends inside the inbound SPI",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-record",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="xfrm-roster",
            name="bounded-generation-overflow",
            case_class="bounded-overflow",
            document="IETF RFC 7296",
            release="RFC 7296",
            clauses=["2.8"],
            direction="local-backend",
            role="xfrm-backend",
            prerequisite="Caller generation bound",
            provenance_class="synthetic-negative",
            notes="Generation 0xffffff exceeds a 16-bit caller bound",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-generation-overflow",
            wire_hex=overflow,
            assertions=["generation=16777215"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "XFRM roster fixture subset",
        """Backend overlap, SPI provenance, rekey, and authenticated relocation.
IKE notify/create/modify/delete/mobility bytes live in `nwu-ike`. Records
contain only version, generation, and synthetic SPI labels.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "xfrm-roster",
            fixtures,
            constructed=["single pair", "overlap", "rekey"],
            receive=["relocation", "old-then-new order"],
            unsupported=["PDU/QFI policy", "IKE notify parsing", "key material"],
        ),
    )
    return fixtures


def n2_dtls(subset_dir: Path) -> list[dict]:
    positive = "00 00 00 42"
    hello = (
        "16 fe fd 00 00 00 00 00 00 00 00 00 0c "
        "01 00 00 00 00 00 00 00 00 00 00 00"
    )
    identity = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-dtls-expected-peer")
    auth = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-sctp-auth-kat-len-64")
    rekey = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-dtls-rekey-generation-2")
    restart = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-dtls-path-failure")
    unknown = "00 00 00 3c"
    duplicate = "00 00 00 42 00 00 00 42"
    ordered = "00 00 00 42 " + hello
    malformed = "16 03 03 00 00"
    truncated = "16 fe fd"
    overflow = "16 fe fd ff ff"
    redacted = " ".join(f"{byte:02x}" for byte in b"opc-n3iwf-dtls-error-redacted")
    wires = [
        positive,
        hello,
        identity,
        auth,
        rekey,
        restart,
        unknown,
        duplicate,
        ordered,
        malformed,
        truncated,
        overflow,
        redacted,
    ]
    fixtures = [
        manifest(
            subset="n2-dtls",
            name="positive-ppid66",
            case_class="positive",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Reuse public SDK DTLS/SCTP machinery; PPID 66 is not a security flag",
            provenance_class="spec-authored",
            notes="NGAP over DTLS/SCTP uses PPID 66",
            referenced="crates/opc-sctp/src/lib.rs",
            sanitized=SYN_ID + NO_KEY,
            wire_name="positive-ppid66",
            wire_hex=positive,
            assertions=["ppid=66", "protection_required=true"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-dtls",
            name="positive-handshake-header",
            case_class="positive",
            document="IETF RFC 6347",
            release="RFC 6347",
            clauses=["4.1"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Identity is a typed expected-peer label, not a certificate dump",
            provenance_class="synthetic-kat",
            notes="DTLS 1.2 record plus 12-octet handshake header; fragment length 0",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="positive-handshake-header",
            wire_hex=hello,
            assertions=[
                "content_type=handshake",
                "version=dtls-1.2",
                "record_length=12",
                "handshake_type=client_hello",
                "fragment_length=0",
            ],
            outcome="constructed",
        ),
        manifest(
            subset="n2-dtls",
            name="positive-identity-label",
            case_class="positive",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="local",
            role="n3iwf",
            prerequisite="Identity is a typed expected-peer label, not a certificate dump",
            provenance_class="synthetic-kat",
            notes="Expected-peer identity label only; no certificate or exporter secret",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="positive-identity-label",
            wire_hex=identity,
            assertions=["identity=expected-peer-label", "material_published=false"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-dtls",
            name="sctp-auth-length",
            case_class="positive",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4.4"],
            direction="local",
            role="n3iwf",
            prerequisite="opc-sctp SctpAuthKey::for_rfc6083 requires 64-octet exporter",
            provenance_class="synthetic-kat",
            notes="Length/label only; exporter secret is not published",
            referenced="crates/opc-sctp/src/lib.rs::SctpAuthKey::for_rfc6083",
            sanitized=NO_KEY,
            wire_name="sctp-auth-length",
            wire_hex=auth,
            assertions=["exporter_len=64", "material_published=false"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-dtls",
            name="rekey-generation-2",
            case_class="ordering",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4.4"],
            direction="local",
            role="n3iwf",
            prerequisite="Key id rotation wraps 65535 to 1",
            provenance_class="synthetic-kat",
            notes="Rekey/rotation generation label",
            referenced="crates/opc-sctp/src/lib.rs",
            sanitized=NO_KEY,
            wire_name="rekey-generation-2",
            wire_hex=rekey,
            assertions=["rekey=true", "generation=2"],
            outcome="receive",
        ),
        manifest(
            subset="n2-dtls",
            name="restart-path-failure",
            case_class="positive",
            document="IETF RFC 4960",
            release="RFC 4960",
            clauses=["6.4"],
            direction="local",
            role="n3iwf",
            prerequisite="Path failure is a transport event, not an NGAP cause",
            provenance_class="synthetic-kat",
            notes="Restart/path-failure label without peer addresses",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="restart-path-failure",
            wire_hex=restart,
            assertions=["path_failure=true", "peer_address_published=false"],
            outcome="receive",
        ),
        manifest(
            subset="n2-dtls",
            name="unknown-ppid60",
            case_class="unknown-critical",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="Protected profile cannot be built from ordinary SctpAssociation",
            provenance_class="synthetic-negative",
            notes="PPID 60 is the unprotected N2 profile and cannot satisfy DTLS",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="unknown-ppid60",
            wire_hex=unknown,
            assertions=["ppid=60", "dtls_profile=unsupported"],
            outcome="unsupported",
        ),
        manifest(
            subset="n2-dtls",
            name="duplicate-ppid66",
            case_class="duplicate",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="One PPID per association profile",
            provenance_class="synthetic-negative",
            notes="Repeated PPID 66 metadata",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="duplicate-ppid66",
            wire_hex=duplicate,
            assertions=["duplicate_ppid=true"],
            outcome="caller-policy",
        ),
        manifest(
            subset="n2-dtls",
            name="ordering-ppid-then-handshake",
            case_class="ordering",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="n3iwf-to-amf",
            role="n3iwf",
            prerequisite="PPID selected before handshake bytes are admitted",
            provenance_class="spec-authored",
            notes="PPID 66 followed by the handshake header",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="ordering-ppid-then-handshake",
            wire_hex=ordered,
            assertions=["order=ppid-then-handshake"],
            outcome="constructed",
        ),
        manifest(
            subset="n2-dtls",
            name="malformed-tls-version",
            case_class="malformed",
            document="IETF RFC 6347",
            release="RFC 6347",
            clauses=["4.1"],
            direction="peer-to-local",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="TLS 1.2 record version is not DTLS",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="malformed-tls-version",
            wire_hex=malformed,
            assertions=["version=tls-1.2"],
            outcome="reject",
        ),
        manifest(
            subset="n2-dtls",
            name="truncated-record",
            case_class="truncation",
            document="IETF RFC 6347",
            release="RFC 6347",
            clauses=["4.1"],
            direction="peer-to-local",
            role="n3iwf",
            prerequisite="None",
            provenance_class="synthetic-negative",
            notes="Record header truncated before length",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="truncated-record",
            wire_hex=truncated,
            assertions=["truncated=true"],
            outcome="reject",
        ),
        manifest(
            subset="n2-dtls",
            name="bounded-record-overflow",
            case_class="bounded-overflow",
            document="IETF RFC 6347",
            release="RFC 6347",
            clauses=["4.1"],
            direction="peer-to-local",
            role="n3iwf",
            prerequisite="Caller record-size bound",
            provenance_class="synthetic-negative",
            notes="DTLS length 0xffff over a five-octet header",
            referenced=None,
            sanitized=SYN_ID,
            wire_name="bounded-record-overflow",
            wire_hex=overflow,
            assertions=["declared_length=65535"],
            outcome="reject",
        ),
        manifest(
            subset="n2-dtls",
            name="redacted-error",
            case_class="malformed",
            document="IETF RFC 6083",
            release="RFC 6083",
            clauses=["4"],
            direction="local",
            role="n3iwf",
            prerequisite="Errors expose only stable labels",
            provenance_class="synthetic-kat",
            notes="Bounded redacted-error label; no peer, cert, or packet bytes",
            referenced=None,
            sanitized=SYN_ID + NO_KEY,
            wire_name="redacted-error",
            wire_hex=redacted,
            assertions=["error_redacted=true", "no_peer_or_cert_bytes=true"],
            outcome="reject",
        ),
    ]
    for item, wire in zip(fixtures, wires, strict=True):
        dump_manifest(subset_dir, item, wire)
    write_readme(
        subset_dir,
        "N2 DTLS fixture subset",
        """PPID 66, handshake/identity labels, SCTP-AUTH length, rekey, restart,
and redacted errors. Ordinary PPID 60 associations cannot satisfy this
subset. No certificates or exporter secrets are published.
""",
    )
    write_completion(
        subset_dir,
        completion(
            "n2-dtls",
            fixtures,
            constructed=["PPID 66", "handshake header", "expected-peer identity label", "SCTP-AUTH length label"],
            receive=["rekey", "path failure"],
            unsupported=["PPID 60 as protection", "NGAP procedure state", "certificate dumps"],
        ),
    )
    return fixtures


def read_existing_publication() -> dict | None:
    path = FIXTURE_ROOT / "PUBLIC_SDK.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def write_publication(existing: dict | None = None) -> None:
    prior = existing if existing is not None else read_existing_publication()
    head = "landing-revision"
    tree = ""
    if prior:
        prior_head = prior.get("head")
        prior_tree = prior.get("tree")
        if isinstance(prior_head, str) and prior_head:
            head = prior_head
        if isinstance(prior_tree, str):
            tree = prior_tree
    payload = {
        "repository": "https://github.com/openpacketcore/openpacketcore-sdk",
        "base": PUBLIC_BASE,
        "head": head,
        "tree_path": "crates/opc-n3iwf-fixtures/fixtures",
        "tree": tree,
        "interoperability_note": (
            "Round trips alone do not prove external interoperability. "
            "These contracts publish constructed, receive, and unsupported "
            "outcomes with fixture provenance and digests only."
        ),
    }
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    (FIXTURE_ROOT / "PUBLIC_SDK.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def stamp_publication_from_git() -> None:
    """Record the public HEAD commit and fixtures tree after they exist."""
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{FIXTURE_ROOT.relative_to(ROOT).as_posix()}"],
        cwd=ROOT,
        text=True,
    ).strip()
    write_publication({"head": head, "tree": tree})


def generate() -> dict[str, list[dict]]:
    existing_publication = read_existing_publication()
    if FIXTURE_ROOT.exists():
        for path in FIXTURE_ROOT.rglob("*"):
            if path.is_file():
                path.unlink()
    writers = {
        "eap5g": eap5g,
        "nwu-ike": nwu_ike,
        "ngap": ngap,
        "n2-sctp": n2_sctp,
        "gre-qfi": gre_qfi,
        "n3-gtpu": n3_gtpu,
        "protocol-key": protocol_key,
        "nas-tcp": nas_tcp,
        "xfrm-roster": xfrm_roster,
        "n2-dtls": n2_dtls,
    }
    generated: dict[str, list[dict]] = {}
    for name, writer in writers.items():
        generated[name] = writer(FIXTURE_ROOT / name)
    write_publication(existing_publication)
    return generated


def check() -> int:
    expected = generate()
    errors = 0
    required = {
        "positive",
        "malformed",
        "duplicate",
        "unknown-critical",
        "ordering",
        "truncation",
        "bounded-overflow",
    }
    for subset, fixtures in expected.items():
        classes = {item["case_class"] for item in fixtures}
        missing = required - classes
        if missing:
            print(f"{subset}: missing {sorted(missing)}", file=sys.stderr)
            errors += 1
        if any(item["runtime_claim"] for item in fixtures):
            print(f"{subset}: runtime_claim must be false", file=sys.stderr)
            errors += 1
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--stamp-git", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        generated = generate()
        assert len(generated) == 10
        assert "eap5g" in generated
        print("generate-n3iwf-fixtures self-test ok")
        return 0
    if args.check:
        return check()
    if args.stamp_git:
        stamp_publication_from_git()
        print("stamped PUBLIC_SDK.json from git HEAD")
        return 0
    generate()
    print(f"wrote fixtures under {FIXTURE_ROOT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

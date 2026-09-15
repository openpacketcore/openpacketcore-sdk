"""Independent Release 18 NGAP oracle, using no SDK codec or fixture writer.

The schema is compiled from the hash-pinned ETSI publication, never from the
SDK's generated Rust or Pycrate's bundled (different-release) NGAP module.
Only our synthetic recipes and their wire results belong in the repository.
Downloaded specifications and generated reference modules stay in a temporary
directory. This test tool does not implement a product protocol boundary.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import importlib.util
import io
import re
from pathlib import Path

SPEC_URL = "https://www.etsi.org/deliver/etsi_ts/138400_138499/138413/18.10.00_60/ts_138413v181000p.pdf"
SPEC_SHA256 = "21617ad6dd826e05a0e8356ef96f44199cf4c7bc1be65e6b915e9135e10b59e2"
MAX_SPEC_BYTES = 8 * 1024 * 1024
MAX_WIRE_BYTES = 65535
VERSIONS = {"pycrate": "0.8.1", "pypdf": "6.1.0"}

# Exact, counted PDF layout repairs, not ASN.1 changes. The three comment
# continuations are on the AMFCPRelocationIndicationIEs page. All other repairs
# remove a space or line break inside an existing identifier/keyword. Hashes
# below cover all six complete modules after these repairs.
REPAIRS = (
    (1, "mandator y", "mandatory", 1),
    (1, "mandat ory", "mandatory", 1),
    (1, "manda tory", "mandatory", 1),
    (1, "optiona l", "optional", 2),
    (1, "--this IE is not used and \nignored", "--this IE is not used and ignored", 3),
    (
        1,
        "MBSSessionSetupOrModFailureTran sfer",
        "MBSSessionSetupOrModFailureTransfer",
        1,
    ),
    (
        1,
        "MBS-\nDistributionSetupUnsuccessfulTransfer",
        "MBS-DistributionSetupUnsuccessfulTransfer",
        1,
    ),
    (2, "optiona l", "optional", 2),
    (2, "opti onal", "optional", 1),
    (2, "op tional", "optional", 2),
    (2, "optio nal", "optional", 1),
    (2, "opt ional", "optional", 1),
    (2, "conditi onal", "conditional", 1),
    (
        2,
        "UserLocationInformationN3IWF-without-PortNumbe r",
        "UserLocationInformationN3IWF-without-PortNumber",
        1,
    ),
)
MODULE_SHA256 = (
    "4d4ad2431161e708186b5c20a1e790a75a1e3c21663aab5c210129da0b4b8310",
    "d070cd86d0059e962b6ca52d8fc8ee888309e5e980c31fc4226f532b243e384d",
    "81d0b42c391a6bf26c07bcce4e0a9d4e2717bfb53001ffa39371160fb9fdc70b",
    "8dda2cfe90eef534341a59ec0e7c889eca9d238783d90d0575bad007b7d5924b",
    "8892a9fe2b9a2e18c8b9d510778cbbedd0b01dd4807986966d75845f494da977",
    "912bc1e36a5ef5b2f8ca487c4981708adabf27cec3fafe1f03a71bd57d5962ea",
)


class Invalid(ValueError):
    """A constant reason; never include a wire value or compiler exception."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Invalid(reason)


def extract_modules(pdf: bytes) -> list[str]:
    """Verify the source before invoking a PDF parser; check every repair."""
    from pypdf import PdfReader

    require(len(pdf) <= MAX_SPEC_BYTES, "spec-size")
    require(hashlib.sha256(pdf).hexdigest() == SPEC_SHA256, "spec-digest")
    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
    blocks = re.findall(r"-- ASN1START(.*?)-- ASN1STOP", text, re.S)
    require(len(blocks) == 6, "spec-modules")
    blocks = [
        "\n".join(
            line
            for line in block.splitlines()
            if line.strip() != "ETSI" and not line.startswith("ETSI TS 138 413")
        )
        for block in blocks
    ]
    for index, old, new, count in REPAIRS:
        require(blocks[index].count(old) == count, "spec-layout")
        blocks[index] = blocks[index].replace(old, new)
    require(
        tuple(hashlib.sha256(block.encode()).hexdigest() for block in blocks)
        == MODULE_SHA256,
        "spec-module-digest",
    )
    return blocks


def compile_reference(pdf: bytes, directory: Path):
    """Compile strictly, with the reference tool's constraint checks enabled."""
    for package, version in VERSIONS.items():
        require(importlib.metadata.version(package) == version, "reference-version")
    from pycrate_asn1c.asnproc import PycrateGenerator, compile_text, generate_modules

    compile_text(extract_modules(pdf))
    path = directory / "NGAPRelease18.py"
    generate_modules(PycrateGenerator, str(path))
    spec = importlib.util.spec_from_file_location("NGAPRelease18", path)
    require(spec is not None and spec.loader is not None, "reference-module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return Reference(module)


def unpack(value, depth: int = 0):
    """Convert the small, explicit recipe notation to ASN.1 values."""
    require(depth <= 32, "recipe-depth")
    if isinstance(value, list):
        require(len(value) <= 256, "recipe-list")
        return [unpack(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if set(value) == {"hex"}:
            require(
                isinstance(value["hex"], str) and len(value["hex"]) <= 8192,
                "recipe-octets",
            )
            return bytes.fromhex(value["hex"])
        if set(value) == {"bits", "length"}:
            require(
                type(value["length"]) is int and 1 <= value["length"] <= 256,
                "recipe-bits",
            )
            number = int(value["bits"], 16)
            require(0 <= number < 1 << value["length"], "recipe-bits")
            return number, value["length"]
        if set(value) == {"type", "value"}:
            return value["type"], unpack(value["value"], depth + 1)
        return {key: unpack(item, depth + 1) for key, item in value.items()}
    require(type(value) in (str, int), "recipe-value")
    return value


class Reference:
    """APER plus the explicitly enumerated N3IWF corpus admission rules."""

    def __init__(self, schema):
        self.schema = schema
        self.pdu = schema.NGAP_PDU_Descriptions.NGAP_PDU
        self.procedures = {}
        procedures = schema.NGAP_PDU_Descriptions.NGAP_ELEMENTARY_PROCEDURES.get_val()
        for row in procedures.root + (procedures.ext or []):
            for choice, field in (
                ("initiatingMessage", "InitiatingMessage"),
                ("successfulOutcome", "SuccessfulOutcome"),
                ("unsuccessfulOutcome", "UnsuccessfulOutcome"),
            ):
                if field in row:
                    name = row[field]._typeref.called[1]
                    self.procedures[name] = (
                        choice,
                        row["procedureCode"],
                        row["criticality"],
                    )

    def rows(self, name: str) -> list[dict]:
        module = (
            self.schema.NGAP_IEs
            if name.endswith("Transfer")
            else self.schema.NGAP_PDU_Contents
        )
        for suffix in ("IEs", "_IEs"):
            obj = getattr(module, name + suffix, None)
            if obj is not None:
                values = obj.get_val()
                return values.root + (values.ext or [])
        raise Invalid("reference-ie-set")

    def encode(self, value) -> bytes:
        try:
            self.pdu.set_val(copy.deepcopy(value))
            return self.pdu.to_aper()
        except Exception:
            raise Invalid("asn1-value") from None

    def encoded_fields(self, value) -> list[dict]:
        """Independent open-type bytes for checking the SDK's typed IE view."""
        name, body = value[1]["value"]
        rows = {row["id"]: row for row in self.rows(name)}
        result = []
        for field in body["protocolIEs"]:
            if field["id"] in rows:
                obj = rows[field["id"]]["Value"]
                obj.set_val(copy.deepcopy(field["value"][1]))
                raw = obj.to_aper()
            else:
                raw = field["value"][1]
            result.append(
                {
                    "id": field["id"],
                    "criticality": field["criticality"],
                    "value_hex": raw.hex(),
                }
            )
        return result

    def decode(self, wire: bytes, max_ies: int = 256):
        require(0 < len(wire) <= MAX_WIRE_BYTES, "wire-bound")
        try:
            self.pdu.from_aper(wire)
            value = copy.deepcopy(self.pdu.get_val())
            require(self.pdu.to_aper() == wire, "aper-canonical-or-trailing")
        except Invalid:
            raise
        except Exception:
            raise Invalid("aper-decode") from None
        choice, outer = value
        name, body = outer["value"]
        require(name in self.procedures, "procedure")
        require(
            (choice, outer["procedureCode"], outer["criticality"])
            == self.procedures[name],
            "procedure-criticality",
        )
        self.validate_container(name, body, max_ies)
        self.validate_n3iwf(name, body)
        return value

    def validate_container(self, name: str, body: dict, max_ies: int) -> None:
        fields = body["protocolIEs"]
        require(len(fields) <= max_ies, "ie-bound")
        rows = {row["id"]: row for row in self.rows(name)}
        seen = set()
        for field in fields:
            ident = field["id"]
            require(ident not in seen, "duplicate-ie")
            seen.add(ident)
            if ident not in rows:
                require(field["criticality"] != "reject", "unknown-critical-ie")
                continue
            row = rows[ident]
            require(field["criticality"] == row["criticality"], "ie-criticality")
            require(field["value"][0] == row["Value"]._typeref.called[1], "inner-ie")
            self.validate_nested(field["value"])
        require(
            all(
                row["id"] in seen
                for row in rows.values()
                if row["presence"] == "mandatory"
            ),
            "missing-mandatory-ie",
        )

    def validate_nested(self, value) -> None:
        if isinstance(value, tuple) and isinstance(value[0], str):
            name, body = value
            if isinstance(body, dict) and "protocolIEs" in body:
                self.validate_container(name, body, 256)
                if name == "PDUSessionResourceSetupRequestTransfer":
                    self.validate_session_setup(body)
            else:
                self.validate_nested(body)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key.endswith("Transfer"):
                    # Pycrate can retain a malformed CONTAINING value as opaque
                    # octets. A successful outer decode must not admit those.
                    require(
                        isinstance(item, tuple) and isinstance(item[0], str),
                        "nested-transfer",
                    )
                self.validate_nested(item)
        elif isinstance(value, list):
            sessions = [
                item["pDUSessionID"]
                for item in value
                if isinstance(item, dict) and "pDUSessionID" in item
            ]
            require(len(sessions) == len(set(sessions)), "duplicate-session")
            for item in value:
                self.validate_nested(item)

    @staticmethod
    def validate_session_setup(body: dict) -> None:
        fields = {field["id"]: field["value"][1] for field in body["protocolIEs"]}
        flows = fields[136]
        qfis = [flow["qosFlowIdentifier"] for flow in flows]
        require(len(qfis) == len(set(qfis)), "duplicate-qfi")
        for flow in flows:
            characteristics = flow["qosFlowLevelQosParameters"]["qosCharacteristics"]
            # The synthetic corpus uses standardized non-GBR 5QI 9 only.
            # Other QoS profiles need their own reviewed conditional evidence.
            require(
                characteristics[0] == "nonDynamic5QI"
                and characteristics[1]["fiveQI"] == 9,
                "reference-qos-profile",
            )
        # TS 38.413 8.2.1.4: omission fails the corresponding session; it
        # cannot be admitted as a successful non-GBR session setup.
        require(130 in fields, "missing-session-ambr")

    def validate_n3iwf(self, name: str, body: dict) -> None:
        known = {row["id"] for row in self.rows(name)}
        fields = {
            field["id"]: field["value"][1]
            for field in body["protocolIEs"]
            if field["id"] in known
        }
        if name == "NGSetupRequest":
            require(fields[27][0] == "globalN3IWF-ID", "global-node-kind")
        if 121 in fields:
            location = fields[121]
            require(
                location[0] == "userLocationInformationN3IWF-with-PortNumber"
                or (location[0] == "choice-Extensions" and location[1]["id"] == 439),
                "location-kind",
            )
        if name == "PDUSessionResourceSetupResponse":
            require(75 in fields or 58 in fields, "missing-resource-result")
        # TS 38.413 9.2.2.1: C-ifPDUsessionResourceSetup applies whenever
        # the initial context request includes PDU session resources.
        if name == "InitialContextSetupRequest" and 71 in fields:
            require(110 in fields, "missing-ue-ambr")
        for success, failed in ((72, 55), (75, 58)):
            if success in fields and failed in fields:
                accepted = {item["pDUSessionID"] for item in fields[success]}
                rejected = {item["pDUSessionID"] for item in fields[failed]}
                require(accepted.isdisjoint(rejected), "conflicting-resource-result")

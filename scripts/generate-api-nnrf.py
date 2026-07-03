#!/usr/bin/env python3
"""
Generate Rust types for opc-api-nnrf from 3GPP OpenAPI YAML specifications.

This is a focused pilot generator for TS 29.510 (Nnrf_NFManagement) covering
NfProfile and NfService.  It resolves $refs, maps OpenAPI primitive types to
Rust, and emits serde-friendly structs with camelCase renaming.

Usage:
    python3 scripts/generate-api-nnrf.py --output crates/opc-api-nnrf/src/types.rs

Determinism: fields are emitted in alphabetical order; enum variants are emitted
in the order declared in the YAML.  Inputs are pinned by content hash
(EXPECTED_HASHES): a fetched or cached file that does not match the recorded
SHA-256 aborts generation, so identical inputs always produce bit-identical
output.  Files are fetched once into target/api-codegen-cache/ and subsequent
runs are fully offline.

Requires: Python 3.9+ and PyYAML (`pip install pyyaml`). Cargo builds never
run this script; types.rs is committed and only regenerated explicitly via
`make generate-api`.
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Any, Optional, Set

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "error: PyYAML is required to regenerate the API types "
        "(pip install pyyaml). Cargo builds do not need it.\n"
    )
    raise SystemExit(1)

BASE_URL = "https://raw.githubusercontent.com/jdegre/5GC_APIs/master/"
# Inputs are pinned by content hash, not by URL: whatever BASE_URL serves is
# verified against EXPECTED_HASHES and generation aborts on any mismatch
# (e.g. when upstream master moves on). To bump the 3GPP release: delete
# target/api-codegen-cache/, refresh EXPECTED_HASHES from the new files, and
# review the regenerated diff.
FILES = [
    "TS29510_Nnrf_NFManagement.yaml",
    "TS29571_CommonData.yaml",
]

# Expected SHA-256 hashes for the pinned revision (computed once and recorded).
EXPECTED_HASHES = {
    "TS29510_Nnrf_NFManagement.yaml": "db7dfebd6b084c17d623736265e3d171c8369af83a05e9a1455776ba9569b2fc",
    "TS29571_CommonData.yaml": "ada4343f25dd182400bf2fb5aa4c5563fbc50675dbe8618e11c4a0ed47f28b31",
}

# Map external $refs to opc-types re-exports or plain Rust primitives.
EXTERNAL_TYPE_MAP: dict[str, str] = {
    "TS29571_CommonData.yaml#/components/schemas/NfInstanceId": "opc_types::NfInstanceId",
    # PlmnId and ExtSnssai use object-form serde wrappers (TS 29.571
    # {mcc,mnc} and {sst,sd}) so generated types interoperate with conformant
    # NRF peers instead of emitting OpenPacketCore's compact string form.
    "TS29571_CommonData.yaml#/components/schemas/PlmnId": "crate::serde_3gpp::NnrfPlmnId",
    "TS29571_CommonData.yaml#/components/schemas/ExtSnssai": "crate::serde_3gpp::NnrfSnssai",
    "TS29571_CommonData.yaml#/components/schemas/Ipv4Addr": "String",
    "TS29571_CommonData.yaml#/components/schemas/Ipv6Addr": "String",
    "TS29571_CommonData.yaml#/components/schemas/Fqdn": "String",
    "TS29571_CommonData.yaml#/components/schemas/DateTime": "String",
    "TS29571_CommonData.yaml#/components/schemas/UriScheme": "String",
    "TS29571_CommonData.yaml#/components/schemas/SupportedFeatures": "String",
    "TS29571_CommonData.yaml#/components/schemas/NfServiceSetId": "String",
    "TS29571_CommonData.yaml#/components/schemas/Nid": "String",
    "TS29571_CommonData.yaml#/components/schemas/Uri": "String",
    "TS29571_CommonData.yaml#/components/schemas/PlmnIdNid": "String",
    "TS29571_CommonData.yaml#/components/schemas/ChangeItem": "serde_json::Value",
}

# Local refs that we generate as primitive or local types.
LOCAL_PRIMITIVE_MAP: dict[str, str] = {
    "#/components/schemas/NFType": "NfType",
    "#/components/schemas/NFStatus": "NfStatus",
    "#/components/schemas/NFServiceStatus": "NfServiceStatus",
    "#/components/schemas/ServiceName": "String",
    "#/components/schemas/NFServiceVersion": "NfServiceVersion",
    "#/components/schemas/IpEndPoint": "IpEndPoint",
    "#/components/schemas/CallbackUriPrefixItem": "String",
    "#/components/schemas/DefaultNotificationSubscription": "String",
    "#/components/schemas/PlmnSnssai": "PlmnSnssai",
    "#/components/schemas/RuleSet": "String",
    "#/components/schemas/VendorId": "u32",
    "#/components/schemas/VendorSpecificFeature": "String",
    "#/components/schemas/PlmnOauth2": "String",
    "#/components/schemas/SelectionConditions": "String",
    "#/components/schemas/UdrInfo": "serde_json::Value",
    "#/components/schemas/UdmInfo": "serde_json::Value",
    "#/components/schemas/AusfInfo": "serde_json::Value",
    "#/components/schemas/AmfInfo": "serde_json::Value",
    "#/components/schemas/SmfInfo": "serde_json::Value",
    "#/components/schemas/CollocatedNfInstance": "String",
    # v0 expansion: NFManagement subscription/notification payloads.
    "#/components/schemas/NotificationEventType": "NotificationEventType",
    "#/components/schemas/ConditionEventType": "ConditionEventType",
    "#/components/schemas/NotifCondition": "NotifCondition",
    "#/components/schemas/SubscrCond": "serde_json::Value",
    "#/components/schemas/LocalityDescription": "serde_json::Value",
    "#/components/schemas/SubscriptionContext": "serde_json::Value",
    "#/components/schemas/ProfileChange": "serde_json::Value",
    "#/components/schemas/SharedData": "serde_json::Value",
}


def fetch_yaml(name: str, cache_dir: Path) -> Any:
    path = cache_dir / name
    if path.exists():
        return parse_verified_yaml(name, path.read_bytes())

    url = BASE_URL + name
    import urllib.request

    print(f"Downloading {url} ...", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = resp.read()

    parsed = parse_verified_yaml(name, data)

    cache_dir.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

    return parsed


def parse_verified_yaml(name: str, data: bytes) -> Any:
    expected = EXPECTED_HASHES.get(name)
    if expected is None:
        raise SystemExit(f"error: missing expected SHA-256 for {name}")

    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"error: hash mismatch for {name}: expected {expected}, got {actual}"
        )

    return yaml.safe_load(data.decode("utf-8"))


def resolve_ref(ref_str: str, docs: dict) -> Any:
    """Resolve a $ref string against the loaded documents."""
    if "#" not in ref_str:
        raise ValueError(f"Unsupported ref format: {ref_str}")

    file_part, path_part = ref_str.split("#", 1)
    doc = docs[file_part] if file_part else list(docs.values())[0]
    segments = [s for s in path_part.split("/") if s]
    node = doc
    for seg in segments:
        node = node[seg]
    return node


def rust_type_for(
    schema: Any,
    docs: dict[str, Any],
    required: bool = True,
    in_ref: Optional[Set[str]] = None,
) -> str:
    """Map an OpenAPI schema fragment to a Rust type string."""
    if in_ref is None:
        in_ref = set()

    if isinstance(schema, dict):
        if "$ref" in schema:
            ref = schema["$ref"]
            if ref in EXTERNAL_TYPE_MAP:
                ty = EXTERNAL_TYPE_MAP[ref]
            elif ref in LOCAL_PRIMITIVE_MAP:
                ty = LOCAL_PRIMITIVE_MAP[ref]
            else:
                # Try to resolve and inline a simple object ref.
                resolved = resolve_ref(ref, docs)
                ref_name = ref.split("/")[-1]
                if ref in in_ref:
                    # Recursive reference; punt to serde_json::Value for pilot.
                    ty = "serde_json::Value"
                else:
                    in_ref = in_ref.union({ref})
                    ty = rust_type_for(resolved, docs, required=True, in_ref=in_ref)
            return f"Option<{ty}>" if not required else ty

        schema_type = schema.get("type")
        if schema_type == "string":
            return f"Option<String>" if not required else "String"
        if schema_type == "integer":
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum == 0 and maximum == 65535:
                ty = "u16"
            elif minimum == 0 and maximum == 100:
                ty = "u8"
            elif minimum == 0 and maximum == 4294967295:
                ty = "u32"
            else:
                ty = "i64"
            return f"Option<{ty}>" if not required else ty
        if schema_type == "boolean":
            return f"Option<bool>" if not required else "bool"
        if schema_type == "array":
            item_ty = rust_type_for(schema.get("items", {}), docs, required=True, in_ref=in_ref)
            vec_ty = f"Vec<{item_ty}>"
            return f"Option<{vec_ty}>" if not required else vec_ty
        if schema_type == "object":
            if "additionalProperties" in schema:
                # Map type; pilot maps to serde_json::Value for simplicity.
                val_ty = rust_type_for(
                    schema["additionalProperties"], docs, required=True, in_ref=in_ref
                )
                map_ty = f"std::collections::HashMap<String, {val_ty}>"
                return f"Option<{map_ty}>" if not required else map_ty
            # Untyped object
            return f"Option<serde_json::Value>" if not required else "serde_json::Value"

        # anyOf with enum + string fallback
        any_of = schema.get("anyOf", schema.get("oneOf", []))
        if any_of and len(any_of) == 2:
            first, second = any_of[0], any_of[1]
            if (
                isinstance(first, dict)
                and first.get("type") == "string"
                and "enum" in first
                and isinstance(second, dict)
                and second.get("type") == "string"
            ):
                # This is an extensible string enum; caller should have handled
                # it by generating an enum type.  Here we just return the enum name.
                return "String"

    return "serde_json::Value"


def to_pascal_case(name: str) -> str:
    """Convert a SCREAMING_SNAKE_CASE or kebab-case string to PascalCase."""
    parts = name.replace("-", "_").split("_")
    result = []
    for p in parts:
        if p == "5G":
            result.append("FiveG")
        elif p:
            result.append(p.capitalize())
    return "".join(result)


def doc_comment(text: Optional[str], fallback: str, indent: str = "") -> list[str]:
    """Render a rustdoc comment from an OpenAPI description, wrapping long
    lines; falls back to a generated sentence when the schema has none."""
    content = " ".join((text or fallback).split())
    lines: list[str] = []
    line = ""
    for word in content.split(" "):
        candidate = f"{line} {word}".strip()
        if len(candidate) > 72 and line:
            lines.append(f"{indent}/// {line}")
            line = word
        else:
            line = candidate
    if line:
        lines.append(f"{indent}/// {line}")
    return lines


def emit_enum(name: str, schema: Any, docs: dict[str, Any]) -> list[str]:
    """Emit Rust enum for an anyOf [enum, string] schema."""
    lines: list[str] = []
    lines.extend(
        doc_comment(
            schema.get("description"),
            f"`{name}` enumeration generated from 3GPP TS 29.510.",
        )
    )
    lines.append("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]")
    lines.append('#[serde(rename_all = "SCREAMING_SNAKE_CASE")]')
    lines.append(f"pub enum {name} {{")

    any_of = schema.get("anyOf", schema.get("oneOf", []))
    variants: list[tuple[str, str]] = []
    for alt in any_of:
        if isinstance(alt, dict) and alt.get("type") == "string" and "enum" in alt:
            for val in alt["enum"]:
                variants.append((to_pascal_case(val), val))

    for v, wire in variants:
        lines.extend(doc_comment(None, f"Wire value `{wire}`.", indent="    "))
        lines.append(f"    {v},")

    # Add catch-all for extensible enums.
    lines.extend(
        doc_comment(
            None,
            "Forward-compatibility catch-all for values not in this release.",
            indent="    ",
        )
    )
    lines.append("    #[serde(untagged)]")
    lines.append("    Other(String),")
    lines.append("}")
    lines.append("")
    return lines


def to_snake_case(name: str) -> str:
    """Convert a camelCase or PascalCase string to snake_case."""
    result = []
    for i, ch in enumerate(name):
        if ch.isupper():
            if i > 0 and name[i - 1].islower():
                result.append("_")
            elif i > 0 and i + 1 < len(name) and name[i + 1].islower():
                result.append("_")
            result.append(ch.lower())
        else:
            result.append(ch)
    return "".join(result)


def sanitize_ident(name: str) -> str:
    """Sanitize an OpenAPI property name into a valid Rust identifier."""
    name = to_snake_case(name)
    if name[0].isdigit():
        name = "_" + name
    return name


def emit_struct(name: str, schema: Any, docs: dict[str, Any]) -> list[str]:
    """Emit Rust struct for an object schema."""
    lines: list[str] = []
    lines.extend(
        doc_comment(
            schema.get("description"),
            f"`{name}` generated from the 3GPP TS 29.510 OpenAPI schema.",
        )
    )
    lines.append("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]")
    lines.append('#[serde(rename_all = "camelCase")]')
    lines.append(f"pub struct {name} {{")

    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    for prop_name in sorted(props.keys()):
        prop_schema = props[prop_name]
        is_required = prop_name in required
        ty = rust_type_for(prop_schema, docs, required=is_required)
        rust_name = sanitize_ident(prop_name)
        requirement = "Mandatory" if is_required else "Optional"
        lines.extend(
            doc_comment(
                prop_schema.get("description") if isinstance(prop_schema, dict) else None,
                f"{requirement} `{prop_name}` attribute per TS 29.510.",
                indent="    ",
            )
        )
        lines.append(f"    pub {rust_name}: {ty},")

    lines.append("}")
    lines.append("")
    return lines


def generate_types(docs: dict[str, Any]) -> list[str]:
    """Generate the full types.rs content."""
    lines: list[str] = []
    lines.append("// Auto-generated by scripts/generate-api-nnrf.py")
    lines.append("// Do not edit manually.  Re-run `make generate-api`.")
    lines.append("")
    lines.append("use serde::{Deserialize, Serialize};")
    lines.append("")

    # Generate local enums first.
    enum_schemas = {
        "NfType": "#/components/schemas/NFType",
        "NfStatus": "#/components/schemas/NFStatus",
        "NfServiceStatus": "#/components/schemas/NFServiceStatus",
        # v0 expansion: subscription/notification event types.
        "NotificationEventType": "#/components/schemas/NotificationEventType",
        "ConditionEventType": "#/components/schemas/ConditionEventType",
    }
    for rust_name, ref_path in enum_schemas.items():
        schema = resolve_ref(ref_path, docs)
        lines.extend(emit_enum(rust_name, schema, docs))

    # Generate supporting structs that NFProfile/NFService depend on.
    # For the pilot we keep these minimal.
    support_structs = {
        "NfServiceVersion": "#/components/schemas/NFServiceVersion",
        "IpEndPoint": "#/components/schemas/IpEndPoint",
        "PlmnSnssai": "#/components/schemas/PlmnSnssai",
        # v0 expansion: notification condition.
        "NotifCondition": "#/components/schemas/NotifCondition",
    }
    for rust_name, ref_path in support_structs.items():
        schema = resolve_ref(ref_path, docs)
        lines.extend(emit_struct(rust_name, schema, docs))

    # Generate main target structs.
    nf_profile = resolve_ref("#/components/schemas/NFProfile", docs)
    nf_service = resolve_ref("#/components/schemas/NFService", docs)
    subscription_data = resolve_ref("#/components/schemas/SubscriptionData", docs)
    notification_data = resolve_ref("#/components/schemas/NotificationData", docs)
    lines.extend(emit_struct("NfProfile", nf_profile, docs))
    lines.extend(emit_struct("NfService", nf_service, docs))
    lines.extend(emit_struct("SubscriptionData", subscription_data, docs))
    lines.extend(emit_struct("NotificationData", notification_data, docs))

    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate opc-api-nnrf types")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("crates/opc-api-nnrf/src/types.rs"),
        help="Path to write generated types.rs",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("target/api-codegen-cache"),
        help="Directory to cache downloaded YAML files",
    )
    args = parser.parse_args()

    docs: dict[str, Any] = {}
    for name in FILES:
        docs[name] = fetch_yaml(name, args.cache_dir)

    lines = generate_types(docs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Generated {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

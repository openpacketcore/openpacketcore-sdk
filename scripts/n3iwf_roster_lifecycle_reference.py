#!/usr/bin/env python3
"""Independent ordinal schedules for the existing durable object-roster contract.

This model imports no SDK/runtime/catalog writer. Its ordered acquisition and
reverse compensation obligations come from the published SDK contract, not a
recording of the implementation. These are backend schedules, not IKE packets,
installed Child-SA selection, packet provenance or whole-roster relocation.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crates/opc-n3iwf-fixtures/oracles/roster-lifecycle.json"
TABLE = "crates/opc-ipsec-xfrm/tests/fixtures/roster-lifecycle.tsv"
SCOPE = "durable-object-roster-lifecycle"
PREFIX = "opc.n3iwf.xfrm-roster.v1.lifecycle-"
CONTRACT = "crates/opc-ipsec-xfrm/README.md"
START = "## Durable grouped object roster restart recovery\n"
END = "## Opaque outbound-SA binding\n"
# Filled from the independently reviewed, unchanged contract section.
CONTRACT_DIGEST = "fa4a43b1605dc427b5e4de5310b8247df4b6317b73616240fa1199fd621ead05"
FAMILIES = (
    "finalize", "adopt", "recover-applied", "recover-prepared",
    "sweep-failure", "foreign-conflict", "install-failure",
    "issuing-before", "issuing-after",
)
COLUMNS = (
    "name", "layout", "trigger", "ordinal", "admit_effect", "before_phase",
    "run_outcome", "installs", "run_removes", "before_present", "before_members",
    "finish_operation", "finish_outcome", "finish_removes", "final_present",
    "final_members", "repeated_outcome",
)


class Invalid(Exception):
    """A bounded, value-free reference refusal."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def cases():
    records = []
    for shape in ("sa", "policy", "mixed"):
        for count in range(1, 9):
            layout = ("s" * count if shape == "sa" else "p" * count
                      if shape == "policy" else ("sp" * count)[:count])
            for family in FAMILIES:
                for ordinal in (range(count) if family in FAMILIES[4:] else [-1]):
                    name = f"{family}-{shape}-{count}" + (f"-{ordinal}" if ordinal >= 0 else "")
                    row = dict(name=name, layout=layout, trigger=family, ordinal=ordinal,
                        admit_effect=family == "issuing-after", before_phase="applied",
                        run_outcome="applied", installs=list(range(count)), run_removes=[],
                        before_present=[1] * count, before_members=["acquired"] * count,
                        finish_operation="recover", finish_outcome="owned_residue_retired",
                        finish_removes=list(reversed(range(count))), final_present=[0] * count,
                        final_members=["retired"] * count, repeated_outcome="retired")
                    if family in ("finalize", "adopt"):
                        row.update(finish_operation=family,
                            finish_outcome="committed" if family == "finalize" else "adopted",
                            finish_removes=[], final_present=[1] * count,
                            final_members=["acquired"] * count, repeated_outcome="committed")
                    elif family in ("recover-prepared", "sweep-failure"):
                        row.update(before_phase="prepared", run_outcome="not-run" if family == "recover-prepared"
                            else "xfrm_object_roster_issue_pre_effect_readback", installs=[],
                            before_present=[0] * count, before_members=["pending"] * count,
                            finish_outcome="no_mutation", finish_removes=[], final_members=["pending"] * count)
                    elif family == "foreign-conflict":
                        present = [int(i == ordinal) for i in range(count)]
                        row.update(before_phase="no_mutation", run_outcome="no_mutation", installs=[],
                            before_present=present, before_members=["pending"] * count,
                            finish_outcome="foreign_untouched", finish_removes=[],
                            final_present=present, final_members=["pending"] * count)
                    elif family == "install-failure":
                        members = ["retired" if i < ordinal else "no_mutation" if i == ordinal
                                   else "pending" for i in range(count)]
                        row.update(before_phase="rolled_back", run_outcome="rolled_back",
                            installs=list(range(ordinal + 1)), run_removes=list(reversed(range(ordinal))),
                            before_present=[0] * count, before_members=members,
                            finish_outcome="rolled_back", finish_removes=[], final_members=members)
                    elif family in ("issuing-before", "issuing-after"):
                        acquired = ordinal + int(row["admit_effect"])
                        row.update(before_phase="issuing", run_outcome="cut",
                            installs=list(range(acquired)), before_present=[int(i < acquired) for i in range(count)],
                            before_members=["acquired" if i < ordinal else "pending" for i in range(count)],
                            finish_outcome="rolled_back", finish_removes=list(reversed(range(acquired))),
                            final_members=["retired" if i < acquired else "no_mutation" if i == ordinal
                                           else "pending" for i in range(count)])
                    records.append(row)
    assert len(records) == 636 and len({r["name"] for r in records}) == 636
    return records


def contract_bytes():
    source = (ROOT / CONTRACT).read_text()
    return (START + source.split(START, 1)[1].split(END, 1)[0]).encode()


def reference_bytes():
    value = dict(schema_version=1, scope=SCOPE,
        policy="Existing SDK durable object roster, bounded to eight members; not a wire-standard requirement",
        contract=dict(path=CONTRACT, start=START.strip(), end=END.strip(), sha256=CONTRACT_DIGEST),
        limitations=["scripted backend and real authenticated store", "no packet authentication or live selection",
                     "no complete Child-SA roster relocation", "separate Linux crash-cut qualification"],
        cases=cases())
    return (json.dumps(value, indent=2) + "\n").encode()


def table_bytes():
    def cell(value):
        if isinstance(value, list):
            return ",".join(str(v) for v in value) or "-"
        if isinstance(value, bool):
            return str(int(value))
        return str(value)
    rows = ["# Independent SDK roster obligations; synthetic ordinals only.", "# " + "\t".join(COLUMNS)]
    rows += ["\t".join(cell(row[key]) for key in COLUMNS) for row in cases()]
    return ("\n".join(rows) + "\n").encode()


def wire(family):
    require(family in FAMILIES, "roster-reference-family")
    selected = [row for row in cases() if row["trigger"] == family]
    return (json.dumps(dict(family=family, cases=selected), sort_keys=True, separators=(",", ":")) + "\n").encode()


def check_sources():
    require(hashlib.sha256(contract_bytes()).hexdigest() == CONTRACT_DIGEST, "roster-contract-digest")


def validate(manifest, data):
    source = manifest["context"]["source_vector"]
    require(source["path"] == SOURCE and set(source) == {"path", "sha256", "case"}, "roster-reference-path")
    require(source["sha256"] == hashlib.sha256(reference_bytes()).hexdigest(), "roster-reference-digest")
    family = source["case"]
    require(family in FAMILIES and manifest["sdk_fixture_id"] == PREFIX + family, "roster-reference-family")
    require(data == wire(family), "roster-reference-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(data).hexdigest(), "roster-wire-digest")
    count = sum(row["trigger"] == family for row in cases())
    context = dict(source_vector=source, schedules=count, sdk_store_validation=True,
        backend="scripted", kernel_validation=False, packet_provenance=False, complete_roster_relocation=False)
    require(json.dumps(manifest["context"], sort_keys=True) == json.dumps(context, sort_keys=True), "roster-reference-context")
    require(manifest["encoding"] == "scenario-record" and manifest["validation_scope"] == SCOPE, "roster-reference-scope")
    require(manifest["source"] == dict(document="IETF RFC 7296", release="RFC 7296",
        clauses=["1.3", "2.8", "SDK durable grouped object roster recovery contract"]), "roster-reference-authority")
    require(manifest["semantic_assertions"] == ["family=" + family, "schedules=" + str(count),
        "sdk_store_validation=true", "backend=scripted", "kernel_validation=false",
        "packet_provenance=false", "complete_roster_relocation=false"], "roster-reference-claims")
    require(manifest["direction"] == "local-backend" and manifest["role"] == "xfrm-backend", "roster-reference-direction")
    require(manifest["provenance"]["referenced_public_vector"] == SOURCE + "#" + family
        and manifest["provenance"]["class"] == "referenced-public-vector"
        and manifest["provenance"]["synthetic"] is True
        and manifest["provenance"]["independent_capture"] is False, "roster-reference-provenance")
    require(manifest["expected_outcome"] == "constructed" and manifest["runtime_claim"] is False, "roster-reference-outcome")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        check_sources()
        for relative, data in ((SOURCE, reference_bytes()), (TABLE, table_bytes())):
            target = ROOT / relative
            require(not target.is_symlink(), "roster-reference-path")
            if args.write:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            else:
                require(target.read_bytes() == data, "roster-reference-content")
        if args.check:
            directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/xfrm-roster"
            observed = set()
            for path in directory.glob("lifecycle-*.json"):
                require(not path.is_symlink(), "roster-catalog-path")
                manifest = json.loads(path.read_text())
                require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "roster-catalog-path")
                payload = directory / manifest["wire"]["path"]
                require(not payload.is_symlink(), "roster-catalog-path")
                validate(manifest, bytes.fromhex(payload.read_text()))
                require(manifest["sdk_fixture_id"] not in observed, "roster-reference-duplicate")
                observed.add(manifest["sdk_fixture_id"])
            require(observed == {PREFIX + family for family in FAMILIES}, "roster-reference-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_roster_reference_mismatch")
        return 1
    print(f"n3iwf_roster_reference_valid: {len(cases())} independent schedules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Independent complete-roster obligations; synthetic states, never IKE packets.

This model imports no SDK, runtime trace, fixture writer or sibling oracle.
The reviewed ordered-mutation contract defines three selected outgoing policies,
three distinct incoming policies, four pairs (one receive-only predecessor),
and eight directional SAs. Native packet/process evidence is qualified separately.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "docs/n3-child-sa-mobike.md"
START = "## Ordered mutation contract\n"
END = "## Durable recovery\n"
CONTRACT_DIGEST = "f7977dc983eca152eb9218e6e5d084e6e61e3302948915e3a400df6578ca1037"
SOURCE = "crates/opc-n3iwf-fixtures/oracles/child-sa-relocation.json"
TABLE = "crates/opc-ipsec-xfrm/tests/fixtures/child-sa-relocation.tsv"
SCOPE = "complete-child-sa-roster-relocation"
FAMILIES = ("complete", "mutation-before", "mutation-after", "read-before", "read-after",
            "foreign-member", "missing-member", "mixed-members", "revoked")
COLUMNS = ("name", "family", "old_udp", "new_udp", "ordinal", "after", "prefix", "sa_mask", "policies", "writes", "recovery_writes", "outcome")


def state(cut):
    """Contract order, expressed without runtime step indexes or implementation IO."""
    migrated = min(max(cut - 3, 0), 8)
    policies = []
    for child in range(3):
        policies.append(2 if cut >= 12 + child else 0)
        policies.append(2 if cut >= 15 + child else 1 if cut >= 1 + child else 0)
    return (1 << migrated) - 1, "".join(map(str, policies))


def cases():
    records = []
    for old in (False, True):
        for new in (False, True):
            def add(family, ordinal, after, cut, writes, outcome, mask=None, policies=None):
                expected_mask, expected_policies = state(cut) if cut >= 0 else (-1, "-")
                records.append(dict(name=f"{family}-{int(old)}{int(new)}-{ordinal}", family=family,
                    old_udp=old, new_udp=new, ordinal=ordinal, after=after, prefix=cut,
                    sa_mask=expected_mask if mask is None else mask,
                    policies=expected_policies if policies is None else policies,
                    writes=writes, recovery_writes=17-cut if cut >= 0 else -1, outcome=outcome))
            add("complete", -1, False, 17, 17, "complete")
            # A sweep has eight logical complete-SA reads and six policy reads;
            # Linux tests additionally fail each constituent netlink query.
            for after in (False, True):
                for effect in range(17):
                    cut = effect + int(after)
                    add("mutation-after" if after else "mutation-before", effect*15+14,
                        after, cut, cut, "interrupted")
                for cut in range(18):
                    for resource in range(14):
                        add("read-after" if after else "read-before", cut*15+resource,
                            after, cut, cut, "interrupted")
            for family in ("foreign-member", "missing-member"):
                for resource in range(14):
                    add(family, resource, False, -1, 0, "repair")
            for mask in range(256):
                # Independently characterize an initial run of set bits.
                valid = mask & (mask + 1) == 0
                cut = 3 + mask.bit_count() if valid else -1
                add("mixed-members", mask, False, cut, 0,
                    "observed" if valid else "repair", mask=mask, policies="010101")
            for cut in range(18):
                add("revoked", cut, False, cut, cut, "authentication")
    return records


def contract_bytes():
    raw = (ROOT / CONTRACT).read_text()
    return raw[raw.index(START):raw.index(END)].encode()


def reference_bytes():
    value = dict(schema_version=1, scope=SCOPE,
        contract=dict(path=CONTRACT, start=START.strip(), end=END.strip(), sha256=CONTRACT_DIGEST),
        limitations=["synthetic complete-roster obligations", "no runtime or packet capture imported",
                     "three distinct inbound policies; shared-policy kernel profile qualified separately",
                     "caller namespace writer and application-send exclusion"], columns=COLUMNS,
        cases=[[row[key] for key in COLUMNS] for row in cases()])
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def table_bytes():
    def cell(value):
        return str(int(value)) if isinstance(value, bool) else str(value)
    rows = ["# Independent complete-roster obligations from the reviewed contract.", "# " + "\t".join(COLUMNS)]
    rows += ["\t".join(cell(row[key]) for key in COLUMNS) for row in cases()]
    return ("\n".join(rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        assert hashlib.sha256(contract_bytes()).hexdigest() == CONTRACT_DIGEST
        assert len(cases()) == 3364 and len({row["name"] for row in cases()}) == 3364
        for name, data in ((SOURCE, reference_bytes()), (TABLE, table_bytes())):
            path = ROOT / name
            assert not path.is_symlink()
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            else:
                assert path.read_bytes() == data
    except (OSError, ValueError, AssertionError):
        print("n3iwf_child_sa_relocation_reference_mismatch")
        return 1
    print("n3iwf_child_sa_relocation_reference_valid: 3364 independent schedules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

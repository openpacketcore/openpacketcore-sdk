"""Independently authored Error Indication identity/message recipes.

The caller encodes the recipes through the unmodified pinned Release 18 schema.
No SDK codec or catalog writer is imported. Signalling context and error basis
remain independent of the reported identity (TS 38.413 8.7.5, 9.2.6.13).
"""
import copy


def identity_cases(record, make, entries, field, cause):
    def identity(amf_set, pointer, tmsi):
        return dict(aMFSetID=(amf_set, 10), aMFPointer=(pointer, 6),
                    **{"fiveG-TMSI": tmsi})

    kind = "ErrorIndication"
    sample = identity(731, 41, b"\x01\x02\x03\x04")
    for signalling in ("non-ue", "ue"):
        for amf_set in (0, 1, 511, 512, 1023):
            for pointer in (0, 1, 31, 32, 63):
                for tmsi in (b"\x00" * 4, b"\x01\x02\x03\x04", b"\xff" * 4):
                    values = [(15, cause), (26, identity(amf_set, pointer, tmsi))]
                    if signalling == "ue":
                        values += [(10, 0x8123456789), (85, 0x87654321)]
                    record(f"identity-{signalling}-{amf_set}-{pointer}-{tmsi.hex()}",
                           make(kind, values), signalling=signalling)
        # The identity substitutes neither an error basis nor either UE ID.
        for ids in range(4):
            for basis in range(4):
                values = [(26, sample)]
                if ids & 1:
                    values.append((10, 7))
                if ids & 2:
                    values.append((85, 257))
                if basis & 1:
                    values.append((15, cause))
                if basis & 2:
                    values.append((19, {}))
                record(f"identity-context-{signalling}-{ids}-{basis}", make(kind, values),
                       basis != 0 and (signalling == "non-ue" or ids == 3),
                       "signalling", signalling)

    base = make(kind, [(15, cause), (26, sample)])
    for criticality in ("reject", "notify"):
        changed = copy.deepcopy(base)
        next(v for v in entries(changed) if v["id"] == 26)["criticality"] = criticality
        record("identity-criticality-" + criticality, changed, False, "identity-criticality")
    duplicate = copy.deepcopy(base)
    entries(duplicate).append(field(kind, 26, identity(1023, 63, b"\xff" * 4)))
    record("identity-duplicate", duplicate, False, "identity-duplicate")
    for criticality in ("reject", "ignore", "notify"):
        changed = copy.deepcopy(base)
        entries(changed).append(dict(id=65530, criticality=criticality,
                                    value=("_unk_004", b"\xff\x00")))
        record("identity-unknown-" + criticality, changed,
               criticality != "reject", "unknown", criticality=criticality)

    # Canonical seven-octet leaf taken from the schema recipe above. Mutate the
    # bounded open type independently; the reference decoder must reject or
    # fail canonical re-encoding, even with a fresh enclosing length/digest.
    packed = ((731 << 6) | 41) << 6
    leaf = packed.to_bytes(3, "big") + b"\x01\x02\x03\x04"
    mutations = [("truncated-" + str(end), leaf[:end]) for end in range(7)]
    mutations.append(("trailing", leaf + b"\x00"))
    for offset, masks in ((0, (0x80, 0x40)), (2, (1, 2, 4, 8, 16, 32))):
        for mask in masks:
            wire = bytearray(leaf)
            wire[offset] |= mask
            mutations.append((f"flags-{offset}-{mask}", bytes(wire)))
    for name, wire in mutations:
        changed = copy.deepcopy(base)
        next(v for v in entries(changed) if v["id"] == 26)["value"] = ("_unk_004", wire)
        record("identity-malformed-" + name, changed, False, "identity-malformed")

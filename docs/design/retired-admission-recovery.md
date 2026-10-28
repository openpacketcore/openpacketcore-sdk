# Retired admission witnesses

The selective-absence part of [#1306](https://github.com/openpacketcore/openpacketcore-sdk/issues/1306)
preserves conclusive recovery for an admission whose original fence is above
all physically retired admissions. The witness does not discharge an unresolved
provider or publication obligation.

## Durable contract

`GlobalChargeWitness` version 3 retains two independent unsigned scalars:

- `retired_terminal_sequence` proves the existing globally ordered terminal
  retirement prefix.
- `highest_retired_admission_fence` is the maximum original admission fence of
  every physically removed V1 or V2 roster.

For one atomic deletion batch `D`, the second scalar changes as follows:

```text
H_after = max(H_before, original_admission_fence(r) for every r in D)
```

The original fence comes from validated compact admission/terminal provenance.
The terminal writer's fence, terminal sequence and admission log index do not
substitute for it. Lower fences retiring later leave the maximum unchanged;
several rosters may share a fence. This is one fixed-size scalar, with no
per-completion allocation or increment.

Fresh activation persists an explicit zero witness. Reactivation, reopen and
recovery cannot reinterpret a missing witness as virgin history. Ordinary
admission, terminalization and payload compaction preserve the maximum. Physical
retirement updates it with the row deletion, counters and floor/cursor actions
in the same transaction, including deletion of the last row and partition.

The common mixed V1/V2 planner and the alternate partition planner both retain
the maximum. Native generation reconstruction authenticates each removed carrier,
including a roster created and removed within one generation, and checks the
exact resulting maximum. A rewritten base preserves the scalar without deriving
it from surviving rows. SQLite/native export, import and replacement preserve
it; snapshots cannot omit it, lower it, or omit a local tombstone whose original
fence exceeds the incoming witness.

## Recovery decision

The existing linearizable barrier, exact original key and scope, and live
strictly newer successor lease remain prerequisites. The slot lookup and witness
are read from the same state image.

| Validated state | Result |
| --- | --- |
| Exact retained admission or terminal | Existing exact readback |
| Absent slot and original fence greater than the maximum | `AdmissionRecordMissing` |
| Absent slot and original fence at or below the maximum | `RecoveryHistoryUnavailable` |
| Missing, unsupported or corrupt witness | Storage/recovery error |
| Invalid scope, key, lease or barrier | Existing authority/barrier failure |

A missing result creates no execution, publication or provider-release authority.
The comparison uses the retained original identity, not a substituted successor
identity. Ordinary lease acquisition advances the global frontier; expected-fence
acquisition can instead allocate a newer lease below an unrelated retired maximum.
The latter remains inconclusive, irrespective of elapsed time.

## Format and operations

Both activation profiles bind the witness policy. V1's frozen admission payload
and profile digest remain unchanged; its activation voter digest includes the
new policy. V2's storage compatibility digest includes it. Unsupported witness
bytes and old activation authority are refused. Crossing this stored-format
boundary requires a fresh installation.

Valid state survives crash/reopen and snapshot reconstruction. No new startup
cleanup or operator repair procedure is introduced. Shutdown, drain and rollout
behavior are unchanged.

## Remaining recovery work

An absent original fence at or below the maximum can remain inconclusive even
when that particular admission never committed. Automatic discharge needs an
independent authenticated exclusion contract covering provider, aggregate and
publication effects. This witness does not implement that contract or the
recovery-only retirement operation described in
[#1298](https://github.com/openpacketcore/openpacketcore-sdk/issues/1298), and does
not establish completion of all #1306 acceptance criteria.

## Verification

Focused regressions exercise out-of-order/shared fences, both roster profiles,
a full retirement batch followed by deletion of the last floor, original versus
terminal-writer authority, SQLite and native cold reopen, coalesced native
creation/deletion, compacted bases, export/import and snapshot replacement.
Controls cover below/equal fences, later expected-fence lease allocation,
missing/unsupported witness state, reactivation after witness loss, and altered
native generation maxima with recomputed outer checksums.

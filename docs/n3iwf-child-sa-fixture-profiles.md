# Installed Child-SA fixture references

The `xfrm-roster` subset adds fifteen
`installed-child-sa-evidence-reference` records: 3,364 independent relocation
model projections and 89 authored obligations for separately executed SDK
tests. They supplement the original SPI labels and 636 durable object-roster
schedules. The original records retain their original scope.

| Family | Cases | Evidence referenced |
| --- | ---: | --- |
| `installed-selection` | 16 | Three children, two flows each, both directions, default, rekey, reinstall and foreign policy |
| `inbound-provenance` | 16 | Exact pair/publication/source-event binding, monitor scope, replay/ICV, rekey and teardown |
| `publication-fencing` | 12 | Whole-roster reads, keys, stale writers, cancellation, generation exhaustion and capability refusal |
| `mobike-authority` | 11 | Live IKE scope/event/path/mode, revocation, actor ownership and caller cancellation |
| `native-relocation` | 2 | Native ESP and ESP-in-UDP; four pairs and seven outgoing flows |
| `process-recovery` | 32 | Both profiles at every prefix 0–15, with two separate processes per case |
| `relocation-complete` | 4 | All old/new encapsulation combinations |
| `relocation-mutation-before`, `relocation-mutation-after` | 68 each | Failure on either side of every modeled effect |
| `relocation-read-before`, `relocation-read-after` | 1,008 each | Failure on either side of every modeled member read |
| `relocation-foreign-member`, `relocation-missing-member` | 56 each | Foreign or absent members at the modeled read boundaries |
| `relocation-mixed-members` | 1,024 | Every old/new directional-SA mixture in four encapsulation profiles |
| `relocation-revoked` | 72 | Live authority loss at every whole-roster step |

The independent reference is
`crates/opc-n3iwf-fixtures/oracles/child-sa-profiles.json`, SHA-256
`b092689801a0f85e2d32580ee5ab66b9a103291aa5db36baaf55d815504b3f55`.
It pins the complete relocation model, SHA-256
`f3d39a95e5fc6f4fb29e25d847d9a3901b6d300cb566ab2efefab4ce7a3994af`,
and six test sources. A projection identifies its exact source row, name and
outcome; its digest-bound source retains every model column. Compact references
keep each catalog file within the existing 256 KiB loader limit. The reference
imports neither SDK code, the fixture writer nor runtime traces.

The model has four pairs, three distinct inbound policies and seventeen ordered
effects. The native process-loss profile deduplicates a shared inbound policy
and has fifteen effects. The different counts describe different declared
profiles; neither is substituted for the other.

The referenced public runtime revision is feature base
`58acdfe9afc1cd0b5c7d2fc9a0d1f01bed4325d6`, head
`1c7012e6667a29f27d1100f3492dff5cc2c05d34`, root tree
`1de2e42f567031052e26322d0f581b87993180b2`.
[PR #952](https://github.com/openpacketcore/openpacketcore-sdk/pull/952)
retains the separate runtime qualification, building on
[#950](https://github.com/openpacketcore/openpacketcore-sdk/pull/950) and
[#951](https://github.com/openpacketcore/openpacketcore-sdk/pull/951).
Catalog publication has its own base, content head and fixture tree in
`fixtures/PUBLIC_SDK.json`; these are distinct from the runtime revision.

Every new record keeps `runtime_claim=false`, `execution_claim=false`,
`grants_authority=false`, `requires_separate_runtime_qualification=true` and
`external_interoperability=false`. Source function lookup and ordinary ignored
test runs do not establish execution. A constructed outcome means the reference
record was constructed; it grants no packet, writer or migration authority.

The [installed roster contract](n3-installed-child-sa-roster.md) admits at most
32 pairs and 256 classes with exact full-mask marks and explicit default
selection. Its sealed observations cover bounded ESP-in-UDP source events,
not every packet. The [MOBIKE contract](n3-child-sa-mobike.md) separately admits
at most eight pairs, requires caller-owned IKE trust and writer/send exclusion,
and publishes only a complete freshly verified roster. Those are SDK bounds.
The supported native qualification uses IPv4 synthetic traffic on a pinned
migration-enabled kernel; precise unsupported results remain on other kernels.
IPv6/cross-family native movement, concurrent sends during movement, complete
IKE_AUTH trust, external peer interoperability and deployment certification
remain outside this evidence.

```bash
python3 scripts/n3iwf_child_sa_relocation_reference.py --check
python3 scripts/n3iwf_child_sa_profile_reference.py --check
python3 scripts/test-n3iwf-fixture-contracts.py
cargo test --locked -p opc-n3iwf-fixtures
```

The reference verifier checks source digests, exact row membership/order,
outcomes, inventory, provenance and authority flags independently of the writer.
Adverse tests change source indices, duplicate rows, rewrite outcomes with
refreshed local digests, truncate records, add packet data, alter source/public
revision claims and promote execution or authority. Errors use bounded constant
reasons; the new records contain no keys, packets, peer or subscriber values.

These are the final IKE/XFRM catalog references for #784. Wire notifies,
create/modify/delete and mobility remain in the independently consumable
`nwu-ike` subset. Loading either subset never executes the other. The
[completion map](n3iwf-completion.md) keeps catalog and runtime scope separate.

# Child-SA selection intentions

`opc_ipsec_xfrm::child_sa` describes the caller's choice among overlapping
Child SAs. A validated `ChildSaSelectionPlan` maps opaque traffic classes to
logical children. Each child has one selected outbound incarnation and can
retain receive-only incarnations during rekey. Each directional identity
contains a concrete ESP SPI, destination, exact lookup mark and expected
interface scope.

This is a data contract. Construction and lookup perform no backend I/O and
issue no installed capability, packet authentication proof or relocation
authority. Pairing, selectors, keys, policies and namespace identity remain
outside the plan. Existing `InstalledOutboundSaBinding`, durable installation
and single-SA relocation contracts are unchanged.

A namespace-bound actor can separately publish these intentions through the
[installed-roster contract](../../docs/n3-installed-child-sa-roster.md) after
whole-roster readback. That opaque publication does not turn freely supplied
inbound metadata into authenticated packet provenance.

## Selection

1. Assign a `ChildSaId` to each logical child in a caller-owned scope. Assign a
   new `ChildSaIncarnation` after rekey or removal/reinstall. These labels are
   not kernel cookies, IKE SPIs or proof of lifecycle events.
2. Describe the exact inbound/outbound identities of every retained pair.
   Choose exactly one `Selected` outbound incarnation per child; retain older
   pairs as `ReceiveOnly` when needed. Preference is explicit, independent of
   list order and the numerical incarnation value.
3. Bind one or more opaque `ChildSaClass` labels to each desired child and
   select one default child for the scope. The SDK does not parse PDU IDs,
   QFIs, NAS, GRE or packets to assign these classes.
4. Pass caller-selected inclusive pair/class limits to `ChildSaSelectionPlan::new`.
   Zero class capacity permits a default-only plan; pair capacity must be nonzero.
5. After evaluating product policy, call `select_outbound(Class(label))` or
   explicitly request `Default`. An unknown class fails. It does not silently
   become eligible for a fallback belonging to another traffic scope.
6. `match_inbound_intent(identity, incarnation)` compares supplied metadata
   exactly with declared inbound pairs. It never falls back to the default or
   an outbound identity. Unknown identities and mismatched incarnations fail.

The returned pair exposes the exact intended outbound SPI or matching inbound
identity. Equality with caller-supplied metadata does not establish that a
packet traversed that SA. A caller that labels an old packet with a new
incarnation defeats a data comparison; only a trusted live source can establish
that relationship.

## Identity admission

An identity must have a nonzero SPI, ESP protocol, specified destination,
absent or full-mask lookup mark, and absent or nonzero interface ID. The plan
refuses collisions between any two retained directional identities, including
inbound/outbound collisions within a pair or across children.

For equal destination/protocol/SPI, distinct full-mask marks are disjoint.
An unmarked stored SA uses a zero mask and can match every lookup value, so it
conflicts with every marked identity at that tuple. Interface IDs do not
disambiguate Linux SA lookup. They are nevertheless compared exactly when
matching inbound metadata. The caller must also exclude foreign overlapping
SAs outside this plan; validation cannot inspect a kernel table.

`ChildSaTrafficIdentity::query` reuses the existing observation-only
`QuerySaRequest`. Its key omits the interface ID, as Linux lookup does; a live
adapter must compare that field in exact readback separately.

Duplicate class labels, repeated incarnations within a logical child,
missing/multiple outbound choices and dangling default/class references fail
before a plan is returned. Incarnation `checked_next` refuses `u64::MAX`
instead of wrapping. This arithmetic does not provide a shared generation
fence or durable monotonic storage.

Construction takes ownership of the caller's vectors without another
allocation or sorting. Cross-reference validation is quadratic in the bounded
input counts; selection is linear and allocation-free. All new data-bearing
`Debug` implementations are value-free, including alternate formatting.
Errors have static bounded messages and no source chain. Explicit accessors
return the requested data to the caller.

## Standards and scope

[TS 24.502 V18.8.0](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.08.00_60/ts_124502v180800p.pdf)
separates signalling and user-plane children (§7.3.1/§7.3.2.2), permits multiple
QoS flows per user-plane child, requires all-packet user-plane traffic selectors
and one default per PDU session (§7.5.2), and assigns the PDU/QFI versus default
choice to the UE (§8.3.1). The opaque class and scope labels here carry the
caller's result; they do not implement those product rules.

[RFC 4301 §4.4.2](https://www.rfc-editor.org/rfc/rfc4301.html#section-4.4.2)
describes directional SA lookup and inbound selector checking.
[RFC 4303 §3.4](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4)
requires the inbound integrity/replay processing that a metadata comparison
cannot replace. Caller limits, exact mark admission, explicit preference and
incarnation width are SDK policies, not wire requirements.

## Unsupported live outcomes

There is no classifier attachment, packet capture, per-packet authenticated
provenance source, grouped publication receipt or whole-roster relocation API
in this module. Linux and mock receive the same pure plan, with no adapter
method added and no new runtime capability advertised. No live Linux/mock
packet parity or interoperability claim follows from these tests.

The remaining #793 work needs a trusted per-packet source, one generation
fence across the complete readback and all cooperating writers, lifecycle
invalidation, explicit unsupported adapter outcomes, and authenticated
whole-roster relocation. Cancellation or partial kernel mutation must retain
the existing safety fences until reconciliation. A source-address observation
cannot authorize that operation. Existing single-SA migration and durable
object-roster installation are prerequisites, not substitutes for it.

## Reproduction and fixture coverage

```sh
cargo test --locked -p opc-ipsec-xfrm --test child_sa_selection
python3 crates/opc-ipsec-xfrm/tests/child_sa_lookup_reference.py --check
cargo clippy --locked -p opc-ipsec-xfrm --all-targets --all-features -- -D warnings
```

The independent Python oracle imports no SDK code. It uses masked-domain
intersection to generate 4,608 synthetic identity pairs, including 360 ambiguous
pairs, across IPv4/IPv6, SPIs, marks and interface scopes. Rust admits/refuses
each plan and compares both admitted inbound identities.

Six reviewed `xfrm-roster` cases feed real plan admission/selection: single
pair, overlap, replacement, old/new order, duplicate SPI and unknown inbound
SPI. The fixture records are synthetic scenario records; their context flags
are not authentication evidence. Their wire bytes and `runtime_claim` fields
remain unchanged. Fixture-version/truncation parsing, caller-specific bounded
generation and relocation scenarios remain outside this component's claim.

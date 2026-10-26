# Spec-compliance evidence and scope corrections

This accompanies [umbrella #1532](https://github.com/openpacketcore/openpacketcore-sdk/issues/1532)
and the `compliance/spec-audit` branch. It records findings whose requested
change differs from the applicable wire format or existing implementation.
It is not peer-review approval or a claim of complete protocol support.
The umbrella tracks implementation and qualification separately.

## Protocol codec work list #1356

| Finding | Verified behavior and disposition |
| --- | --- |
| TFT error causes | The shared TFT parser returns typed errors. GTPv2-C maps them at the protocol boundary in `bearer_tft_decode_error`, `dedicated_bearer_decode_rejection_cause`, and `DedicatedBearerError::request_rejection_cause`. The existing dedicated-bearer tests cover operation semantics and packet-filter syntax/semantics. Keep the reusable TFT parser independent of GTP-specific Cause values. |
| Extended Bearer QoS | GTPv2-C uses a 22-octet known prefix with four 40-bit rates in kbit/s. TS 24.008's NAS QoS extension bits are a different IE format. Commit `00def1381` corrects receiver extension handling and pins the rate bounds. Adding NAS bits to this GTP IE would corrupt the wire format. |
| NAS EEA/EIA suites | The cited `crates/opc-nas/src/security.rs` does not exist. `opc-proto-nas` implements 5GS NAS, with AES NIA2/NEA2 and explicit null algorithms; its conformance document excludes EPS formats and SNOW 3G/ZUC providers. Naming NIA/NEA identifiers 1 and 3 does not implement those algorithms. Deployments requiring those providers still have a feature gap. |
| TWAN identifiers | `SwmWlanSsid::try_new` enforces 1–32 UTF-8 octets. `SwmBasicServiceSetIdentifier::from_text` validates the 17-octet textual BSSID, its separators, hex digits, and address validity. The six-byte internal representation is encoded as the specified UTF8String, not a six-octet AVP. No missing decoder length check was reproduced. |

Sources: [TS 29.274 §8.15](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/19.06.00_60/ts_129274v190600p.pdf),
[TS 29.273 §5.2.3.22](https://www.etsi.org/deliver/etsi_ts/129200_129299/129273/18.06.00_60/ts_129273v180600p.pdf),
and [TS 32.299 §7.2.30A](https://www.etsi.org/deliver/etsi_ts/132200_132299/132299/18.00.00_60/ts_132299v180000p.pdf).

Code and regression witnesses:

- [GTP TFT error mapping](../crates/opc-proto-gtpv2c/src/ie/typed.rs),
  [dedicated-bearer protocol causes](../crates/opc-proto-gtpv2c/src/dedicated_bearer.rs),
  and [dedicated-bearer tests](../crates/opc-proto-gtpv2c/tests/dedicated_bearer.rs).
- [TWAN value validation](../crates/opc-proto-diameter/src/apps/swm/location.rs)
  and [wire/constructor regression tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_location.rs),
  including `malformed_child_vendor_flags_cardinality_and_values_fail_closed`,
  `common_bssid_spellings_are_accepted_and_canonicalized`, and
  `public_constructors_enforce_bounds_without_value_bearing_errors`.
- [NAS conformance and provider scope](../crates/opc-proto-nas/CONFORMANCE.md).

The GTPv2-C and Diameter suites passed 445 and 770 tests respectively for the
associated remediation batches. Those results do not qualify absent NAS providers.

## Diameter runtime work list #1358

The cited `src/apps/rfc7683.rs` and `src/routing.rs` do not exist in
`opc-proto-diameter`. The SWm typed messages already parse and preserve DOIC,
DRMP, and redirect AVPs. Queue admission, traffic abatement, realm routing,
and redirect-cache ownership are separate runtime responsibilities. The
[codec conformance scope](../crates/opc-proto-diameter/CONFORMANCE.md) and the
transport adapters do not claim a complete Diameter routing agent.

RFC 8583 defines Diameter load information; the DRMP specification is
[RFC 7944](https://www.rfc-editor.org/rfc/rfc7944.html). A runtime implementation
must separately apply [RFC 7683](https://www.rfc-editor.org/rfc/rfc7683.html)
overload reports and [RFC 6733 §6.1.7](https://www.rfc-editor.org/rfc/rfc6733.html#section-6.1.7)
redirect usage/cache scope. Typed AVP tests do not establish that these runtime
features exist. These runtime gaps remain open.

## PFCP/GTPv2-C work list #1359

The mandatory PFCP Node ID and incremental-rule-reference defects are fixed
in commit `80474f343`. Existing GTPv2-C unknown-IE handling defaults to
preservation and offers explicit drop/reject policies; an optional unknown IE
does not abort the default receiver. The witnesses are
[unknown-IE policy tests](../crates/opc-proto-gtpv2c/tests/unknown_ie_policy.rs)
and [procedure receiver tests](../crates/opc-proto-gtpv2c/tests/s2b_receive_policy.rs),
including `procedure_families_discard_known_unexpected_types_and_preserve_unknown_optional_ies`.

The cited PFCP `src/runtime.rs` does not exist. The
[PFCP crate](../crates/opc-proto-pfcp/README.md) explicitly excludes UDP transport,
retransmission, and node lifecycle. Responding to a Heartbeat Request is not
an association supervision state machine. No timeout-state-machine repair is
claimed; implementing such a supervisor remains separate runtime work.

## 5GS interworking work list #1357

NGAP GTP transport addresses now preserve the 160-bit combined form through
uplink/downlink endpoints and nested Setup/Modify transfers. IPv4 occupies the
first 32 bits and IPv6 the remaining 128 bits, as specified by
[TS 38.414 §5.3](https://www.etsi.org/deliver/etsi_ts/138400_138499/138414/18.00.00_60/ts_138414v180000p.pdf)
and referenced by
[TS 38.413 §9.3.2.4](https://www.etsi.org/deliver/etsi_ts/138400_138499/138413/18.02.00_60/ts_138413v180200p.pdf).
The address getter now returns an enum retaining both families. Selecting a
reachable, authorized endpoint remains the caller's decision.

The reported MOBIKE file does not exist. The actual `nwu::mobike` receiver
already accepts IPv6-only outer paths. Its existing
`nat_prohibition_binds_both_addresses_and_ports_for_ipv4_and_ipv6` test performs
an authenticated UPDATE and COOKIE2 exchange over two IPv6 endpoints, verifies
the resulting migration path, and rejects altered addresses/ports. It passes
without a production change.

The IPv4 condition in `ConfigurationReply::new` applies to the requested
**inner** configuration family, not the outer MOBIKE path. The N3IWF reply rule
in [TS 24.502 V18.5.0, page 53](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.05.00_60/ts_124502v180500p.pdf)
conditions MOBIKE advertisement on the initial IPv4 configuration attribute.
The existing configuration-family matrix tests that rule. Removing it would
change the NWu profile rather than fix IPv6 outer transport. Neither test
claims live-peer or kernel migration qualification.

## IP foundations work list #1360

| Finding | Verified behavior and disposition |
| --- | --- |
| IPCP DNS options | `opc-proto-gtpv2c::pco` already parses options 129/131, correlates Configure-Nak identifiers and requested options, and exposes primary/secondary DNS. All 56 PCO tests pass, including independent literal replies, unsolicited options, stale identifiers and unit-local malformed-input handling. |
| Raw IPv4 checksum | Injection accepts validated packets rather than assembling a zero-checksum header. `Header::parse` calls `valid_ipv4_header`, which rejects an incorrect checksum; the fragmenter and ICMP builders compute new checksums. Linux raw `IP_HDRINCL` also fills the checksum. `whole_batch_is_validated_before_its_first_send` proves a corrupted fragment prevents any send. No missing checksum computation was reproduced. |
| IPv6 fragment cache cleanup | The cited `model.rs` location has no fragment cache or timer. Outer reassembly belongs to the Linux kernel; the SDK does not own the reported IPv6 reassembly cache. Inner fragments are handled by the documented forwarding profile. No cache-expiry repair is claimed, and this disposition does not qualify full IPv6 outer reassembly. |
| NAI SASLprep | RFC 7542 does not prescribe SASLprep in a Diameter AVP parser. It assigns normalization primarily to the edge with locale information and cautions AAA intermediaries against normalization. Preserve the received identity bytes; automatic parser rewriting could break exact EAP/User-Name correlation. |
| DNS hostname syntax | Fixed in `b37d5cf84`: address queries validate RFC 1123 hostnames while SRV/S-NAPTR service-owner syntax remains separate. |
| ICMP quote length | The IPv4 PTB builder already quotes the IPv4 header plus eight payload octets; `icmpv4_ptb_matches_rfc1191_layout_and_verifies_checksums` verifies the exact quote and both checksums. IPv6 uses its separate minimum-MTU quote rule. Moreover, RFC 1812 §4.3.2.3 recommends retaining more original IPv4 data within a 576-byte response; eight octets are not a universal maximum. |
| IPv6 scope ID | The cited `opc-net-util` crate does not exist. The SCTP socket boundary already copies `scope_id` into native `sin6_scope_id` and restores it on readback. The new `link_local_scopes_survive_raw_and_packed_addresses` regression verifies three nonzero scope values, including `u32::MAX`, against literal packed offsets and native byte order. The 14 ordinary Linux sys-layer tests pass; no production change is needed. The session TCP helper passes the complete `SocketAddr` to Tokio. |

Witnesses: [PCO tests](../crates/opc-proto-gtpv2c/tests/pco.rs),
[injection validation](../crates/opc-gtpu-dataplane/src/injection.rs),
[shared IPv4 header validator](../crates/opc-gtpu-dataplane/src/inner_fragment.rs),
[reassembly ownership](../crates/opc-gtpu-dataplane/src/reassembly.rs),
[ICMP builders/tests](../crates/opc-gtpu-dataplane/src/icmp.rs),
[SCTP native address conversion/tests](../crates/opc-libsctp-sys/src/linux.rs),
and [TCP connect helper](../crates/opc-session-net/src/scope/socket.rs).

Standards: [RFC 1877](https://www.rfc-editor.org/rfc/rfc1877.html),
[Linux raw socket checksum behavior](https://www.man7.org/linux/man-pages/man7/raw.7.html),
[RFC 7542 §2.6](https://www.rfc-editor.org/rfc/rfc7542.html#section-2.6),
[RFC 1812 §4.3.2.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.3),
and [RFC 4007 §6](https://www.rfc-editor.org/rfc/rfc4007.html#section-6).

## Management work list (#1363): gNMI subscription behavior

`TARGET_DEFINED` now selects configuration events and operational samples
within the same subtree, using the existing schema-backed path selector and
Subscribe authorization. Zero `SAMPLE` intervals use the server minimum.
Sampling, heartbeat and suppression settings remain local to each subscription;
an ON_CHANGE heartbeat does not require `suppress_redundant`. One initial
authorized observation seeds every schedule, preserving overlapping-path
deduplication and changes arriving during initialization.

The six runtime regressions in
[target_defined.rs](../crates/opc-gnmi-server/src/service/tests/target_defined.rs)
check mixed delivery, keyed prefixes, Subscribe-versus-Read authorization,
zero intervals, independent cadences/suppression and heartbeats. The complete
Linux gNMI suite passes 274 tests, including 62 keyed-read/subscription tests
and seven retained-audit integration tests. These tests establish the scoped
subscription change; the YANG generation evidence follows below.

Specification: [gNMI 0.10.0 §3.5.1.5.2](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#35152-stream-subscriptions).

## Management work list (#1363): YANG cardinality and NETCONF evidence

YANG `mandatory`, `min-elements` and `max-elements` are now retained in the IR,
validated during source ingestion and Rust generation, bound into the schema
digest, and enforced by generated configuration validation. The compiled
[cardinality fixture](../crates/opc-yanggen/tests/fixtures/cardinality_test.rs)
checks absent non-presence containers, inactive presence containers, per-entry
requirements, zero-valued mandatory booleans, sensitive leaf-lists and both
cardinality boundaries. All four runtime tests failed before the fix.
Source/IR regressions additionally check malformed statements, round trips,
source mismatch and digest changes. The complete generator suite and its
294-case generated-code lint/runtime matrix pass on Rust 1.99.1. At the
cardinality commit, unchanged legacy artifacts retained their full-file pins.

The remaining non-decimal reports were checked against current code:

| Report | Disposition and evidence |
| --- | --- |
| Unbounded revision index | `source::parse_module` retains one module revision (the first declaration) and the source text used for get-schema. It has no accumulating revision index. RFC 8525 §3 describes the served YANG library and does not mandate the claimed history-retention ceiling. No revision-retention feature is introduced. |
| Missing edit-config operations | `edit_xml::parse_operation` already recognizes create, replace and delete, retains per-node operations and passes the parsed edit to the binding applicator. Generated applicators implement their existence and replacement semantics. The full server and generator suites pass. The cited `operations/edit_config.rs` does not exist. |
| Missing notification subscription | `create_subscription_starts_live_config_change_notifications` exercises the real session, subscription RPC, configuration change and delivered notification. `notification_subscription_installs_retained_byte_budget` verifies bounded retention. These pass with the existing binding; replay and filter shapes remain explicitly unsupported by the advertised profile. |
| Missing get-schema/session inventory | The existing monitoring binding serves `/netconf-state` and get-schema, with positive, authorization, absent/ambiguous module, provider-error and size-limit tests. `get_schema_returns_schema_content_when_monitoring_and_nacm_allow` passes. This operation is specified by RFC 6022 §3.1, not RFC 8525 §4. |
| Boolean exactness | Generated JSON uses Rust `bool`; the new fixture verifies `false` is a present valid value while strings, numbers and absent required values are rejected. NETCONF scalar parsers also use the exact boolean parser. |

The complete Linux NETCONF run passes 533 tests, including retained-audit
recovery and process-loss cases. It runs with `umask 0077` so the test directories
satisfy retained-storage admission; the initial group-writable VM directories
were correctly rejected. No production check or test assertion was relaxed.
The decimal64 correction and its verification are described below.

Witnesses: [edit parser](../crates/opc-netconf-server/src/edit_xml.rs),
[server and tests](../crates/opc-netconf-server/src/server.rs),
[source ingestion](../crates/opc-yanggen/src/source.rs),
[RFC 7950 §§7.6.5 and 7.7.5–7.7.6](https://www.rfc-editor.org/rfc/rfc7950.html#section-7.6.5),
[RFC 6022 §3.1](https://www.rfc-editor.org/rfc/rfc6022.html#section-3.1),
[RFC 5277 §2.1.1](https://www.rfc-editor.org/rfc/rfc5277.html#section-2.1.1),
and [RFC 8525 §3](https://www.rfc-editor.org/rfc/rfc8525.html#section-3).

## Management work list (#1363): exact decimal64

`fraction-digits` is now mandatory, unique and retained in source IR and runtime
metadata. Generated `YangDecimal64<F>` stores a signed 64-bit coefficient; the
shared parser rejects unsupported syntax, non-finite numbers, precision loss
and values beyond the declared scale. Canonical output retains all significant
digits and uses `0.0` for zero. JSON requires a string. Redundant fractional
zeros are valid when they do not change the represented value.

The compiled [decimal fixture](../crates/opc-yanggen/tests/fixtures/decimal64_test.rs)
checks literal large adjacent values, both domain endpoints, 18 fractional
digits, canonical zero, defaults, chained leafrefs, list/leaf-list identity,
JSON, XML, gNMI, patches and value-free errors for secret fields. Baseline
runtime tests demonstrated that `900719925474099.21` became
`900719925474099.3` and `9.223372036854775807` lost its last digits. Decimal
leafrefs and list-key patches also exposed generated-code compilation failures;
the corrected types and parsers compile and preserve distinct values. The
shared parser tests every declared scale at signed coefficient boundaries.

XPath comparisons intentionally retain the IEEE 754 number semantics required
by RFC 7950 §6.4. That conversion is confined to evaluation and never modifies
the stored value. Public constraint IR is exercised with both path and
`current()` operands. Source-level must/when lowering and decimal range
restrictions remain explicitly unsupported by the existing generator profile;
this change does not silently accept or discard those restrictions.

Default-omission tests also found that NETCONF trim retained explicit values
equal to their schema default. Both ordinary and bounded subtree projection
now apply value-based omission, with exact decimal comparison. Existing
authorization assertions are preserved using a non-default boolean fixture;
separate tests check trim and explicit reporting of the same default value.

All 78 generated-file pins were first reproduced from commit `63440381b`.
Only the decimal codec/type/scale-digest changes and RFC 6243 trim changes
appeared in the reviewed generated output; the complete-file assertions remain.
The old proof that accepted subnormal/exponent/NaN/infinite float values is
replaced by exact-domain round trips and explicit refusal assertions. Public
IR, metadata and generated-type migrations are documented in the changelog.

Witnesses: [exact scalar](../crates/opc-mgmt-schema/src/decimal64.rs),
[source and IR tests](../crates/opc-yanggen/tests/scalars_and_names/decimal.rs),
[RFC 7950 §§9.3–9.3.4](https://www.rfc-editor.org/rfc/rfc7950.html#section-9.3),
[RFC 7950 §6.4](https://www.rfc-editor.org/rfc/rfc7950.html#section-6.4),
[RFC 7951 §6.1](https://www.rfc-editor.org/rfc/rfc7951.html#section-6.1), and
[RFC 6243 §3.2](https://www.rfc-editor.org/rfc/rfc6243.html#section-3.2).

## GTP-U multi-homing #1347

The eBPF default checked the configured outer peer address exactly. TS 29.281
§§4.3.0 and 4.4.3.3 allow one entity to use multiple source addresses. The issue's
explicit TEID/local validation option is now `GtpuPeerSourcePolicy::TeidAndLocal`.
It is per context and keeps local endpoint, attachment, source-port, inner-PAA,
TEID, ownership/generation and N3 QFI checks. Unspecified sources and malformed
record versions remain rejected; N3 source addresses remain unicast. It does
not authenticate an alternate address, so transport-network admission remains
caller policy. Outgoing routing still uses the configured peer.

`BackendDefault` retains eBPF's exact peer check and Linux GTP's native behavior.
The Linux kernel's `gtp1u_udp_encap_recv` already looks up the incoming TEID
without comparing the outer source to the configured outgoing peer. Linux GTP
rejects the new explicit opt-in because its netlink codec cannot retain that
setting. It is therefore not labelled an exact-peer policy across all backends.

Default-policy bytes retain their existing versions. The opt-in has new binding,
ordinary/N3 entry and durable-descriptor versions; older readers reject them.
Policy bytes enter owner/commit equality and selector-admission fingerprints.
Readback/restart preserve the policy, while exact install/removal and TEID-only
reattachment detect a policy conflict. The shared borrowed checks also serve
the kernel-reassembly consumer.

Witnesses include raw-byte typed/borrowed tests for both families and N3,
malformed-version refusal, ownership mismatch, ordinary/marked restart, grouped
readback, durable descriptor/fingerprint tests, and userspace reassembly parity.
The privileged Linux test injects alternate-source packets, proves default
rejection and opt-in delivery across restart, and rejects wrong local address,
UDP source port, TEID and inner PAA. Existing IPv4 round-trip, ordinary IPv6 and
N3 live contracts qualify the rebuilt object separately. A full Linux test run
initially failed during durable selector fixture provisioning (`Indeterminate`);
the isolated test and complete rerun passed without changing that test or its
assertions. This is retained as test history, not treated as peer-review approval.

Sources: [TS 29.281 v18.4.0 §§4.3.0, 4.4.3.3](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf),
[Linux v6.8 GTP receive path](https://github.com/torvalds/linux/blob/v6.8/drivers/net/gtp.c),
[shared binding](../crates/opc-gtpu-ebpf-common/src/lib.rs),
[grouped wire authorizers](../crates/opc-gtpu-ebpf-common/src/session.rs), and
[live packet proof](../crates/opc-gtpu-dataplane/tests/ebpf_gtpu_privileged/multihoming.rs).

## IKE cryptographic transforms #1352

The executable software provider now implements MODP groups 15–18, RFC 4754
ECDSA methods 9–11, P-521/SHA-512, RSA-PSS with SHA-256/384/512, and pure
Ed25519. DH selection, exact peer-value bounds, SA_INIT exchange, IKE rekey,
and single-export encrypted checkpoints all retain the new group widths.
SHA-512 and Identity offers require actual provider admission. Existing
proposal defaults and transcript/nonce authorization remain in force.

Methods 9–11 carry fixed-width `r || s`; method 14 carries its algorithm
identifier and DER ECDSA, PSS, or pure Ed25519 signature. The PSS parser
accepts equivalent RFC 4055 SHA-2 encodings, including absent/NULL hash
parameters and RFC 7427's explicit trailer field. Its supported profile
requires matching SHA-2/MGF1 digests, digest-sized salt and trailer field 1.
Malformed identifiers, wrong salt/MGF/hash, mismatched credentials, weak
Ed25519 keys, non-canonical scalars and unbound hash offers are rejected.
The original candidate's extra context wrapper inside the PSS MGF1
identifier was invalid ASN.1 and has a dedicated refusal regression.

Local PSS AUTH self-verification selects an exact signature scheme with
`authorize_local_auth_self_verification_with_algorithm`; the previous
hash-only API retains its PKCS#1 choice for RSA. RSA private operations
remain behind `rsa-signing`, with the existing timing-advisory limitation.
Public-key verification is always available. Ed25519 is supported; Ed448
and prehashed Ed25519 are explicitly unsupported. Certificate extraction
still supplies a verification key, not certificate-chain trust. Startup
PKCS#8 inspection supports P-521/Ed25519 without granting signing authority.

A follow-up private-operation review replaced RSA-PSS's unblinded signer with
the library's `BlindedSigningKey` and enabled the same randomized RSA blinding
in the existing PKCS#1 helper. All 45 signature/provider tests pass on macOS
and Linux, including unchanged PKCS#1 signature bytes and all PSS hashes.
This reduces avoidable exposure but does not claim to resolve the underlying
`rsa` timing advisory; the explicit signing feature restriction remains.

The baseline public transform/offer regressions failed before implementation.
Published RFC 4754 vectors exercise all three raw ECDSA widths, and RFC 8032
test 2 proves exact pure Ed25519 output. OpenSSL independently verifies these
and the committed RSA-PSS positive/negative fixtures through a required CI
step. MODP primes match RFC 3526 byte-for-byte; Python integer arithmetic and
Node.js BigInt independently reproduce the fixed-exponent shared-secret
digests. Tests cover default-build RSA signing refusal as well as enabled
signing, checkpoint corruption/replay, provider admission and full exchanges.

The change also updates IKE's `crypto-bigint` to 0.7.10 and `ctutils` to 0.4.6
with matching standalone lockfiles. The separate DTLS arithmetic and Tokio
follow-ups are recorded in the integration-verification sections below.

Witnesses: [signature boundary](../crates/opc-proto-ikev2/src/ike_auth_signature.rs),
[DH boundary](../crates/opc-proto-ikev2/src/sa_init_crypto.rs),
[fixture provenance](../crates/opc-proto-ikev2/tests/data/crypto_vectors.md),
[independent OpenSSL gate](../scripts/check-ike-signature-vectors.py),
[RFC 3526 §§4–7](https://www.rfc-editor.org/rfc/rfc3526.html#section-4),
[RFC 4754 §§3, 8](https://www.rfc-editor.org/rfc/rfc4754.html#section-3),
[RFC 7427 §3 and Appendix A.4](https://www.rfc-editor.org/rfc/rfc7427.html#section-3),
[RFC 4055 §3.1](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1), and
[RFC 8420 §2](https://www.rfc-editor.org/rfc/rfc8420.html#section-2).

## SCTP work list #1351: mixed-family static multihoming

Bind/connect address sets now accept IPv4 and IPv6 together, preserving count,
same-port and wildcard limits. Local and remote sets must have a usable family
in common. Socket-family selection examines both complete sets, and mixed
sets use explicit dual-stack configuration before bind/connect. Existing
single-family sockets retain the previous host policy. Packed UAPI addresses
use their concrete 16/28-byte widths, not a fixed `sockaddr_storage` stride.
Native IPv4 and unscoped IPv4-mapped path identities reconcile; wrong ports,
nonzero scopes, IPv4-compatible addresses and different hosts remain distinct.

The portable mixed-set regression failed against the old guard. Native Linux
coverage forms one association in each configured family order, checks both
local and peer address readback, selects each family as primary and delivers
application records with preserved stream/PPID metadata. The required SCTP
CI job executes this ignored kernel test explicitly and checks its test count.
Other #1351 items are tracked separately; this slice does not claim the whole
work list is complete.

Witnesses: [socket boundary](../crates/opc-libsctp-sys/src/linux.rs),
[transport and native proof](../crates/opc-sctp/src/lib.rs),
[configuration regression](../crates/opc-sctp/tests/dual_stack.rs), and
[RFC 6458 §§8.1.15, 9.1, 9.3, 9.5, 9.9](https://www.rfc-editor.org/rfc/rfc6458.html#section-9.1).

## SCTP work list #1351: authentication preference and local readback

The sys boundary exposes `SCTP_HMAC_IDENT` and `SCTP_LOCAL_AUTH_CHUNKS`.
HMAC lists are bounded to the implemented SHA-1/SHA-256 identifiers, reject
duplicates and require SHA-1. The safe configuration offers explicit
SHA-256-first preference while preserving the kernel default otherwise.
Requested order and required local chunk types are read back before setup;
local and peer chunk requirements are verified again on the association.
No signing, transport identity or application authentication is inferred from
SCTP-AUTH alone.

The native test caught a Linux distinction: the socket returned by `accept`
has a newly created endpoint. Its HMAC option can return SHA-1 defaults (or
EACCES with authentication disabled globally), despite the existing
association inheriting the listener's configured SHA-256-first list.
Preference evidence therefore comes from the listener before listen, while
association-specific chunk evidence is read after accept. The implementation
never rewrites a live association's HMAC parameters to force a readback match.

The real key-switch/drain test now exercises SHA-256 preference and local
readback in both namespace authentication-default modes. Both pass, and the
required SCTP CI job executes both explicitly. Unit tests cover malformed
counts/lengths, unknown or duplicate identifiers, missing SHA-1, missing DATA
or FORWARD-TSN requirements and reversed preference. Existing key lifecycle
and drain assertions remain.

Witnesses: [safe authentication boundary](../crates/opc-sctp/src/lib.rs),
[bounded UAPI codecs](../crates/opc-libsctp-sys/src/linux.rs),
[RFC 4895 §§3.3, 6.1](https://www.rfc-editor.org/rfc/rfc4895.html#section-3.3),
[RFC 6458 §§8.1.17, 8.2.4](https://www.rfc-editor.org/rfc/rfc6458.html#section-8.1.17), and
[Linux endpoint/association readback](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).

## SCTP work list #1351: Diameter stream admission

RFC 6083 section 4.4 permits sending application records solely on stream zero.
However, RFC 6733 section 2.1.1 requires Diameter receivers to accept messages
on any negotiated stream, including peer-selected unordered delivery. The
Diameter facade now applies that receiver contract in both sequential and
concurrent operation. Its selected-stream send method retains exact-generation
command admission. SCTP remains responsible for negotiating and enforcing the
available stream range; stream 65535 is rejected locally.

The existing bounded epoch/record-number correlation tracks authenticated
carrier metadata. Handshake, CCS and Alert records remain ordered on stream
zero. Cleartext, foreign PPIDs, malformed records, truncated metadata and
notifications still fail closed. The separately configured generic RFC 6083
ordered-stream policy retains its original restrictions. Default Diameter
sends and the concurrent runtime still choose ordered stream zero, with its
head-of-line blocking tradeoff; this change does not implement a stream scheduler.

The old implementation fails the new peer-stream regression. The fixed
selection passes 236 tests on each host and Linux, covering both roles and
both runtime forms, highest usable stream ID, unordered application delivery,
protected selected-stream sends and terminal metadata/control refusals. The
existing native Diameter qualification additionally sends in both directions
over negotiated streams 1, 7 and 15, preserving its original stream-zero and
reciprocal-close assertions. All 11 native RFC 6083 cases and Linux strict
all-target/all-feature Clippy pass.

Witnesses: [Diameter transport](../crates/opc-diameter-transport/src/dtls.rs),
[regressions](../crates/opc-diameter-transport/src/dtls_tests/diameter_streams.rs),
[native proof](../crates/opc-diameter-transport/src/dtls_tests.rs), and
[RFC 6733 section 2.1.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-2.1.1).
The other #1351 lifecycle and optional-extension claims remain separately tracked.

## SCTP work list #1351: remaining lifecycle claims

- RFC 6083 section 4.6 leaves renegotiation use to the upper layer. It does not
  require automatic HelloRequest handling or uninterrupted writes. The existing
  explicit rekey profile retains the section 4.7 drain/key barriers; its native
  multistream rekey and packet-capture proofs pass. The Diameter facade continues
  to use bounded connection retirement instead of offering renegotiation.
- RFC 6525 sections 6.3.1 and 7 distinguish event subscription from enabling
  reconfiguration. Reset requests are disabled by default and require explicit
  application enablement. The documented N2 owner observes lifecycle events;
  it does not advertise a reset/add-stream API. Enabling extensions merely
  because their events are observed is not required. RFC 6083 section 4.8,
  also cited by the issue, concerns shared keys rather than stream resets.
- RFC 6458 section 4.1.7 specifies that SHUT_RDWR initiates SCTP shutdown.
  The expanded native close regression verifies all eight queued 1 KiB
  responses reach the peer before Closed, for both descriptor drop and the
  explicit local terminal-close handle. The required SCTP CI job runs this
  proof explicitly. This is loopback delivery evidence, not a guarantee that
  a peer or network failure cannot interrupt an SCTP shutdown.

Wire ABORT remains open. The legacy `abort` handle closes local I/O using
SHUT_RDWR and must not be presented as a wire-ABORT API. An uncommitted
SCTP_ABORT-send prototype returned EINVAL on the native one-to-one association
and was removed. Linux explicitly rejects that flag for its TCP-style SCTP
sockets; a correct abort path must coordinate physical descriptor closure
and abortive linger without replacing an owned descriptor while registered.
RFC 6733 section 2.1 also requires wire abort when Diameter framing cannot be
recovered. This remaining requirement is not waived by the graceful-close proof.

Witnesses: [native close regression](../crates/opc-sctp/src/lib.rs),
[RFC 6083 sections 4.6–4.8](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.6),
[RFC 6525 section 6.3.1](https://www.rfc-editor.org/rfc/rfc6525.html#section-6.3.1),
[RFC 6458 section 4.1.7](https://www.rfc-editor.org/rfc/rfc6458.html#section-4.1.7), and
[Linux one-to-one flag check and linger-based close](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).

## Integration verification: Tokio descriptor ownership

The branch updates every Tokio lock to 1.53.3 and keeps the storage consumer's
exact version requirement. The deprecated `AsyncFd` constructors are replaced
at all SCTP, boot-time clock and storage-backoff call sites. The new narrow
`opc-tokio-fd-sys` boundary takes an `OwnedFd`, retains it through deregistration
and exposes no mutable or owning access to the registration. Compile-fail
checks reject raw integers, descriptor replacement and inner extraction.
Boot-time timers transfer their existing descriptor without duplication and
retain the existing counter validation and redacted errors.

The blocking-pool queue still enqueues at the back and dequeues at the front.
Compared with Tokio 1.53.1, 1.53.3's pool changes only lock release before
rejecting a task after shutdown; the multi-thread worker source is unchanged.
All 28 existing admitted-SQLite-write and authority-backoff tests pass on Linux,
including queue bounds, closed owners, panic, cancellation, runtime shutdown,
borrowed/current-thread execution and shared timer expiry. An initial compile
exhausted the 6 GiB test VM before running; the unchanged selection passed with
16 GiB. No test deadline or assertion was relaxed.

The ordinary affected-crate selection passes 374 Linux tests, and native SCTP
authentication (both namespace defaults), single-family multihoming and
mixed-family multihoming pass explicitly. Host coverage passes the 116 portable
SCTP tests and the four descriptor ownership/readiness checks. These results do
not claim a macOS eBPF backend: its existing Aya dependency is Linux-only.

Witnesses: [owned registration](../crates/opc-tokio-fd-sys/src/lib.rs),
[storage handoff matrix](../crates/opc-session-store/src/consensus/storage.rs),
[backoff tests](../crates/opc-session-store/src/sqlite/native.rs),
[boot-time clock test](../crates/opc-egress-fence/src/linux_control.rs),
[ADR amendment pending peer review](adr/0017-sctp-transport-ffi-boundary.md), and
[the upstream advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386.html).
The full Linux workspace passes all-target/all-feature Clippy. The mechanical
unsafe boundary, all committed lockfile metadata and test-shard coverage checks
pass. The DTLS arithmetic follow-up is recorded below.

## Integration verification: DTLS arithmetic and standalone time dependency

The vendored RustCrypto provider now uses P-256/P-384 0.14 and ECDSA 0.17,
with a manifest floor of crypto-bigint 0.7.10 for external consumers.
Ephemeral-key generation propagates OS entropy failures and explicitly retains
uncompressed SEC1 public points. Private-key decoding imports the matching
PKCS#8 trait; the existing bounded certificate/SEC1 DER paths, cipher suites,
key exchange groups and signature wire formats remain unchanged.

The standalone vendor lock also exposed an older `time` advisory. Its manifest
now requires at least 0.3.47 and the lock resolves 0.3.55. The vendor MSRV is
1.88, below the SDK's 1.89 floor. The resulting Clippy suggestions only replace
divisibility/chunk operations and nested conditions with equivalent standard
operations and short-circuit let chains. Guards retain their evaluation order.

After the final changes, all-feature coverage passes 636 tests and 11 doc tests;
RustCrypto-only coverage passes 323 tests and nine doc tests. Both feature
selections pass all-target Clippy and the stricter production panic lints.
The two existing WolfSSL DTLS 1.3 omissions remain explicit: application-data
MTU fragmentation and a HelloRetryRequest that the peer cannot be made to send.

Linux SDK coverage passes 233 ordinary tests. All 11 ignored native RFC 6083
cases run explicitly and pass, including stream delivery, path loss, restart,
rekey, SNI and certificate policy. Rekey and SNI captures retain complete
key-ID progression with zero capture drops. Independent RFC 5746/RFC 6066,
certificate and CRL fixtures, external-consumer resolution/compilation,
source invariants, formatting and every committed lockfile metadata check pass.
Root and vendor dependency audits report no unignored vulnerabilities or
warnings under the existing RSA-private-operation and unused-rkyv exceptions;
neither exception is expanded by this change.

Witnesses: [vendor patch and validation contract](../vendor/dimpl/UPSTREAM.md),
[RustCrypto key exchange](../vendor/dimpl/src/crypto/rust_crypto/kx_group.rs),
[native qualification](../ci/qualify-rfc6083-native.sh),
[arithmetic advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), and
[time advisory](https://rustsec.org/advisories/RUSTSEC-2026-0009.html).

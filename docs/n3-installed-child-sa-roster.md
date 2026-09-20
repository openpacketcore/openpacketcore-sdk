# Installed Child-SA selection roster

`XfrmBackend` exposes optional `begin_child_sa_roster_update`,
`publish_child_sa_roster` and `select_installed_child_sa` operations. The
namespace-bound Linux actor implements them. Raw Linux, mock and unsupported
backends return `UnsupportedFeature { feature: "installed_child_sa_roster" }`.
The existing freely constructed `ChildSaSelectionPlan` remains intent data.

This is an installed-selection increment of #793. It does not complete that
issue's sealed inbound packet-provenance or authenticated whole-roster
relocation requirements. It introduces no IKE parsing, PDU/QFI policy, key
custody, SA installation or endpoint-migration authority.

## Admitted profile

The caller supplies at most 32 directional pairs and 256 opaque traffic
classes. Every logical child has exactly one selected outbound incarnation;
other incarnations remain receive-only during rekey overlap. The caller names
one explicit default child. Several classes may select the same child.
These bounds and preferences are SDK/caller policy, not 3GPP requirements.

Each pair carries transient expected SA parameters and its inbound allow
policy. The selected incarnation also carries an outbound allow policy. Both
SAs must exist, use authenticated tunnel mode with replay enabled, and match
the declared destination/SPI/protocol, exact optional mark and interface scope.
The policy selector equals the associated SA selector. Selected outbound
children require distinct full-mask marks and concrete policy-template SPIs.
Classified application traffic must carry the selected child's mark. Unmarked
outbound selection, wildcard outbound SPI preference and partial lookup marks
are outside this profile.

An inbound wildcard-SPI template is admitted only with the exact nonzero
request ID already required by the existing SA/policy validator. Identical
inbound policies may therefore serve several incarnations. That shared policy
does not identify which inbound SA authenticated a packet. Receive-only
outbound SAs retain the selected child's exact policy lookup identity and have
no separately declared outbound allow policy; the current concrete-SPI policy
selects the successor.

## Publication and writer fencing

1. Install resources and finish required durable adoption/recovery using the
   existing APIs. Retain exclusive namespace-wide XFRM writer ownership.
2. Acquire an affine `ChildSaRosterUpdate` after installation. It binds the
   actor's current generation, including its private process-local identity.
3. Consume that ticket with the complete ordered roster. The actor withdraws
   its previous publication and burns the ticket before any readback.
4. Read every policy and both SAs of every pair. Policy and immutable SA
   metadata must match exactly. Fresh publication also compares transient
   caller-supplied keys with zeroizing kernel readback. Missing, redacted,
   ambiguous, malformed, mismatched or failed reads issue no publication.
5. Only the complete successful read issues `InstalledChildSaRoster`. It retains
   key-free expectations and the validated class/default plan. At most one
   roster is current on an actor; handles and tickets cannot be constructed
   from caller labels or persisted generation numbers.

Every admitted ordinary or durable actor mutation invalidates the publication
and pending tickets through the same central fence as counter receipts. This
includes mutations that subsequently fail or become indeterminate. Unresolved
object-install, SA-relocation and object-roster recovery truth blocks roster
publication and selection. Generation arithmetic never wraps: exhaustion
permanently disables publication on that actor. Another actor targeting the
same namespace has a different seal and cannot consume the old authority.

Selection checks the current opaque publication and freshly reads the entire
roster, including unselected predecessors. A readback conflict permanently
retires that publication; restoring identical kernel bytes cannot revive it.
A stale ticket or handle is refused before any kernel read. Unknown traffic
classes are refused without falling back implicitly to the default.

An admitted command runs to completion on the existing supervised namespace
actor even if the caller drops its reply receiver. A lost publication reply
requires a new ticket and complete readback. Process loss likewise requires
fresh publication; this in-memory receipt adds no durable recovery format.

## Authority limits

The returned `InstalledChildSaSelection` is a point-in-time installed-state
result. It does not lock the actor across later application packet sends.
The caller serializes classification and sending with namespace writers and
excludes independent/raw writers and foreign overlapping policies. Readback
cannot prove that an uncooperative writer will not change state afterward, or
distinguish every remove/reinstall with identical immutable metadata and keys.
Cooperating writes always invalidate the SDK generation.

Neither publication nor selection grants counter restoration, same-SPI/key
reuse, key export, default eligibility, inbound packet authentication or
relocation authority. The existing custody, counter-resume and migration
contracts still govern those operations. In particular, the public mutable
`EspPeerObservation` must not be promoted into an authenticated roster receipt.
Source-address observation alone remains insufficient to authorize MOBIKE.

## Evidence

The literal roster tests drive the production Linux encoder/parser through
scripted netlink replies. They exercise a signalling child, two overlapping
user-plane children, multiple classes/default, every policy/SA read failure,
exact-key and direction substitution, stale/wrong-actor tickets, rekey overlap,
readback conflicts and non-revival. A separate test exhausts the generation.
Cancelling an admitted publication at each of its twelve reads still drains
the entire roster, withdraws the predecessor and requires fresh readback before
the caller obtains another handle. Raw Linux/mock/unsupported results are explicit.

The native consumer fails to compile against the parent with the missing public
API. Seven removed-guard controls fail after successful compilation: actor
mutation invalidation, whole-roster reread, stale-ticket rejection, exact key
comparison, SA direction, generation exhaustion and concrete outbound SPI.
The key control substitutes the same wrong key in both redundant kernel
authentication attributes, so consistency between those attributes cannot mask
the missing comparison with transient intent.

`xfrm_child_sa_roster_privileged` uses fresh Linux network namespaces and real
XFRM state with identical all-packet selectors. Only the outer UDP encapsulation
sockets have socket-scoped empty-template allow policies, so Linux can admit
the outer datagram before decapsulation. Inner application sockets retain the
authenticated tunnel policy. Independent AF_PACKET captures check the intended ESP SPI for seven
outbound class/default choices and six inbound authenticated deliveries. A
successor packet uses the new SPI while predecessor SAs remain installed.
Removal/reinstallation and a deliberately foreign policy conflict refuse the
old publication. This test uses synthetic authentication-only ESP-in-UDP
traffic; it is not external interoperability, sealed inbound SDK provenance,
native-ESP relocation or full N3IWF qualification. The CI native lane requires
one passing test, zero ignored cases and its completion marker, without debug
profile overrides.

No new dependencies, secret-bearing publication fields, metrics or production
log values are added. Errors carry existing static XFRM error labels; request,
ticket, publication and selection `Debug` output is fully redacted.

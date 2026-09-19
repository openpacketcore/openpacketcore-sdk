# Required direct CRLs for generic RFC 6083 transport

This extends the [generic transport contract](rfc6083-generic-transport.md)
with an explicit revocation profile for both endpoint roles. It reuses the
same vendored DTLS engine, WebPKI path verification, exact expected SPIFFE
identity, TLS material controller and SCTP-AUTH barriers. No Diameter
procedure or NGAP handler is involved. The original `Connector::new`,
`Acceptor::new` and Diameter endpoint behavior remains unchanged.

## Public contract

Create `rfc6083::CrlPublisher::new(&material_controller)` after admitting the
intended credential/trust epoch, obtain current CRLs through a trusted local
source, and call `publish` with the entire issuer set. Pass its read-only
`source()` to `Connector::new_with_required_crls` or
`Acceptor::new_with_required_crls`, together with the expected peer and policy.
The source carries its own controller, so an unrelated controller with the
same numeric epoch cannot be substituted. Rotation requires a new publisher
for the new material epoch. The publisher is local authority, not evidence
that its input is signed; verification occurs against the selected peer path
during each handshake. No peer URL is fetched.

Each successful handshake requires valid certificate signatures, validity,
role EKU, trust domain and exact SPIFFE identity, plus all of the following:

- Complete current direct CRL coverage for the leaf and every intermediate
  on the selected verified path. Unknown status is refused. The trust anchor
  is not itself checked for revocation.
- A valid CRL signature under that certificate's selected issuer, including
  `KeyUsage.cRLSign` on the actual issuer certificate, even for a trust anchor.
  Exactly one issuer Subject Key Identifier must match the CRL Authority Key
  Identifier. Ambiguous issuer names on the selected path are refused.
- No certificate on the checked path appears in its issuer's CRL.

CRL parsing requires strict DER, v2 complete CRLs, noncritical Authority Key
Identifier (key identifier only) and CRL Number, and
`thisUpdate <= now < nextUpdate`. Other CRL extensions, including delta,
indirect and distribution-point partitioning, are refused. Revoked entries
may carry noncritical reason and invalidity date; duplicate serials and
duplicate extensions are refused. One CRL per issuer is allowed, regardless
of input order. These supported-profile restrictions are deliberately narrower
than all of [RFC 5280 sections 5 and 6.3](https://www.rfc-editor.org/rfc/rfc5280.html).

The SDK resource policy allows at most 16 CRLs, 65,536 DER bytes each and
262,144 DER bytes per publication, checked before parsing. Authority key
identifiers are at most 64 bytes and CRL numbers at most 20 bytes. These
limits do not assert standards maxima. Per-issuer number and `thisUpdate`
floors survive withdrawal and removal from the current set; equal numbers
must retain identical DER. The lifetime issuer roster is also bounded to 16,
retaining at most 16 individual CRL byte strings for rollback comparison in
addition to the current parsed set. Generation exhaustion and all failed
publications withdraw the source. Publisher recreation or process restart
does not preserve rollback floors: callers own durable freshness/provenance
and must not use recreation to authorize older input.

## Connection lifetime

Evidence exposes an opaque publication generation, its material epoch and
the earliest `nextUpdate` across the supplied set. Generation comparison is
meaningful only within one source. A publication, including identical bytes,
creates a new generation and invalidates older connections. Withdrawal,
malformed publication, rejected rollback and publisher drop also invalidate
them. There is no fallback to the original non-CRL profile and no revival of
retired connections. Establish a fresh association against the current input.

Handshake and connection deadlines are capped by the CRL set's earliest
expiry as well as the existing material, certificate and age bounds.
Publication changes interrupt a pending handshake or operation. Readback,
send and receive synchronously recheck the exact retained snapshot and
freshness; a scheduled watcher cannot extend admission or release queued
plaintext after withdrawal. Successful operations retain the existing
post-operation checks. Material replacement/withdrawal uses the original
controller retirement machinery. Errors and Debug output disclose no CRL,
issuer, serial, peer, credential or packet contents.

## Independent evidence and scope

`crates/opc-diameter-transport/tests/fixtures/rfc6083/revocation.py` uses
`cryptography==49.0.0`, deterministic synthetic P-256 keys and its own
certificate/CRL classifier, without SDK imports. Run it with Python to
regenerate and compare the checked-in TSV; `--write` explicitly updates it.
The TSV has 52 cases and SHA-256
`52869f0cb4242bce8d2e49d06b63042637a8536b49cdc0a636537dbb247a8f2c`.
Its PKCS#8 values are public synthetic test keys, never deployment material.
The dates deliberately span 2010–2100 for valid fixtures; stale/future cases
use 2020/2090, and the independent classifier's reference date is 2026.

Both handshake roles consume the independently authored valid, revoked leaf,
revoked intermediate, incomplete coverage, wrong issuer/key/identifier, bad
signature, missing signing usage, invalid time, malformed DER, duplicate,
unsupported-extension and unrelated-revocation cases. Admitted vectors enter
real mutual DTLS handshakes; authentication failures return no connection.
The original eight certificate vectors and their classifier are unchanged.

Lifecycle tests exercise queued delivery, pending receive/handshake,
replacement, withdrawal, publisher loss, obsolete epochs, rollback and finite
generation exhaustion. A short-lived runtime-generated CRL separately tests
the expiry bound; it is not independent wire provenance. The ignored Linux
`generic_kernel_required_crls_retire_both_roles` test must be run explicitly
in an isolated SCTP-AUTH network namespace to qualify the real carrier.
Ordinary passing tests with this test ignored do not supply kernel evidence.

This profile remains reliable ordered stream zero at protected PPID 47 or
66. The new corpus exercises PPID 66; unchanged existing tests qualify the
Diameter and original generic profiles separately. Full 3GPP PKI, OCSP,
network CRL retrieval, persistent rollback protection, nonzero streams,
in-place rekey, restart and multihoming qualification remain outside this
increment. The older pinned lifecycle fixture contract describes its own
non-revocation schedules and is not retroactively claimed to cover these CRLs.

Tracking: #794, #784 and #795. This increment does not satisfy every acceptance
criterion of those issues.

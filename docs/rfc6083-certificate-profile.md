# Bounded operator certificate constraints

Generic RFC 6083 endpoints can add
`CertificateProfile::NdsAfEcdsa` with `with_certificate_profile`. Construct the
endpoint with `new_with_required_crls` first. The profile requires complete,
current direct CRLs for both the local and peer chains and their trust-domain
bundles. Missing inputs fail closed. The default endpoints and Diameter API
retain their existing behavior.

This is an ECDSA certificate subset, not a complete NDS/AF or N2 conformance
claim. It adds checks to the existing exact SPIFFE identity, cryptographic
path, role, validity and revocation verification. Optional
`with_server_name` still separately requires SNI and the exact server DNS SAN.
Subject organization and other directory fields never select a peer,
credential, trust bundle or application authority.

## Selected paths and lifetime

Local credentials are verified before the first Hello. The controller owns
credential admission and private-key custody; the new code consumes its
read-only certificate/trust material. Peer checks run on the path actually
selected by WebPKI after signature, usage and required-CRL verification.
The trust anchor's original configured certificate supplies fields omitted
from WebPKI's `TrustAnchor`. Distinct DER certificates matching that selected
anchor are refused as ambiguous; byte-identical duplicates are harmless.
An unrelated configured anchor is not treated as part of this path.
The selected path, including its anchor, is bounded to eight certificates,
64 KiB per certificate and 256 KiB in total, using the existing SDK budgets.

The anchor remains an explicitly configured trust point. Its own issuer or
self-signature is not an additional authenticated path. Presented certificate
order, the existing wire size/count bounds and exact SPIFFE trust-domain
selection still apply. A peer-supplied issuer cannot become a new anchor.

`Evidence::certificate_profile` is `Some(NdsAfEcdsa)` only after successful
mutual authentication. The immutable constraint is checked again on the peer
chain during coordinated rekey. Local credentials cannot change within their
admitted material epoch. Credential or CRL replacement/withdrawal, publisher
loss, expiry and cancellation retain their existing retirement rules.
Both expiry readbacks include the selected anchor. The connection's original
absolute lifetime is bounded by those expiries and is never extended by rekey.
Profile errors are value-free; evidence and endpoint Debug remain redacted.

## Certificate subset

[TS 33.310 V18.8.0 clauses 6.1.1, 6.1.2, 6.1.3a and 6.1.4a](https://www.etsi.org/deliver/etsi_ts/133300_133399/133310/18.08.00_60/ts_133310v180800p.pdf)
define the source certificate constraints: v3, supported signature/public-key
algorithms, signer-key strength, distinguished names, extension criticality,
TLS entity key usage/EKU/distribution points and issuing CA constraints.

| Checked object | This SDK subset |
| --- | --- |
| Every selected certificate, including anchor | P-256/P-384 named EC key; ECDSA with SHA-256/SHA-384 and absent signature parameters; matching inner/outer signature identifiers; current validity; unique parseable extensions |
| Each authenticated child/issuer edge | Exact issuer/subject equality; issuer key security at least the child's |
| Leaf | Critical KeyUsage containing digitalSignature; optional noncritical EKU explicitly containing its TLS role; noncritical CRL distribution points |
| Direct TLS CA | Critical CA BasicConstraints with path length zero; critical keyCertSign and cRLSign |
| Upper CA/anchor | Critical CA BasicConstraints with sufficient path length or no limit; critical keyCertSign and cRLSign |
| Other extensions | Noncritical; malformed recognized extensions are refused |

The following narrower choices are SDK policy. All directory RDNs are
single-valued, nonempty and use canonical DER order: optional country,
organization, common name; or at least two domain components, optional
organizational unit, common name. Organization/common name use UTF8String;
country uses a two-letter PrintableString. The domain form uses IA5String
DNS labels and UTF8String unit/hostname. Its LDAP display order is reversed.
These formatting checks do not establish administrative-domain ownership.

This profile requires cRLSign on every selected CA, even where the source
describes its assertion as recommended. The existing direct-CRL publisher
also requires issuer SKIs, AKIs in CRLs, freshness and rollback floors.
Distribution points must be nonempty named points without a reason subset
or indirect issuer. Their names are metadata: the transport never resolves
or fetches them. Selected anchor validity/path constraints are enforced even
though a general RFC 5280 trust anchor can omit those certificate fields.
Self-issued CAs do not receive a path-length exemption in this subset.

The existing `opc-identity`/`opc-tls` material admission contract still applies
before endpoint construction. In particular, local SPIFFE material must meet
its existing TLS usage requirements. Peer verification independently admits
the certificate's corresponding single TLS role or an absent EKU; the added
profile cannot relax the upstream controller's local admission contract.

## Qualification and remaining work

`crates/opc-diameter-transport/tests/fixtures/rfc6083/nds_certificates.py`
independently builds and classifies 146 deterministic signed cases with public
synthetic keys: 22 admissions and 124 refusals. The TSV SHA-256 is
`1a9968c0889344ec64f8ef30d2ff1d3f2ec50c60ed13a98c3cb1856795ea6f09`.
It covers both roles, both curves, stronger/weaker issuers, direct CA anchors,
names/encodings, criticality, usage, expiry, revocation and ambiguous anchors.
The original certificate and CRL corpora and pinned fixture contract remain
byte-identical. The new generator imports no SDK or catalog implementation.

Every case reaches the SDK's actual peer-path verifier with complete signed
CRLs. Separate mutual DTLS tests check accepted profiles, local refusal,
selected/unused anchors, exact expiry readback, rekey and queued-delivery
retirement. Adversarial peers bypass only their local profile check while
retaining genuine DTLS signatures/SPIFFE/SNI; the honest peer independently
rejects them. A private Linux SCTP-AUTH case runs all three ciphers, both
roles and six rekey transitions per peer with stream delivery and close.
The required native runner resolves eleven exact cases, with zero ignored
tests and explicit completion markers. Ordinary Cargo ignores are not native
evidence. These are independent-fixture and SDK/kernel observations, not
external-peer interoperability.

Thirteen isolated negative controls each compile and then fail one exact
runtime test: twelve removed enforcement checks and one independently signed
anchor mutation. All mutated source bytes are restored before qualification.
A separate parent compilation confirms that the public profile API was absent;
that compilation failure is not runtime evidence.

```sh
python3 crates/opc-diameter-transport/tests/fixtures/rfc6083/nds_certificates.py
cargo test --locked -p opc-diameter-transport --all-features
# Build the library test binary and run ci/qualify-rfc6083-native.sh as in CI.
# The runner requires root inside a fresh private network namespace.
```

RSA/DHE negotiation and certificate support, remote CRL retrieval (including
LDAPv3), OCSP, full combined 3GPP profile qualification and external-peer
interoperability remain open. This adds no fetching, certificate issuance,
application policy, DTLS 1.3 or resumption. Refs #794, #784 and #795.

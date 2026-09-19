# Named RFC 6083 endpoints

`rfc6083::ServerName::new` creates one bounded ASCII DNS name. Apply it to
`Connector::with_server_name` and `Acceptor::with_server_name` before opening
the association. The connector emits RFC 6066 `host_name` and requires the
server's empty acknowledgement. The acceptor requires that exact name and
checks that its admitted certificate contains the corresponding DNS SAN.
Neither endpoint silently falls back when configured with a name.

The connector independently verifies the DNS SAN of the authenticated server
certificate. The existing exact SPIFFE peer, trust-domain chain, validity,
role and optional required-CRL checks still apply. A matching DNS name grants
no peer or trust authority. There is no CN fallback, wildcard matching,
network DNS lookup, virtual-host callback or peer-directed credential lookup.
The caller selects the credential controller and expected SPIFFE identity.

Names are at most 253 ASCII bytes with nonempty labels of at most 63 bytes.
Labels use letters, digits and interior hyphens. Matching ignores ASCII case;
the stored copy is lowercase. IP literals, trailing dots, wildcards, embedded
NULs and Unicode input are refused. The caller performs any A-label conversion.
These are explicit resource and name-profile bounds. The extension's list,
type and lengths follow [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
Unknown name types, multiple entries and duplicate extensions are refused.

The default endpoints do not advertise or acknowledge SNI. An unconfigured
acceptor can ignore a well-formed name; a configured connector then rejects
the missing acknowledgement. An unsolicited or nonempty server
acknowledgement is always refused. The name is immutable within a connection
and is sent, checked and certificate-validated again during coordinated
[rekey](rfc6083-rekey-transport.md). `Evidence::server_name` reports it only on
an established connection after the existing live readback checks. Debug and
errors omit its value; `as_str` is an explicit borrowed accessor.

## Qualification

`vendor/dimpl/tests/dtls12/rfc6066_reference.py --check` reproduces 109
independently framed extension and AES-GCM-protected Hello cases: 11 admitted
name/acknowledgement checks and 98 refusals. The TSV SHA-256 is
`987802915ffc4be74421a2c770f1d17253e1cc8a2db9699710e3741ba2a10517`.
Python writes lengths and record authentication independently of the Rust
implementation. Both production Hello handlers consume those encrypted
records under the synthetic record-test context. This is parser/negotiation
evidence, not certificate or external-peer interoperability evidence.

Genuine mutual-certificate SDK tests separately cover all three supported
ciphers, same-name rekey, stream delivery, missing/wrong names, missing/wrong
DNS SANs, CN/wildcard refusal and unchanged SPIFFE/trust enforcement. An
adversarial authenticated test peer acknowledges SNI while bypassing its own
local SAN check; the production connector must independently refuse its
certificate. Positive control uses the same peer with a matching DNS SAN.

The parent revision lacks the public name type, retained as a compile-time
API detector. Nine production guard removals compile and fail their exact
runtime tests: both Hello checks, both extension emissions, name retention
on rekey, the client DNS verifier and its configured input, the local-server
SAN guard and the name-length bound. Mutating an independently admitted
extension also fails. Each source is restored byte for byte. A separate
native wire-name mutation must fail the capture checker even after the real
Rust test passes; this separates live endpoint success from wire evidence.

The SNI increment qualified ten SCTP-AUTH cases, including three
named associations and two rekeys per peer. Its independent bounded loopback
capture requires the exact initial ClientHello name and empty ServerHello
acknowledgement in all three associations, key IDs 0 through 3 matching DTLS
epochs, old-key ChangeCipherSpec, a handshake first under every new key, and
zero capture drops. Rekey names remain encrypted; their preservation is
covered by endpoint checks and the independently encrypted adversarial
fixtures. Capture metadata alone does not prove HMAC validation or key
deletion. Ordinary ignored tests are not native qualification.

```sh
python3 vendor/dimpl/tests/dtls12/rfc6066_reference.py --check
cargo test --locked -p opc-diameter-transport --all-features
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml --all-features --all-targets
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml \
  --no-default-features --features rust-crypto --all-targets
# Run ci/qualify-rfc6083-native.sh with the compiled transport test binary
# inside a fresh privileged network namespace; see the CI workflow.
```

## Remaining 3GPP profile work

[TS 33.501 V18.12.0 clause 9.2](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/18.12.00_60/ts_133501v181200p.pdf)
references RFC 6083 and the TLS/certificate profiles. Its clause 9.1.2 also
specifies separate IKE/IPsec obligations. SNI does not complete those profiles.

| Profile requirement | Current bounded SDK support | Remaining evidence or implementation |
| --- | --- | --- |
| [TS 33.210 V18.2.0 clause 6.2.3](https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/18.02.00_60/ts_133210v180200p.pdf): cipher/signature profile | ECDHE-ECDSA AEAD suites; P-256/P-384 and SHA-256/SHA-384 | Mandatory DHE-RSA AES-128-GCM and RSA signature profile; associated parameter validation and independent interoperability |
| Same TLS profile: extensions | Signature algorithms, supported groups, extended master secret, coordinated RFC 5746 rekey and explicit RFC 6066 SNI | Complete combined-profile qualification; recommended OCSP/resumption are outside this transport |
| [TS 33.310 V18.8.0 clause 6.1.3a](https://www.etsi.org/deliver/etsi_ts/133300_133399/133310/18.08.00_60/ts_133310v180800p.pdf): TLS entity certificate profile | Exact SPIFFE identity and optional DNS SAN, chain/time/role checks and opt-in complete direct CRLs | The later [bounded ECDSA certificate profile](rfc6083-certificate-profile.md) adds operator certificate constraints and independent signed fixtures; RSA, remote CRL retrieval and OCSP remain unsupported |

The older hash-pinned fixture contract retains its original scope. This
increment adds no dependencies, DTLS 1.3, resumption or application identity
policy. Refs #794, #784 and #795; the aggregate issues remain open.

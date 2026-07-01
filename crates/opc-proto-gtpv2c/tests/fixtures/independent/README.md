# Independent GTPv2-C captures

No independent GTPv2-C capture is committed yet. Add files here only after the
capture source, independent implementation and version, license/permission,
redaction status, and expected byte-exact re-encode behavior are documented per
ADR 0015 and `tests/fixtures/README.md`.

Each capture is one sanitized GTPv2-C datagram in a `.bin` file with a sibling
`.metadata` file using `key: value` lines. The replay harness rejects captures
without finalized metadata and requires `expected_raw_preserving_reencode:
byte_exact`.

Required metadata keys:

```text
capture_kind: independent-peer-s2b
independent_implementation: <implementation or product family, sanitized if needed>
implementation_version: <version or build identifier approved for disclosure>
capture_permission: <license/permission statement for committing sanitized bytes>
redaction_review: <reviewer/date or approved process identifier>
redacted_fields: <IMSI/MSISDN/APN/IP/TEID/session/private fields redacted or synthetic>
synthetic_replacements: <documentation-range replacements used in the byte stream>
expected_message: <S2b procedure and request/response direction>
expected_raw_preserving_reencode: byte_exact
fuzz_seed_policy: <allowed or not-allowed, with reason>
reviewer: <human or process owner approving public commit>
```

Do not commit a capture when any metadata value is `todo`, `tbd`, `pending`, or
`unknown`. Do not commit packet bytes containing real subscriber identifiers,
real APNs/DNNs, routable customer or peer IPs, production TEIDs/session IDs,
private/vendor IEs that reveal deployment topology, LI identifiers, key material,
tokens, hostnames, or other deployment secrets.

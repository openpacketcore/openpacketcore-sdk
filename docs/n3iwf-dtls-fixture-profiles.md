# N2 DTLS fixture profile inventory

The `n2-dtls` catalog preserves its fifteen original framing/metadata/label
records and ten stream-zero lifecycle records byte for byte. Ten additive
`rfc6083-profile-evidence-reference` records connect consumers to the later
bounded SDK profiles. Their 634 cases contain synthetic roles, row indices,
operations and outcomes. They contain no credential blobs, key values,
encrypted records or endpoint names.

| Family | Published cases | Bound source and scope |
| --- | ---: | --- |
| Certificate profile | 146 | Independent positive/negative certificate corpus; bounded ECDSA profile |
| CRL profile | 52 | Independent local complete-CRL corpus; no network retrieval or OCSP |
| Stream framing | 159 | All 92 framing admissions and 67 selected refusals from the 18,560-row source |
| Rekey binding | 100 | Independent RFC 5746 extension cases, including missing/duplicate/truncated/mismatched bindings |
| Protected rekey Hello | 13 | Independent authenticated Hello cases, referenced without their record octets |
| Server name | 109 | Independent RFC 6066 cases; name values omitted from the projection |
| Coordinated rekey | 25 | Three ciphers and three epochs in both roles; policy, cancellation, age and credential withdrawal |
| Publication retirement | 16 | Both roles, seven publication changes and withdrawal during rekey |
| Native path loss | 8 | Both role arrangements, DATA-drop qualification, surviving path, total loss and fresh association |
| Native process restart | 6 | Both roles, actual peer-process death, wrong replacement identity and fresh authenticated replacement |

Each vector projection identifies its original one-based data-row number and
the SHA-256 of the entire source corpus. The stream record explicitly publishes
the full source count separately from its selected-case count. Framing
admission is not successful DTLS authentication. The certificate/CRL and
protected-Hello source generators are independently checked in the existing
audited-DTLS CI environment; the catalog gate needs only Python's standard
library and verifies their exact pinned bytes.

The lifecycle records are authored obligations with digest-bound test source
and exact function names. They do not contain a transcript or claim a fresh
execution. Runtime evidence remains with the separately qualified
[rekey](rfc6083-rekey-transport.md),
[CRL retirement](rfc6083-crl-transport.md),
[ordered streams](rfc6083-stream-transport.md),
[certificate](rfc6083-certificate-profile.md),
[server-name](rfc6083-server-name.md),
[path-loss](rfc6083-native-path-qualification.md) and
[process-restart](rfc6083-process-restart-qualification.md) contracts.
Native execution requires the explicit private-namespace runner and zero
ignored cases. Neither source lookup nor an ordinary ignored test run supplies
that evidence.

Every new manifest keeps `runtime_claim=false`, `execution_claim=false`,
`requires_separate_runtime_qualification=true` and
`external_interoperability=false`. Its constructed outcome means a reference
record was constructed. The old receive-labelled rekey/rotation/path records
remain labels. The old stream-zero records retain their explicit exclusions;
the additive records do not silently promote them to broader transport proofs.

The remaining exclusions include arbitrary 3GPP PKI, remote CRLs, OCSP, in-place
SCTP association restart, host reboot, resumption and interoperability with
another implementation. Exact wire bodies, counters, kernel key deletion and
remote delivery are not observations made by this fixture crate.

`scripts/n3iwf_dtls_profile_reference.py --check` checks source digests,
projections, lifecycle obligations, inventory, provenance and all scope flags
independently of the catalog writer. Regression tests try substituted row
indices, rewritten outcomes with corrected local digests, truncated records,
source drift, copied record fields, boolean/integer substitutions and promoted
execution claims. Historical manifest/wire identity is checked against the
parent revision. Publication uses the existing content-commit then stamp-commit
scheme in `fixtures/PUBLIC_SDK.json`, so base, content head and fixture tree can
be verified without a self-referential Git hash. Refs #784 and #795.

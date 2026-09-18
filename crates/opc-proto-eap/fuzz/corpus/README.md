# EAP-AKA fuzz corpus

The `project_packet` target accepts complete arbitrary byte slices. Its
`project_packet/` directory contains redaction-safe valid and malformed seeds.
Semantic seeds use a harness-only `hex:` envelope so the repository can retain
binary packet shapes without opaque subscriber data. LibFuzzer's generated
corpus and failure artifacts remain local or CI artifacts and must not contain
production packet captures.

## EAP-5G seeds

`eap5g_packet/` contains raw bytes decoded from all eleven published synthetic
`opc-n3iwf-fixtures/fixtures/eap5g/wire/*.hex` vectors. The corresponding
manifests retain their source clauses, provenance and SHA-256 digests. No
captured traffic is used. Run fuzzing with a separate writable corpus when
preserving this small reviewed seed inventory.

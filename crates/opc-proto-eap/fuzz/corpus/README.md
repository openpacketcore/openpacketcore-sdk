# EAP-AKA fuzz corpus

The `project_packet` target accepts complete arbitrary byte slices. Its
`project_packet/` directory contains redaction-safe valid and malformed seeds.
Semantic seeds use a harness-only `hex:` envelope so the repository can retain
binary packet shapes without opaque subscriber data. LibFuzzer's generated
corpus and failure artifacts remain local or CI artifacts and must not contain
production packet captures.

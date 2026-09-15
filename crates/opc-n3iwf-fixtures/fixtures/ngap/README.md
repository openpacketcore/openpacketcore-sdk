# NGAP N3IWF fixture subset

Reuses the issue 493 DecodeContext / IE cardinality contract and the
sanitized 78-byte derivative of the legacy libngap structural vector. It is
not an independent Release-18 N3IWF message oracle. IE tables are extracted
separately from TS 38.413 V18.10.0 ASN.1, including presence rules. TS 29.413
V18.5.0 clauses 5.2–5.4 decide which first-CNF messages are admitted for
N3IWF. Canonical typed encode remains unsupported.

`matrices/` publishes identifier/criticality/cardinality for every admitted
first-CNF sent/received outcome plus Paging (5.4 discard). TS 29.413 5.2
messages outside the issue 493 typed subset stay unpublished. Clause 5.3
RAN-specific ignore is not encoded in the rows. Constructed N3IWF send is
unsupported. This crate does not select an AMF or apply subscriber policy.

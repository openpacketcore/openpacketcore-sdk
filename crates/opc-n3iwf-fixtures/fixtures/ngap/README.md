# NGAP N3IWF fixture subset

Reuses the issue 493 DecodeContext / IE cardinality contract and the
public 78-byte Rel-18 NGSetupRequest vector (TS 38.413 V18.10.0). TS 29.413
V18.5.0 clauses 5.2–5.4 decide which first-CNF messages are admitted for
N3IWF. Canonical typed encode remains unsupported.

`matrices/` publishes identifier/criticality/cardinality for every admitted
sent/received outcome plus Paging (5.4 discard). Constructed N3IWF send is
unsupported. This crate does not select an AMF or apply subscriber policy.


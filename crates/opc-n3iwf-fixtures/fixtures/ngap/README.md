# NGAP N3IWF fixture subset

Complete messages for all 15 admitted outcomes are independently
encoded and decoded with Pycrate 0.8.1 compiled directly from the hash-pinned
TS 38.413 V18.10.0 publication. They contain N3IWF identifiers, location and
nested PDU-session transfers. Negative cases separate reference admission
from the current SDK's structural decoder. The legacy empty wrappers remain
at `aper-structural-dispatch`; the new scope is `ngap-release18-message`.

The reference gate validates ASN.1 constraints, mandatory fields, criticality,
cardinality, nested transfers and enumerated TS 29.413 N3IWF conditions.
NAS remains opaque. SecurityKey, where present, is an all-zero synthetic
placeholder; these vectors do not prove key derivation or authentication.

`matrices/` publishes identifier/criticality/cardinality for every admitted
first-CNF sent/received outcome plus Paging (5.4 discard). Each admitted matrix
links to a complete independently validated positive vector. TS 29.413 5.2
messages outside the issue 493 typed subset stay unpublished. Clause 5.3
RAN-specific ignore is not encoded in the rows. Canonical SDK encoding and
SDK semantic admission remain unsupported (#787). No real AMF exchange,
AMF selection or subscriber policy is claimed.

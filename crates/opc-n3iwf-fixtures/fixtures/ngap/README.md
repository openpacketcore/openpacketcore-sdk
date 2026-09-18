# NGAP N3IWF fixture subset

Complete messages for all 23 qualified outcomes are independently
encoded and decoded with Pycrate 0.8.1 compiled directly from the hash-pinned
TS 38.413 V18.10.0 publication. They contain N3IWF identifiers, location and
nested PDU-session transfers. Negative cases separate reference admission
from the current SDK's structural decoder. The legacy empty wrappers remain
at `aper-structural-dispatch`; the new scope is `ngap-release18-message`.

The 68 complete-message cases include 16 unchanged vectors from the existing
UE-request, Reset, Notify and Modify corpora in `opc-proto-ngap/tests/fixtures`.
Their source files and individual cases are pinned by digest. The gate checks
those references before independently recompiling and checking the recipes.
Reset, Reset Acknowledge and Error Indication apply in either direction.

The reference gate validates ASN.1 constraints, mandatory fields, criticality,
cardinality, nested transfers and enumerated TS 29.413 N3IWF conditions.
NAS remains opaque. SecurityKey, where present, is an all-zero synthetic
placeholder; these vectors do not prove key derivation or authentication.

`matrices/` publishes identifier/criticality/cardinality for every admitted
first-CNF sent/received outcome plus Paging (5.4 discard). Each admitted matrix
links to a complete independently validated positive vector. TS 29.413 5.2
messages requiring an external handler stay unpublished. Clause 5.3
RAN-specific ignore is not encoded in the rows. SDK tests compare every opaque
IE and canonical container with independent bytes; typed field admission is
qualified separately in `opc-proto-ngap` (#787). No real AMF exchange,
AMF selection or subscriber policy is claimed.

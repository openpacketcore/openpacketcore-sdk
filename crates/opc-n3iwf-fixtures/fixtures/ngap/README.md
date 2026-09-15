# NGAP N3IWF fixture subset

Reuses the issue 493 DecodeContext / IE cardinality contract and the
public 78-byte NGSetupRequest vector. Canonical typed encode remains
unsupported. Release 18 identifier/criticality/cardinality matrices for the
typed procedures live in `crates/opc-proto-ngap/src/policy.rs` and are
cited by path. The 78-byte vector is copied by digest and locked to that
source file by `tests/contracts.rs`.

Admitted send/receive outcomes in this subset: receive NGSetupRequest and
empty wrappers. Constructed N3IWF encode is unsupported until issue 787.


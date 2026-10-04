# Protocol-key fixture subset

Independent RFC 7296 IKE AUTH known answers for both peers use complete
synthetic SA_INIT messages, public test P-256 scalars, and the zero NGAP
SecurityKey placeholder. Published negative cases and bit/prefix mutations
check transcript, identity, nonce, direction, key and MIC binding through the
existing SDK crypto API. AUTH payload bodies are not complete protected IKE
exchanges, peer authentication, or K_AMF hierarchy derivation evidence.

Legacy scenario labels still model wrong-generation, reuse, drop and
cancellation obligations for issue 791. They do not exercise a custody API
or prove actual memory zeroization. Twenty-five separate scenario records replay
wrong-generation, reuse, foreign/stale authority, invalid handoff/input, drop,
cancellation and concurrent consumption through the public SDK API. Every
successful consumption must match both independent AUTH answers. The existing
private zeroization audit separately checks clearing before buffer release;
opaque public errors are not used to infer that result. Monotonic local labels
are SDK policy, not wire-standard obligations. No real key or nonce is published.

# Protocol-key fixture subset

Independent RFC 7296 IKE AUTH known answers for both peers use complete
synthetic SA_INIT messages, public test P-256 scalars, and the zero NGAP
SecurityKey placeholder. Published negative cases and bit/prefix mutations
check transcript, identity, nonce, direction, key and MIC binding through the
existing SDK crypto API. AUTH payload bodies are not complete protected IKE
exchanges, peer authentication, or K_AMF hierarchy derivation evidence.

Legacy scenario labels still model wrong-generation, reuse, drop and
cancellation obligations for issue 791. They do not exercise a custody API
or prove actual memory zeroization. No real peer key or nonce is published.

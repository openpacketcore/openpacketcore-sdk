# opc-key-hygiene-probe

Test-only allocator probe for issue #1262 security-key hygiene.

The SDK crates forbid `unsafe`, but an allocator wrapper is the only portable
way to observe whether a dropped heap buffer still contains key octets before
the memory is released. This `publish = false` crate is the single scoped
exception: it installs a global allocator that counts frees of blocks still
containing a fixed 32-octet marker. It records only a hit count, never
allocation contents.

Tests in `tests/` prove, with positive controls, that the probe observes both
`Vec` and `bytes::Bytes` deallocations, then assert zero hits for:

- a decoded NGAP key-bearing PDU after drop (raw receive copy, extracted key
  owner, IE placeholders);
- a decode that fails after the security-key IE was parsed;
- a key-free PDU (negative control);
- SCTP `SensitiveBytes`, `InboundMessage` and admitted `N2Payload` drops.

The crate is intentionally tiny and adds no runtime dependency to the SDK.

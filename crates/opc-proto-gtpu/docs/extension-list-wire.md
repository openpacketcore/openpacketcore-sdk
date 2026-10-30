# Extension Header Type List wire correction

The typed Supported Extension Headers Notification codec now reads and
writes IE 141 as `type | u8 count | count extension types`. Previously it
incorrectly applied the general two-octet TLV length. For a list containing
`0x40, 0x85`, the correct IE is `8d 02 40 85`; the former output was
`8d 00 02 40 85` and its enclosing GTP-U length was one byte too large.

[TS 29.281 V18.4.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf),
figure 8.5-1, assigns the count to octet 2 and entries to octets 3 through
`n+2`. The generic TLV classification in table 8.1 does not replace that
IE-specific layout. Peer Address and Private Extension still use their
two-octet lengths. Public Rust models are unchanged.

The corrected typed decoder accepts counts 0 through 255 and retains
first-singleton, nonzero-type, duplicate-type, ordering, framing, message/IE cap
and output-cap checks. It does not admit an alternate legacy two-octet
format. The generic raw-preserving `GtpuMessage` codec remains unchanged;
it can still expose opaque payload bytes without validating this procedure.

`tests/fixtures/extension_list.py` independently constructs wire bytes
without importing SDK code. Its checked-in TSV contains **2,555 cases:
768 admissions and 1,787 refusals**, SHA-256
`1e94edc56d9db342337f9cb06f0b7d50b6f48efa234da3e405cee5c668e01e58`.
It spans every count, coexistence with a two-octet Private Extension TLV,
wrong counts, zero/duplicate types, first-wins duplicate lists, tails, truncation and
the former wide-length encoding. Separate send/receive tests fail on the
original codec. Existing control fixtures and both fuzz seed directories
use the corrected layout. The pinned N3IWF fixture catalog is unchanged.

```sh
python3 crates/opc-proto-gtpu/tests/fixtures/extension_list.py --check
cargo test --locked -p opc-proto-gtpu --all-features
```

These are synthetic specification-derived bytes. This correction does not
establish live-peer interoperability, a control socket, packet forwarding,
peer admission, rate policy or End Marker lifecycle ordering. Those
runtime contracts are documented with the [dataplane control port](../../opc-gtpu-dataplane/docs/control-port.md),
including the retained Linux/eBPF socket implementation for #341 and its
caller-owned admission, pacing and lifecycle limits.

Receiver correction #1521 applies TS 29.060 §11.1.12 (via TS 29.281 §9.1):
the 256 duplicate-list cases now admit the first list and canonical encoding
omits the later occurrence. Duplicate values inside a single list still fail.

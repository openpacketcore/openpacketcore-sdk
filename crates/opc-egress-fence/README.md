# opc-egress-fence

`opc-egress-fence` provides a protocol-neutral, lease-bound Linux tc/eBPF
egress gate for datagram sockets.

The crate is under active development for SDK issue #608. Its public contract
is fail-closed: traffic in the configured endpoint/mark domain is emitted only
while the exact 64-bit socket cookie has an unexpired suspend-aware kernel
deadline.

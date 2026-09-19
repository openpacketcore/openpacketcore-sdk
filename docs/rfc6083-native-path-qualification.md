# Native protected SCTP path qualification

The required Linux SCTP CI job runs seven real kernel RFC 6083 cases through
`ci/qualify-rfc6083-native.sh`. The script requires a private network namespace
before changing its SCTP-AUTH setting, builds nothing as root, and requires
every named test to resolve exactly once and report one pass with zero ignored
cases. A missing test, failed kernel prerequisite, timeout or ignored-only run
fails the job. Each case has a 60-second outer hang guard; its shorter operation
deadlines remain in force. Logs are retained as the `rfc6083-native` artifact.

The cases exercise required-CRL retirement in both roles, protected PPID 66
delivery and reciprocal close, terminal-carrier readback, refusal of unsafe
carriers, the existing Diameter transport, ordered application streams, and
the multihoming scenario below. These proofs compose the existing public
`SctpAssociation`, `rfc6083::Transport`, `Connector`, `Acceptor` and `Connection`
APIs. This increment changes qualification and CI, not production transport
behavior or authority construction.

## Fault model and assertions

`generic_kernel_multihoming_preserves_protection_and_bounds_total_path_loss`
creates real one-to-one SCTP associations with two local and two peer IPv4
loopback addresses in an isolated namespace. It requires pristine DATA AUTH
state and verifies the selected primary peer path before the protected
handshake. Both DTLS roles take turns on the SCTP connecting endpoint; DTLS
roles do not have to match the SCTP active/passive socket roles.

Before the handshake, a separate probe requires a nonzero total drop count
while the PPID 66 DATA count stays zero. This prevents heartbeats and other
non-DATA chunks from qualifying application-path loss. The two counters use
the kernel's [SCTP chunk expression](https://netfilter.org/projects/nftables/manpage.html)
and an all-SCTP drop rule for the selected destination. Both rules are scoped
to the current association's ports, excluding traffic from prior associations.

After mutual DTLS authentication, both directions exchange exact opaque
records on streams 0, 1, 2 and 15. A private nftables rule then drops all SCTP
traffic destined for one peer address of the connecting endpoint. SCTP can
change its active destination during the handshake, so the fixture tries
each of its two peer addresses at most once. An attempt with zero dropped
PPID 66 DATA packets cannot qualify path failure. The qualifying attempt leaves
the other peer address and all return destinations available. Delivery must still
succeed in both directions, and the kernel DATA counter must show actual
protected-data drops. A heartbeat-only counter is insufficient. Readback must
preserve the exact role, PPID, DTLS version, cipher, material epoch, both
certificate expiry bounds, expected
peer, stream count and correlation capacity. This scenario uses the explicit
profile without required CRLs; the separate native CRL case qualifies that
profile's retirement behavior.

A second rule blocks all four destinations. Both endpoints attempt protected
sends; neither may return received plaintext. The one-second absolute receive
deadline must retire both connections, and both readbacks must refuse access.
The PPID 66 DATA counter must again show traffic reaching the fault. Removing the
rule cannot revive the old connections. A fresh association must complete a
new mutual handshake, exchange protected records, expose valid readback, and
perform reciprocal close. RAII removes only the test-owned nftables table;
namespace destruction also bounds fault lifetime after a killed test.

RTO 100–400 ms (initially 200 ms), heartbeat 100 ms, one path retransmission,
ten-second connection, eight-second delivery, one-second blocked receive and
five-second close bounds are explicit test policies. They are not universal
network convergence guarantees or requirements of
[RFC 6083](https://www.rfc-editor.org/rfc/rfc6083.html).
The proof observes an actual destination-path fault and authenticated delivery;
it does not expose a new post-handshake SCTP path-observer API.

## Reproduction and limits

Build the transport's all-feature library test binary as an ordinary user:

```sh
cargo test --locked -p opc-diameter-transport --all-features --lib --no-run
sudo unshare --net -- bash ci/qualify-rfc6083-native.sh \
  /absolute/path/to/opc_diameter_transport-TEST_HASH /absolute/path/to/logs
```

Linux SCTP, network namespace support, `ip`, `sysctl`, `nft` and `timeout` are
required. CI obtains the exact binary from Cargo's JSON artifact output; it
does not select a stale binary by filename glob. The ordinary transport suite
continues to ignore these privileged cases, so its passing count is separate
from this native evidence.

This qualifies same-process association replacement after path loss, not
process restart, durable restoration of a protected connection, arbitrary
network topologies or interoperability with another implementation. The peer
is another SDK endpoint. In-place renegotiation, full 3GPP PKI and aggregate
fixture acceptance remain in #794 and #784. The older pinned fixture contracts
keep their original scopes; this document extends the separate
[stream transport profile](rfc6083-stream-transport.md).

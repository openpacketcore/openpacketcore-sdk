# N2 DTLS fixture subset

Legacy PPID 66 metadata, isolated ServerHelloDone framing, and lifecycle labels.
SCTP-AUTH length, verified identity, reliable delivery, and key rotation are
explicit caller preconditions. DATA B/E flags describe message boundaries;
they do not prove reliability. Restart/path failure and error labels model
scenarios without executing a transport or handshake. Ordinary PPID 60 associations cannot satisfy this subset. No
certificates or exporter secrets are published.

Ten separate rfc6083-stream-zero-lifecycle records bind eight existing independent
client-certificate vectors and 78 authored SDK lifecycle schedules. The generic
transport replays them using real mutual DTLS over the private in-memory SCTP
harness at protected PPID 66, ordered stream zero. They cover record bounds,
cancellation, deadlines, credential/trust replacement, withdrawal, terminal
carrier observations, reciprocal close, invalid metadata and foreign PPIDs.
Certificate vectors also run at protected Diameter PPID 47. Separate Linux
tests qualify the kernel adapter; these records do not claim kernel execution,
in-place rekey, multistream, revocation, restart or external interoperability.

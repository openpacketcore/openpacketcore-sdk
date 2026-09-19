# Native RFC 6083 peer process restart

The required Linux SCTP CI job executes
`generic_kernel_process_restart_requires_fresh_mutual_authentication` in a
private SCTP-AUTH network namespace. This is a real child-process crash and
replacement test of the existing public transport. It adds no production API,
resumption mechanism, deployment policy or in-place renegotiation support.

For each DTLS role, the parent and a separate process establish a fresh SCTP
association and mutual DTLS 1.2 authentication at protected PPID 66. They
exchange exact generation-tagged synthetic payloads on ordered streams 0, 1,
2 and 15. The child then queues another protected record. The parent sends
SIGKILL and requires the OS exit status to report signal 9. Rust destructors
and reciprocal DTLS close do not run at that crash cut.

Without calling application receive, the survivor must observe terminal
carrier state within five seconds. Readback and receive must then report
`ConnectionClosed`, including with the pre-crash record queued. A second
process loads a valid certificate signed by the same test CA but carrying the
wrong exact peer identity; a new mutual handshake must fail. A third process
loads newly issued credentials for the correct identity, performs a fresh
mutual handshake, exchanges generation-one payloads, and completes reciprocal
close. Each replacement binds the same listener address and port as its
predecessor. The two independent role scenarios use distinct ports to avoid
coupling through kernel state left by the first scenario's graceful close.
Its PID differs from both previous peers. The old connection must still
reject readback and send while the new connection is active.

Both endpoints inspect role, protected protocol, DTLS version, the explicitly
selected AES-128-GCM cipher, local credential/trust epoch, expected peer,
stream range, queue bound and redacted diagnostics. The parent additionally
compares both certificate expiry values to the exact generated identities.
Each new SCTP carrier must have a pristine RFC 6083 AUTH state before sealing.
Epochs are process-local observations; the test does not claim a persistent
or globally monotonic epoch across restarts.

Credentials are generated solely for this test and passed through a private
stdin pipe as bounded DER blobs. Keys are never stored in files, command-line
arguments, environment variables or logs. The stdout control pipe admits only
fixed stage markers. No DTLS engine state, traffic key, connection object or
prior readback is serialized into the replacement process. All child
processes are reaped, including on an assertion failure.

## Scope and reproduction

The test uses the same SDK implementation at both endpoints and a loopback
kernel SCTP association. It qualifies bounded peer-process death followed by
new-association authentication, including rejection of a wrong replacement
identity. It does not qualify in-place SCTP association restart, host reboot,
network partition, durable CRL rollback-floor storage, session resumption,
cross-implementation interoperability or the full 3GPP PKI profile. The
explicit profile here has no required CRL source; separate native tests cover
CRL retirement and multihoming path loss.

Five-second transport/termination guards, ten-second child-stage guards, the
fixed private listener ports and stream/cipher selection are test policies,
not standards limits. The CI runner retains a sixty-second outer test guard
and fails if the named case is missing, ignored, unavailable or unsuccessful.

Build the library test binary without root, using the Cargo JSON selection in
[the workflow](../.github/workflows/ci.yml). Run
[the native qualification script](../ci/qualify-rfc6083-native.sh) as root in a
fresh `unshare -n` namespace, with the absolute binary and log-directory paths
as arguments. All eight named cases must execute with zero ignored tests.
The final process-restart marker is required separately from the test count.

Related contracts: [generic transport](rfc6083-generic-transport.md),
[ordered streams](rfc6083-stream-transport.md), and
[native path qualification](rfc6083-native-path-qualification.md).

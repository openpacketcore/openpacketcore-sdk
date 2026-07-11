# opc-sa-mirror

Experimental live IPsec SA keymat mirroring for near-hitless failover in which
SA keys **never persist** (RFC 015).

## Purpose

An SA owner mirrors freshly derived keymat to a designated standby over mTLS;
the standby holds it exclusively in zeroizing memory and, on owner loss, yields
it together with validated `opc_ipsec_lb::SameSpiResume` evidence
(`ResumeKeySource::LiveMirrored`) for the fenced re-pin. Nothing on this path
can reach a persistence layer: the crate has no store dependency and the keymat
type is deliberately not serializable.

## API Shape

- `SaMirrorProducer` — owner-side port: `mirror_install`, `mirror_checkpoint`,
  `mirror_withdraw`.
- `SaMirrorSink` — standby-side inbound port fed by the transport server.
- `StandbyKeymatSource` — standby-side takeover port; `take_for_repin` yields
  `LiveMirroredTakeover { keymat, epoch, resume }` with the resume evidence
  already validated (mandatory forward-jump, bounded anti-replay reopening).
- `InMemoryStandbyHolder` implements both standby ports with epoch
  anti-rollback, constant-time idempotency, and a fail-closed capacity bound.
- `RemoteMirrorProducer::new(addr, tls_config, deadline)` — mTLS producer
  client. There is **no plaintext mode**, not even behind a test feature.
- `SaMirrorReceiver::new(sink, tls_config)` + `listen(bind_addr)` — mTLS
  receiving server; `with_max_connections`, `with_max_frame_size`,
  `with_idle_timeout` configure it.
- `InProcessMirrorProducer` — in-memory fake mesh for tests.

## Custody invariant

The plane that persists never holds keys; the plane that holds keys never
persists. See `docs/rfc/015-live-sa-mirror.md` for the full design, the
normative takeover ordering, and the deployment-side memory controls
(no swap, `RLIMIT_CORE=0`, ptrace denied).

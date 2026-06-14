# opc-mgmt-opstate

The NF-supplied operational-state provider contract for the OpenPacketCore
management plane.

`opc-config-bus` owns *configuration*; it does not hold config-false
(operational/state) data. gNMI `Get(STATE|OPERATIONAL|ALL)` and NETCONF `<get>`
must read that data from the consuming NF. This crate defines the seam every CNF
implements: [`OperationalStateProvider`].

The defining rule is **anti-fabrication**: a provider returns values only for the
SDK-canonical `YangPath`s it can actually supply. Omitting a requested path means
"no operational data here" — the server simply omits it — and the provider must
never invent a value or an origin it does not know. NMDA [`Origin`] metadata is
attached only when requested and genuinely known.

Values are carried as syntax-checked RFC 7951 JSON strings so this stays
decoupled from any particular generated model while still failing closed on
malformed provider output. `OperationalResponse::validate_for_request` lets
servers reject provider responses that report unrequested paths, duplicate paths,
or origin metadata the request did not ask for. The streaming on-change
subscription used by gNMI `Subscribe`/NETCONF notifications is layered in the
Subscribe slice, not here.

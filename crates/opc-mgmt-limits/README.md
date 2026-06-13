# opc-mgmt-limits

Shared, fail-closed input-bound limits for the OpenPacketCore management plane.

`opc-runtime`'s `ResourceBudget` is advisory and is **not** enforced on sockets,
so the gNMI and NETCONF servers must bound their own input. This crate gives both
servers one validated `MgmtLimits` struct (max message bytes, paths per request,
value bytes, XML depth/attributes/namespace declarations, subscriber queue bytes,
subscriptions per session, sessions) with conservative production defaults and
typed over-limit errors, so "no protocol parser accepts unbounded input" is
enforced identically on both transports.

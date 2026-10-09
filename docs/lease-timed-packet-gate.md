# Retired lease-timed namespace packet gate proposal

Status: retired. [RFC 022](rfc/022-scope-leases.md#untimed-authority) now defines
untimed scope authority. Ownership does not expire, and elapsed time or store
unavailability does not authorize stopping installed forwarding or succeeding
an unconfirmed lost worker.

The previous proposal's renewal, packet-stop and remote-exclusion deadlines
are not part of the current scope contract. The unused experimental
clock-conversion API has been removed.

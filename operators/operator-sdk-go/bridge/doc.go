// Package bridge provides a hardened subprocess client for the OpenPacketCore
// Rust lifecycle CLI (operator-lifecycle-cli).
//
// It handles contract-version handshake, structured error decoding, timeout
// enforcement, and mapping of CLI outcomes to Kubernetes conditions/events.
package bridge

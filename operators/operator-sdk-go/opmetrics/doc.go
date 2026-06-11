// Package opmetrics provides Prometheus collectors and event-recorder wiring
// for OpenPacketCore operators, using metric names defined in RFC 009 §17.
//
// It integrates with controller-runtime's metrics registry and provides
// helpers to instrument reconcile loops, drain operations, and version-skew
// detection.
package opmetrics

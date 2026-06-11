// Package conditions implements the RFC 009 condition and phase state machine
// for OpenPacketCore operators.
//
// It provides stable condition-type constants, a ConditionManager that enforces
// monotonic observedGeneration and correct LastTransitionTime semantics, and
// phase-transition guards (CanTransition) for the lifecycle state machine.
package conditions

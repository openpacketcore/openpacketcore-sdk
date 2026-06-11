// Package drain orchestrates graceful shutdown of CNF pods via the
// opc-runtime admin drain endpoints.
//
// It defines an Orchestrator interface, provides an HTTP-based implementation,
// and integrates with the reference reconciler to drive the Draining phase
// and finalizer.
package drain

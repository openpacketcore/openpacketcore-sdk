// Package conditions implements the RFC 009 condition and phase state machine
// for OpenPacketCore operators.
//
// It provides stable condition-type constants, a ConditionManager that enforces
// monotonic observedGeneration and correct LastTransitionTime semantics, and
// phase-transition guards (CanTransition) for the lifecycle state machine.
package conditions

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConditionType defines the stable condition types from RFC 009 §6.
type ConditionType string

// Condition types named in RFC 009 §6, plus the additional operational
// conditions used by the reference controller.
const (
	Admitted          ConditionType = "Admitted"
	Resolved          ConditionType = "Resolved"
	Provisioned       ConditionType = "Provisioned"
	Bootstrapped      ConditionType = "Bootstrapped"
	ConfigResolved    ConditionType = "ConfigResolved"
	AppConfigApplied  ConditionType = "AppConfigApplied"
	Drift             ConditionType = "Drift"
	MigrationReady    ConditionType = "MigrationReady"
	MigrationApplied  ConditionType = "MigrationApplied"
	DrainReady        ConditionType = "DrainReady"
	RollbackAvailable ConditionType = "RollbackAvailable"
	Ready             ConditionType = "Ready"
	Degraded          ConditionType = "Degraded"
	Progressing       ConditionType = "Progressing"
	DrainComplete     ConditionType = "DrainComplete"
	RecoveryRequired  ConditionType = "RecoveryRequired"
)

// Phase defines the lifecycle phases from RFC 009 §5.
type Phase string

// Lifecycle phases named in RFC 009 §5.
const (
	PhaseAdmitted      Phase = "Admitted"
	PhaseResolved      Phase = "Resolved"
	PhaseProvisioning  Phase = "Provisioning"
	PhaseBootstrapping Phase = "Bootstrapping"
	PhaseConfiguring   Phase = "Configuring"
	PhaseVerifying     Phase = "Verifying"
	PhaseReady         Phase = "Ready"
	PhaseDraining      Phase = "Draining"
	PhaseMigrating     Phase = "Migrating"
	PhaseDegraded      Phase = "Degraded"
	PhaseFailed        Phase = "Failed"
	PhaseTerminating   Phase = "Terminating"
)

// ErrStaleGeneration is returned when a condition write targets a generation
// older than the manager's current observedGeneration.
type ErrStaleGeneration struct {
	TargetGeneration   int64
	ObservedGeneration int64
}

func (e ErrStaleGeneration) Error() string {
	return fmt.Sprintf("stale generation: target %d < observed %d", e.TargetGeneration, e.ObservedGeneration)
}

// ConditionManager wraps a condition slice with enforcement of RFC 009
// semantics: monotonic observedGeneration, LastTransitionTime bumped only
// on status change, and stable ordering.
type ConditionManager struct {
	conditions         []metav1.Condition
	observedGeneration int64
}

// NewConditionManager creates a manager for the given observedGeneration.
func NewConditionManager(observedGeneration int64) *ConditionManager {
	return &ConditionManager{observedGeneration: observedGeneration}
}

// LoadConditions seeds the manager from an existing condition slice,
// preserving order. The observedGeneration is not changed.
func (cm *ConditionManager) LoadConditions(conds []metav1.Condition) {
	cm.conditions = make([]metav1.Condition, len(conds))
	copy(cm.conditions, conds)
}

// Set updates or creates a condition of the given type. It returns
// ErrStaleGeneration if generation is older than the manager's current
// observedGeneration.
func (cm *ConditionManager) Set(ct ConditionType, status metav1.ConditionStatus, reason, message string, generation int64) error {
	if generation < cm.observedGeneration {
		return ErrStaleGeneration{TargetGeneration: generation, ObservedGeneration: cm.observedGeneration}
	}
	now := metav1.NewTime(time.Now().UTC())
	for i := range cm.conditions {
		if cm.conditions[i].Type == string(ct) {
			if cm.conditions[i].Status != status {
				cm.conditions[i].LastTransitionTime = now
			}
			cm.conditions[i].Status = status
			cm.conditions[i].Reason = reason
			cm.conditions[i].Message = message
			cm.conditions[i].ObservedGeneration = generation
			cm.observedGeneration = generation
			return nil
		}
	}
	cm.conditions = append(cm.conditions, metav1.Condition{
		Type:               string(ct),
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: generation,
	})
	cm.observedGeneration = generation
	return nil
}

// SetReason updates only the Reason and Message of an existing condition,
// preserving Status and LastTransitionTime.
func (cm *ConditionManager) SetReason(ct ConditionType, reason, message string) {
	for i := range cm.conditions {
		if cm.conditions[i].Type == string(ct) {
			cm.conditions[i].Reason = reason
			cm.conditions[i].Message = message
			return
		}
	}
}

// Get returns the condition for the given type, or nil if absent.
func (cm *ConditionManager) Get(ct ConditionType) *metav1.Condition {
	for i := range cm.conditions {
		if cm.conditions[i].Type == string(ct) {
			return &cm.conditions[i]
		}
	}
	return nil
}

// Conditions returns the current slice in a stable order.
func (cm *ConditionManager) Conditions() []metav1.Condition {
	out := make([]metav1.Condition, len(cm.conditions))
	copy(out, cm.conditions)
	return out
}

// ObservedGeneration returns the highest generation seen by this manager.
func (cm *ConditionManager) ObservedGeneration() int64 {
	return cm.observedGeneration
}

// SyncToStatus copies the managed conditions and observedGeneration into the
// provided status object. The status type must implement the two setters.
func (cm *ConditionManager) SyncToStatus(setConditions func([]metav1.Condition), setObservedGen func(int64)) {
	setConditions(cm.Conditions())
	setObservedGen(cm.observedGeneration)
}

// transitionGraph encodes the legal phase transitions from RFC 009 §5.
// Any phase can transition to Failed and Terminating. Terminating is terminal.
var transitionGraph = map[Phase][]Phase{
	PhaseAdmitted:      {PhaseResolved, PhaseFailed, PhaseTerminating},
	PhaseResolved:      {PhaseProvisioning, PhaseFailed, PhaseTerminating},
	PhaseProvisioning:  {PhaseBootstrapping, PhaseFailed, PhaseTerminating},
	PhaseBootstrapping: {PhaseConfiguring, PhaseFailed, PhaseTerminating},
	PhaseConfiguring:   {PhaseVerifying, PhaseFailed, PhaseTerminating},
	PhaseVerifying:     {PhaseReady, PhaseDegraded, PhaseFailed, PhaseTerminating},
	PhaseReady:         {PhaseDraining, PhaseMigrating, PhaseDegraded, PhaseFailed, PhaseTerminating},
	PhaseDraining:      {PhaseReady, PhaseDegraded, PhaseFailed, PhaseTerminating},
	PhaseMigrating:     {PhaseReady, PhaseDegraded, PhaseFailed, PhaseTerminating},
	PhaseDegraded:      {PhaseReady, PhaseDraining, PhaseMigrating, PhaseFailed, PhaseTerminating},
	PhaseFailed:        {PhaseAdmitted, PhaseTerminating},
	PhaseTerminating:   {},
}

// CanTransition reports whether a transition from -> to is legal per RFC 009.
func CanTransition(from, to Phase) bool {
	if from == to {
		return true
	}
	allowed, ok := transitionGraph[from]
	if !ok {
		return false
	}
	for _, p := range allowed {
		if p == to {
			return true
		}
	}
	return false
}

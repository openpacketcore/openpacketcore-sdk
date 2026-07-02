package conditions

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConditionTypeConstants(t *testing.T) {
	// Verify all RFC 009 §6 constants are present.
	want := []ConditionType{
		Admitted, Resolved, Provisioned, Bootstrapped,
		ConfigResolved, AppConfigApplied, Drift,
		MigrationReady, MigrationApplied, DrainReady,
		RollbackAvailable, Ready,
	}
	for _, ct := range want {
		if ct == "" {
			t.Errorf("condition constant must not be empty")
		}
	}
}

func TestPhaseConstants(t *testing.T) {
	want := []Phase{
		PhaseAdmitted, PhaseResolved, PhaseProvisioning,
		PhaseBootstrapping, PhaseConfiguring, PhaseVerifying,
		PhaseReady, PhaseDraining, PhaseMigrating,
		PhaseDegraded, PhaseFailed, PhaseTerminating,
	}
	for _, p := range want {
		if p == "" {
			t.Errorf("phase constant must not be empty")
		}
	}
}

func TestNewConditionManager(t *testing.T) {
	cm := NewConditionManager(5)
	if cm.ObservedGeneration() != 5 {
		t.Fatalf("expected observedGeneration 5, got %d", cm.ObservedGeneration())
	}
	if len(cm.Conditions()) != 0 {
		t.Fatal("expected empty conditions")
	}
}

func TestSetCreatesCondition(t *testing.T) {
	cm := NewConditionManager(1)
	if err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conds := cm.Conditions()
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}
	if conds[0].Type != string(Ready) {
		t.Errorf("unexpected type: %s", conds[0].Type)
	}
	if conds[0].ObservedGeneration != 1 {
		t.Errorf("unexpected generation: %d", conds[0].ObservedGeneration)
	}
}

func TestSetUpdatesCondition(t *testing.T) {
	cm := NewConditionManager(1)
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cm.now = func() time.Time { return t0 }
	if err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	first := *cm.Get(Ready)

	cm.now = func() time.Time { return t0.Add(time.Minute) }

	if err := cm.Set(Ready, metav1.ConditionFalse, "NotReady", "something broke", 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second := *cm.Get(Ready)

	if second.Status != metav1.ConditionFalse {
		t.Errorf("expected status False, got %s", second.Status)
	}
	if second.Reason != "NotReady" {
		t.Errorf("expected reason NotReady, got %s", second.Reason)
	}
	if second.ObservedGeneration != 2 {
		t.Errorf("expected generation 2, got %d", second.ObservedGeneration)
	}
	if !second.LastTransitionTime.After(first.LastTransitionTime.Time) {
		t.Errorf("expected LastTransitionTime to advance on status change")
	}
}

func TestSetNoOpPreservesTimestamp(t *testing.T) {
	cm := NewConditionManager(1)
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cm.now = func() time.Time { return t0 }
	if err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	first := *cm.Get(Ready)

	cm.now = func() time.Time { return t0.Add(time.Minute) }

	// Same status: timestamp must NOT change.
	if err := cm.Set(Ready, metav1.ConditionTrue, "StillReady", "still good", 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second := *cm.Get(Ready)

	if !second.LastTransitionTime.Time.Equal(first.LastTransitionTime.Time) {
		t.Errorf("expected LastTransitionTime to be preserved on no-op status change, got %v vs %v", second.LastTransitionTime.Time, first.LastTransitionTime.Time)
	}
	if second.Reason != "StillReady" {
		t.Errorf("expected reason updated to StillReady, got %s", second.Reason)
	}
}

func TestSetRejectsStaleGeneration(t *testing.T) {
	cm := NewConditionManager(5)
	err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 3)
	if err == nil {
		t.Fatal("expected stale-generation error")
	}
	if _, ok := err.(ErrStaleGeneration); !ok {
		t.Fatalf("expected ErrStaleGeneration, got %T", err)
	}
}

func TestSetAdvancesObservedGeneration(t *testing.T) {
	cm := NewConditionManager(1)
	if err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cm.ObservedGeneration() != 3 {
		t.Errorf("expected observedGeneration 3, got %d", cm.ObservedGeneration())
	}
	// Writing an equal generation should succeed.
	if err := cm.Set(Ready, metav1.ConditionFalse, "NotReady", "bad", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetReason(t *testing.T) {
	cm := NewConditionManager(1)
	if err := cm.Set(Ready, metav1.ConditionTrue, "Ready", "all good", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cm.SetReason(Ready, "Updated", "new message")
	c := cm.Get(Ready)
	if c.Reason != "Updated" || c.Message != "new message" {
		t.Errorf("expected reason/message updated")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected status unchanged")
	}
}

func TestSyncToStatus(t *testing.T) {
	cm := NewConditionManager(7)
	_ = cm.Set(Ready, metav1.ConditionTrue, "Ready", "ok", 7)

	var gotConds []metav1.Condition
	var gotGen int64
	cm.SyncToStatus(
		func(c []metav1.Condition) { gotConds = c },
		func(g int64) { gotGen = g },
	)

	if gotGen != 7 {
		t.Errorf("expected generation 7, got %d", gotGen)
	}
	if len(gotConds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(gotConds))
	}
}

func TestCanTransitionSelf(t *testing.T) {
	for _, p := range []Phase{PhaseAdmitted, PhaseReady, PhaseFailed, PhaseTerminating} {
		if !CanTransition(p, p) {
			t.Errorf("expected self-transition for %s to be legal", p)
		}
	}
}

func TestCanTransitionLegal(t *testing.T) {
	cases := []struct{ from, to Phase }{
		{PhaseAdmitted, PhaseResolved},
		{PhaseResolved, PhaseProvisioning},
		{PhaseProvisioning, PhaseBootstrapping},
		{PhaseBootstrapping, PhaseConfiguring},
		{PhaseConfiguring, PhaseVerifying},
		{PhaseVerifying, PhaseReady},
		{PhaseVerifying, PhaseDegraded},
		{PhaseReady, PhaseDraining},
		{PhaseReady, PhaseMigrating},
		{PhaseReady, PhaseDegraded},
		{PhaseDraining, PhaseReady},
		{PhaseDegraded, PhaseReady},
		{PhaseDegraded, PhaseDraining},
		{PhaseFailed, PhaseAdmitted},
		{PhaseFailed, PhaseTerminating},
		{PhaseReady, PhaseTerminating},
	}
	for _, tc := range cases {
		if !CanTransition(tc.from, tc.to) {
			t.Errorf("expected %s -> %s to be legal", tc.from, tc.to)
		}
	}
}

func TestCanTransitionIllegal(t *testing.T) {
	cases := []struct{ from, to Phase }{
		{PhaseAdmitted, PhaseReady},
		{PhaseResolved, PhaseBootstrapping},
		{PhaseReady, PhaseAdmitted},
		{PhaseTerminating, PhaseReady},
		{PhaseTerminating, PhaseFailed},
		{PhaseFailed, PhaseReady},
	}
	for _, tc := range cases {
		if CanTransition(tc.from, tc.to) {
			t.Errorf("expected %s -> %s to be illegal", tc.from, tc.to)
		}
	}
}

func TestCanTransitionUnknown(t *testing.T) {
	// Unknown phases should return false for non-self transitions.
	if CanTransition(Phase("UnknownPhase"), PhaseReady) {
		t.Error("expected unknown -> Ready to be illegal")
	}
	if CanTransition(PhaseReady, Phase("UnknownPhase")) {
		t.Error("expected Ready -> unknown to be illegal")
	}
}

func TestGateConstantsAreNonEmpty(t *testing.T) {
	want := []GateName{
		GateConfig, GateCriticalTasks, GateListeners, GateSecurityMaterial,
		GateExternalPeer, GateDiameterPeer, GateSCTPAssociation, GateSessionStore,
		GateReplication, GateDataplaneKernel, GateXFRM, GateGTPUserPath,
		GateChargingPeer, GateLIDelivery, GateCertificateRevocation, GateDrain,
	}
	for _, g := range want {
		if g == "" {
			t.Error("gate constant must not be empty")
		}
	}
}

func TestGateCondition(t *testing.T) {
	cm := NewConditionManager(1)
	if err := GateCondition(cm, GateDrain, GatePassing, "DrainPassing", "drain complete", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := cm.Get(ConditionType(GateDrain))
	if c == nil {
		t.Fatal("expected drain gate condition")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected status True for passing gate, got %s", c.Status)
	}
	if c.Reason != "DrainPassing" {
		t.Errorf("expected reason DrainPassing, got %s", c.Reason)
	}
}

func TestGateStatusFromCondition(t *testing.T) {
	cases := []struct {
		name string
		cond metav1.Condition
		want GateStatus
	}{
		{"true passing", metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ReadyPassing"}, GatePassing},
		{"true degraded", metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ReadyDegraded"}, GateDegraded},
		{"false", metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse}, GateFailing},
		{"unknown", metav1.Condition{Type: "Ready", Status: metav1.ConditionUnknown}, GateUnknown},
		{"custom reason suffix degraded", metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "CustomDegraded"}, GatePassing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GateStatusFromCondition(tc.cond)
			if got != tc.want {
				t.Errorf("GateStatusFromCondition(%+v) = %s, want %s", tc.cond, got, tc.want)
			}
		})
	}
}

func TestGateConditionDegradedRoundTrip(t *testing.T) {
	cm := NewConditionManager(1)
	reason := GateReason(GateDrain, GateDegraded)
	message := GateMessage(GateDrain, GateDegraded)
	if err := GateCondition(cm, GateDrain, GateDegraded, reason, message, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := cm.Get(ConditionType(GateDrain))
	if c == nil {
		t.Fatal("expected drain gate condition")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected status True for degraded gate, got %s", c.Status)
	}
	if got := GateStatusFromCondition(*c); got != GateDegraded {
		t.Errorf("expected GateDegraded round-trip, got %s", got)
	}
}

func TestGateReasonAndMessage(t *testing.T) {
	if got := GateReason(GateXFRM, GateFailing); got != "xfrmFailing" {
		t.Errorf("unexpected reason: %s", got)
	}
	if got := GateMessage(GateXFRM, GatePassing); got != "Gate xfrm is passing" {
		t.Errorf("unexpected message: %s", got)
	}
}

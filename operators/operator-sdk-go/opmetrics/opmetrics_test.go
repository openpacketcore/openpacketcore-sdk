package opmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricNames(t *testing.T) {
	expected := []string{
		"opc_operator_reconcile_total",
		"opc_operator_reconcile_duration_seconds",
		"opc_operator_rollout_total",
		"opc_operator_migration_total",
		"opc_operator_drain_total",
		"opc_operator_drift_observations_total",
		"opc_operator_rollback_total",
		"opc_operator_version_skew",
	}

	// Verify each expected name appears in the collector descriptors.
	// We collect from the DefaultGatherer which aggregates all registries.
	for _, name := range expected {
		found := false
		for _, c := range []prometheus.Collector{
			ReconcileTotal,
			ReconcileDuration,
			RolloutTotal,
			MigrationTotal,
			DrainTotal,
			DriftObservationsTotal,
			RollbackTotal,
			VersionSkew,
		} {
			desc := testutil.CollectAndCount(c)
			if desc >= 0 { // always true if collector is valid
				// Extract name from Describe
				ch := make(chan *prometheus.Desc, 1)
				c.Describe(ch)
				close(ch)
				for d := range ch {
					if strings.Contains(d.String(), "\""+name+"\"") {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("expected metric %s to be registered", name)
		}
	}
}

func TestReconcileTotalIncrement(t *testing.T) {
	ReconcileTotal.WithLabelValues("SdkManagedNetworkFunction", "success").Inc()
	if val := testutil.ToFloat64(ReconcileTotal.WithLabelValues("SdkManagedNetworkFunction", "success")); val != 1 {
		t.Errorf("expected reconcile_total=1, got %v", val)
	}
}

func TestDrainTotalIncrement(t *testing.T) {
	DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "timeout").Inc()
	if val := testutil.ToFloat64(DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "timeout")); val != 1 {
		t.Errorf("expected drain_total=1, got %v", val)
	}
}

func TestVersionSkewSet(t *testing.T) {
	VersionSkew.WithLabelValues("SdkManagedNetworkFunction").Set(1)
	if val := testutil.ToFloat64(VersionSkew.WithLabelValues("SdkManagedNetworkFunction")); val != 1 {
		t.Errorf("expected version_skew=1, got %v", val)
	}
	VersionSkew.WithLabelValues("SdkManagedNetworkFunction").Set(0)
}

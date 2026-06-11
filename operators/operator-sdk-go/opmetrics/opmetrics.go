// Package opmetrics provides Prometheus collectors named exactly per
// RFC 009 §17 for operator lifecycle instrumentation.
package opmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

func init() {
	metrics.Registry.MustRegister(
		ReconcileTotal,
		ReconcileDuration,
		RolloutTotal,
		MigrationTotal,
		DrainTotal,
		DriftObservationsTotal,
		RollbackTotal,
		VersionSkew,
	)
}

// ReconcileTotal counts reconcile loops by kind and outcome.
var ReconcileTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_reconcile_total",
		Help: "Total number of reconcile loops.",
	},
	[]string{"kind", "outcome"},
)

// ReconcileDuration tracks reconcile latency by kind and phase.
var ReconcileDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "opc_operator_reconcile_duration_seconds",
		Help:    "Reconcile loop latency in seconds.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"kind", "phase"},
)

// RolloutTotal counts rollout attempts by kind, strategy, and outcome.
var RolloutTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_rollout_total",
		Help: "Total number of rollout attempts.",
	},
	[]string{"kind", "strategy", "outcome"},
)

// MigrationTotal counts migration attempts by kind, type, and outcome.
var MigrationTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_migration_total",
		Help: "Total number of migration attempts.",
	},
	[]string{"kind", "type", "outcome"},
)

// DrainTotal counts drain orchestrations by kind and outcome.
var DrainTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_drain_total",
		Help: "Total number of drain orchestrations.",
	},
	[]string{"kind", "outcome"},
)

// DriftObservationsTotal counts observed configuration drift by kind and state.
var DriftObservationsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_drift_observations_total",
		Help: "Total number of drift observations.",
	},
	[]string{"kind", "state"},
)

// RollbackTotal counts rollback attempts by kind and outcome.
var RollbackTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "opc_operator_rollback_total",
		Help: "Total number of rollback attempts.",
	},
	[]string{"kind", "outcome"},
)

// VersionSkew exposes the current version skew (1 = skew detected, 0 = none).
var VersionSkew = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "opc_operator_version_skew",
		Help: "Current version skew indicator (1 = skew detected).",
	},
	[]string{"kind"},
)

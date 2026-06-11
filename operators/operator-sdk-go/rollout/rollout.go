// Package rollout implements RFC 009 §12 rollout strategy policy evaluation
// and Kubernetes Deployment strategy synthesis.
package rollout

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Strategy defines the rollout strategies supported per RFC 009 §12.
type Strategy string

const (
	StrategyRolling     Strategy = "rolling"
	StrategyPartitioned Strategy = "partitioned"
	StrategyCanary      Strategy = "canary"
	StrategyBlueGreen   Strategy = "blue-green"
	StrategyManual      Strategy = "manual"
)

// NfCharacteristics captures the runtime properties of an NF that determine
// which rollout strategies are safe.
type NfCharacteristics struct {
	Stateful           bool
	SafelyDrainable    bool
	HighRisk           bool
	MajorUpgrade       bool
	IncompatibleChange bool
}

// AllowedStrategies returns the subset of RFC 009 strategies that are
// permitted for the given NF characteristics.
//
// Rules (RFC 009 §12):
//   - rolling:   stateless OR safely-drainable
//   - partitioned: stateful (ordered migration)
//   - canary:    high-risk release or config change
//   - blue-green: major upgrade or incompatible config/state change
//   - manual:    always available as escape hatch
func AllowedStrategies(chars NfCharacteristics) []Strategy {
	var allowed []Strategy

	if !chars.Stateful || chars.SafelyDrainable {
		allowed = append(allowed, StrategyRolling)
	}
	if chars.Stateful {
		allowed = append(allowed, StrategyPartitioned)
	}
	if chars.HighRisk {
		allowed = append(allowed, StrategyCanary)
	}
	if chars.MajorUpgrade || chars.IncompatibleChange {
		allowed = append(allowed, StrategyBlueGreen)
	}
	// manual is always available.
	allowed = append(allowed, StrategyManual)
	return allowed
}

// Evaluate checks whether the desired strategy is allowed for the given NF.
// It returns a descriptive error when the strategy is forbidden.
func Evaluate(chars NfCharacteristics, desired Strategy) error {
	for _, s := range AllowedStrategies(chars) {
		if s == desired {
			return nil
		}
	}
	return fmt.Errorf("rollout strategy %q is not allowed for an NF that is stateful=%v drainable=%v high-risk=%v major=%v incompatible=%v",
		desired, chars.Stateful, chars.SafelyDrainable, chars.HighRisk, chars.MajorUpgrade, chars.IncompatibleChange)
}

// Params carries strategy-specific tuning knobs.
type Params struct {
	Strategy Strategy

	// MaxSurge is the maximum number of pods that can be created above the
	// desired number of pods during a rolling update.  Defaults depend on
	// Strategy when nil.
	MaxSurge *intstr.IntOrString

	// MaxUnavailable is the maximum number of pods that can be unavailable
	// during a rolling update.  Defaults depend on Strategy when nil.
	MaxUnavailable *intstr.IntOrString
}

// BuildDeploymentStrategy synthesizes an appsv1.DeploymentStrategy from the
// requested rollout parameters. An unsupported strategy returns an error
// rather than panicking, so a reconciler fed an unvalidated CR degrades
// gracefully instead of crash-looping; validate intent first via Evaluate.
func BuildDeploymentStrategy(params Params) (appsv1.DeploymentStrategy, error) {
	switch params.Strategy {
	case StrategyRolling:
		return rollingStrategy(params), nil
	case StrategyPartitioned:
		return partitionedStrategy(params), nil
	case StrategyCanary:
		return canaryStrategy(params), nil
	case StrategyBlueGreen:
		return blueGreenStrategy(params), nil
	case StrategyManual:
		return manualStrategy(params), nil
	default:
		// Fail closed for unknown strategies.
		return appsv1.DeploymentStrategy{}, fmt.Errorf("unsupported rollout strategy: %q", params.Strategy)
	}
}

func rollingStrategy(params Params) appsv1.DeploymentStrategy {
	maxSurge := intstr.FromString("25%")
	if params.MaxSurge != nil {
		maxSurge = *params.MaxSurge
	}
	maxUnavailable := intstr.FromString("25%")
	if params.MaxUnavailable != nil {
		maxUnavailable = *params.MaxUnavailable
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxSurge:       &maxSurge,
			MaxUnavailable: &maxUnavailable,
		},
	}
}

func partitionedStrategy(params Params) appsv1.DeploymentStrategy {
	// Partitioned updates proceed one pod at a time (ordered migration).
	maxSurge := intstr.FromInt(0)
	if params.MaxSurge != nil {
		maxSurge = *params.MaxSurge
	}
	maxUnavailable := intstr.FromInt(1)
	if params.MaxUnavailable != nil {
		maxUnavailable = *params.MaxUnavailable
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxSurge:       &maxSurge,
			MaxUnavailable: &maxUnavailable,
		},
	}
}

func canaryStrategy(params Params) appsv1.DeploymentStrategy {
	// Canary updates allow a small surge (typically 1 extra pod) while keeping
	// all existing pods available so traffic can be shifted gradually.
	maxSurge := intstr.FromInt(1)
	if params.MaxSurge != nil {
		maxSurge = *params.MaxSurge
	}
	maxUnavailable := intstr.FromInt(0)
	if params.MaxUnavailable != nil {
		maxUnavailable = *params.MaxUnavailable
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxSurge:       &maxSurge,
			MaxUnavailable: &maxUnavailable,
		},
	}
}

func blueGreenStrategy(_ Params) appsv1.DeploymentStrategy {
	// Blue-green requires a full replacement: tear down the old Deployment
	// before the new one is ready.  We represent this as Recreate on a
	// single Deployment; a production implementation would use two
	// Deployments and a Service selector switch.
	return appsv1.DeploymentStrategy{
		Type: appsv1.RecreateDeploymentStrategyType,
	}
}

func manualStrategy(_ Params) appsv1.DeploymentStrategy {
	// Manual strategy uses conservative replacement (maxSurge 0, maxUnavailable 1)
	// so any update proceeds one pod at a time with no extra capacity.  A
	// production implementation would gate the actual Deployment image change
	// on an operator approval signal.
	maxSurge := intstr.FromInt(0)
	maxUnavailable := intstr.FromInt(1)
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxSurge:       &maxSurge,
			MaxUnavailable: &maxUnavailable,
		},
	}
}

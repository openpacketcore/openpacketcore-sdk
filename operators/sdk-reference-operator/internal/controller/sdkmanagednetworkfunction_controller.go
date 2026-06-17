package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"openpacketcore.io/operator-sdk-go/bridge"
	"openpacketcore.io/operator-sdk-go/conditions"
	"openpacketcore.io/operator-sdk-go/drain"
	"openpacketcore.io/operator-sdk-go/opmetrics"
	"openpacketcore.io/operator-sdk-go/workload"
	"openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const drainFinalizer = "lifecycle.openpacketcore.io/drain"

// drainRetryInterval is how long to wait before retrying a drain that has not
// yet reached a terminal state during deletion.
const drainRetryInterval = 10 * time.Second

// SdkManagedNetworkFunctionReconciler reconciles SdkManagedNetworkFunction resources.
type SdkManagedNetworkFunctionReconciler struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Bridge   *sdkbridge.Bridge
	Drainer  drain.Orchestrator
	Recorder record.EventRecorder
	// EnableWorkloadSynthesis is a reference-grade opt-in flag that causes the
	// reconciler to create/update a Deployment derived from the CR spec.
	// It is off by default and should not be enabled in production operators
	// without additional validation.
	EnableWorkloadSynthesis bool
}

// +kubebuilder:rbac:groups=reference.openpacketcore.io,resources=sdkmanagednetworkfunctions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=reference.openpacketcore.io,resources=sdkmanagednetworkfunctions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch

func (r *SdkManagedNetworkFunctionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	start := time.Now()
	outcome := "success"
	defer func() {
		opmetrics.ReconcileDuration.WithLabelValues("SdkManagedNetworkFunction", outcome).Observe(time.Since(start).Seconds())
		opmetrics.ReconcileTotal.WithLabelValues("SdkManagedNetworkFunction", outcome).Inc()
	}()

	// 1. Fetch SdkManagedNetworkFunction resource
	crd := &v1beta1.SdkManagedNetworkFunction{}
	err := r.Client.Get(ctx, req.NamespacedName, crd)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		outcome = "error"
		return ctrl.Result{}, err
	}

	// Monotonicity check: do not process stale generations
	if crd.Generation < crd.Status.ObservedGeneration {
		logger.Info("Skipping reconciliation of stale generation", "generation", crd.Generation, "observed", crd.Status.ObservedGeneration)
		return ctrl.Result{}, nil
	}

	// ConditionManager drives all condition mutations with RFC 009 semantics.
	cm := conditions.NewConditionManager(crd.Status.ObservedGeneration)
	cm.LoadConditions(crd.Status.Conditions)

	// Finalizer handling
	if !crd.DeletionTimestamp.IsZero() {
		if r.Drainer != nil && containsString(crd.Finalizers, drainFinalizer) {
			if err := r.runDrain(ctx, crd, cm); err != nil {
				// Drain has not reached a terminal state (it failed to start,
				// failed, or is still in progress). Keep the finalizer and
				// requeue so active sessions are not cut; only a completed or
				// timed-out drain removes the finalizer. Persist the
				// DrainReady=False condition for observability.
				logger.Error(err, "Drain during deletion not complete; requeuing without removing finalizer")
				r.syncConditions(crd, cm)
				if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
					logger.Error(updateErr, "failed to persist drain condition")
				}
				return ctrl.Result{RequeueAfter: drainRetryInterval}, nil
			}
		}
		crd.Finalizers = removeString(crd.Finalizers, drainFinalizer)
		if err := r.Client.Update(ctx, crd); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !containsString(crd.Finalizers, drainFinalizer) {
		crd.Finalizers = append(crd.Finalizers, drainFinalizer)
		if err := r.Client.Update(ctx, crd); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 2. Fetch dependencies (NodeCapabilityReport, CompatibilityMatrix, ActiveAlarms)
	isProd := crd.Spec.RuntimeMode == "production"
	if isProd && crd.Spec.ResourceProfile == nil {
		crd.Status.Phase = string(conditions.PhaseDegraded)
		crd.Status.BlockedReason = "Production references require a resource profile before rollout"
		crd.Status.PreflightSummary = "Blocked: resource profile missing"
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "ResourceProfileMissing", crd.Status.BlockedReason, crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "ResourceProfileMissing", crd.Status.BlockedReason, crd.Generation)
		r.syncConditions(crd, cm)
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	var nodeCaps *sdkbridge.NodeCapabilityReport
	cfgMap := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{
		Name:      "node-capability-report",
		Namespace: crd.Namespace,
	}, cfgMap)
	if err == nil {
		if data, ok := cfgMap.Data["report.json"]; ok {
			var report sdkbridge.NodeCapabilityReport
			if json.Unmarshal([]byte(data), &report) == nil {
				nodeCaps = &report
			}
		}
	}

	if isProd && crd.Spec.ResourceProfile != nil && nodeCaps == nil {
		crd.Status.Phase = string(conditions.PhaseDegraded)
		crd.Status.BlockedReason = "Production data-plane preflight requires a node capability report"
		crd.Status.PreflightSummary = "Blocked: node capability report missing"
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "NodeCapabilitiesMissing", crd.Status.BlockedReason, crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "NodeCapabilitiesMissing", crd.Status.BlockedReason, crd.Generation)
		r.syncConditions(crd, cm)
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	var compatMatrix *sdkbridge.CompatibilityMatrix
	var evidence []sdkbridge.CompatibilityEvidence
	if crd.Spec.CompatibilityRef != nil {
		compatCM := &corev1.ConfigMap{}
		err := r.Client.Get(ctx, types.NamespacedName{
			Name:      crd.Spec.CompatibilityRef.Name,
			Namespace: crd.Namespace,
		}, compatCM)
		if err == nil {
			if data, ok := compatCM.Data["matrix.json"]; ok {
				var matrix sdkbridge.CompatibilityMatrix
				if json.Unmarshal([]byte(data), &matrix) == nil {
					compatMatrix = &matrix
				}
			}
			if data, ok := compatCM.Data["evidence.json"]; ok {
				var ev []sdkbridge.CompatibilityEvidence
				if json.Unmarshal([]byte(data), &ev) == nil {
					evidence = ev
				}
			}
		}
	}

	alarms := make([]sdkbridge.Alarm, 0)
	alarmCM := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{
		Name:      "active-alarms",
		Namespace: crd.Namespace,
	}, alarmCM)
	if err == nil {
		if data, ok := alarmCM.Data["alarms.json"]; ok {
			var parsed []sdkbridge.Alarm
			if json.Unmarshal([]byte(data), &parsed) == nil {
				alarms = parsed
			}
		}
	}

	// 3. Construct PreflightReport if we have nodeCaps and resourceProfile
	var preflightReport *sdkbridge.DataPlanePreflightReport
	if crd.Spec.ResourceProfile != nil && nodeCaps != nil {
		pReq := &sdkbridge.PreflightRequest{
			ResourceProfile: sdkbridge.ResourceProfileSpec{
				NfKind:                    crd.Spec.ResourceProfile.NfKind,
				DataPlaneProfile:          crd.Spec.ResourceProfile.DataPlaneProfile,
				NumaPolicy:                crd.Spec.ResourceProfile.NumaPolicy,
				GenericXdpFallbackAllowed: crd.Spec.ResourceProfile.GenericXdpFallbackAllowed,
				IsolatedCores:             crd.Spec.ResourceProfile.IsolatedCores,
				RequireExclusiveCores:     crd.Spec.ResourceProfile.RequireExclusiveCores,
				DataPlaneInterfaces:       crd.Spec.ResourceProfile.DataPlaneInterfaces,
				DataPlaneNumaNode:         crd.Spec.ResourceProfile.DataPlaneNumaNode,
				HugepageNumaNode:          crd.Spec.ResourceProfile.HugepageNumaNode,
				PodSecurityEvidenceID:     crd.Spec.ResourceProfile.PodSecurityEvidenceID,
				SriovResourceName:         crd.Spec.ResourceProfile.SriovResourceName,
				SriovAllowedDeviceDrivers: crd.Spec.ResourceProfile.SriovAllowedDeviceDrivers,
			},
			NodeCapabilities: *nodeCaps,
		}
		if crd.Spec.ResourceProfile.BpfArtifacts != nil {
			pReq.ResourceProfile.BpfArtifacts = make([]sdkbridge.BpfArtifact, len(crd.Spec.ResourceProfile.BpfArtifacts))
			for i, val := range crd.Spec.ResourceProfile.BpfArtifacts {
				pReq.ResourceProfile.BpfArtifacts[i] = sdkbridge.BpfArtifact{
					Name:                val.Name,
					Digest:              val.Digest,
					SignatureRef:        val.SignatureRef,
					SignerIdentity:      val.SignerIdentity,
					ProgramType:         val.ProgramType,
					ExpectedAttachPoint: val.ExpectedAttachPoint,
					AllowedCapabilities: append([]string{}, val.AllowedCapabilities...),
					EvidenceID:          val.EvidenceID,
				}
			}
		}

		rep, err := r.Bridge.EvaluatePreflight(ctx, pReq)
		if err == nil {
			preflightReport = rep
		} else {
			logger.Error(err, "Failed to run preflight check during reconciliation")
			if isProd {
				crd.Status.Phase = string(conditions.PhaseDegraded)
				crd.Status.BlockedReason = "Production data-plane preflight evaluation failed"
				crd.Status.PreflightSummary = "Blocked: preflight evaluation failed"
				_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "PreflightEvaluationFailed", crd.Status.BlockedReason, crd.Generation)
				_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "PreflightEvaluationFailed", crd.Status.BlockedReason, crd.Generation)
				if r.Recorder != nil {
					r.Recorder.Eventf(crd, corev1.EventTypeWarning, "PreflightFailed", "Production preflight evaluation failed: %v", err)
				}
				r.syncConditions(crd, cm)
				if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
		}
	}

	// 4. Map conditions for LifecycleStatus
	statusConds := make([]sdkbridge.LifecycleCondition, 0)
	if crd.Status.Conditions != nil {
		statusConds = make([]sdkbridge.LifecycleCondition, len(crd.Status.Conditions))
		for i, c := range crd.Status.Conditions {
			statusConds[i] = sdkbridge.LifecycleCondition{
				Type:               c.Type,
				Status:             string(c.Status),
				Reason:             c.Reason,
				Message:            c.Message,
				ObservedGeneration: c.ObservedGeneration,
				LastTransitionTime: c.LastTransitionTime.UTC().Format(time.RFC3339),
				RedactionSafeText:  true,
			}
		}
	}

	// 5. Construct ConfigApplyRequest
	applyReq := &sdkbridge.ConfigApplyRequest{
		DesiredGeneration:         crd.Generation,
		CurrentObservedGeneration: crd.Status.ObservedGeneration,
		CurrentVersion:            1, // simplified reference model
		CurrentDigest:             "0000000000000000000000000000000000000000000000000000000000000000",
		LifecycleStatus: sdkbridge.LifecycleStatus{
			Phase:              crd.Status.Phase,
			Conditions:         statusConds,
			ObservedGeneration: crd.Status.ObservedGeneration,
		},
		ActiveAlarms:    alarms,
		PreflightReport: preflightReport,
	}

	if crd.Spec.ResourceProfile != nil {
		evList := evidence
		if evList == nil {
			evList = make([]sdkbridge.CompatibilityEvidence, 0)
		}
		applyReq.Candidate = &sdkbridge.CandidateMetadata{
			Version:           1,
			SchemaDigest:      "0000000000000000000000000000000000000000000000000000000000000000",
			IsCommitConfirmed: true,
			OperatorRelease: &sdkbridge.OperatorReleaseDescriptor{
				OperatorVersion: "0.1.0",
				SdkVersion:      "0.1.0",
			},
			NfRelease: &sdkbridge.NfReleaseDescriptor{
				NfKind:              crd.Spec.ResourceProfile.NfKind,
				NfVersion:           crd.Spec.Version,
				CrdApiVersion:       crd.APIVersion,
				ConfigSchemaVersion: crd.Spec.ConfigSchemaVersion,
				StateSchemaVersion:  crd.Spec.StateSchemaVersion,
			},
			CompatibilityMatrix: compatMatrix,
			Evidence:            evList,
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	applyReq.CurrentTime = &nowStr

	// 6. Invoke CLI bridge
	decision, err := r.Bridge.EvaluateConfigApply(ctx, applyReq)
	if err != nil {
		logger.Error(err, "Failed to evaluate config apply policy")
		crd.Status.Phase = string(conditions.PhaseDegraded)
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "SdkBridgeFailure", err.Error(), crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "SdkBridgeFailure", err.Error(), crd.Generation)

		var bridgeErr *bridge.Error
		if errors.As(err, &bridgeErr) && bridgeErr.Kind == bridge.ErrKindContractMismatch {
			opmetrics.VersionSkew.WithLabelValues("SdkManagedNetworkFunction").Set(1)
			if r.Recorder != nil {
				r.Recorder.Eventf(crd, corev1.EventTypeWarning, "ContractMismatch", "Bridge contract version mismatch: %s", bridgeErr.Message)
			}
		} else {
			opmetrics.VersionSkew.WithLabelValues("SdkManagedNetworkFunction").Set(0)
		}

		r.syncConditions(crd, cm)
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	opmetrics.VersionSkew.WithLabelValues("SdkManagedNetworkFunction").Set(0)

	logger.Info("Evaluated policy config-apply decision", "decision", decision.Type)

	// 7. Update CR status based on Decision
	oldPhase := crd.Status.Phase
	switch decision.Type {
	case "Apply":
		crd.Status.Phase = string(conditions.PhaseReady)
		crd.Status.LastAdmittedVersion = crd.Spec.Version
		crd.Status.CompatibilityDecision = "Allowed"
		crd.Status.BlockedReason = ""
		if preflightReport != nil && preflightReport.Passed {
			crd.Status.PreflightSummary = "Passed"
		} else {
			crd.Status.PreflightSummary = "Skipped"
		}
		_ = cm.Set(conditions.Ready, metav1.ConditionTrue, "ConfigApplied", "Configuration applied successfully", crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionFalse, "ConfigApplied", "Configuration applied successfully", crd.Generation)
		r.recordPhaseTransition(crd, oldPhase, crd.Status.Phase)

	case "NoOp":
		_ = cm.Set(conditions.Ready, metav1.ConditionTrue, "NoOp", "Configuration is already up to date", crd.Generation)

	case "Reject":
		crd.Status.Phase = string(conditions.PhaseDegraded)
		crd.Status.BlockedReason = decision.RejectReason
		crd.Status.CompatibilityDecision = "Rejected"
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "ConfigRejected", decision.RejectReason, crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "ConfigRejected", decision.RejectReason, crd.Generation)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "AdmissionRejected", "Config apply rejected: %s", decision.RejectReason)
		}

	case "RecoveryRequired":
		crd.Status.Phase = string(conditions.PhaseFailed)
		crd.Status.BlockedReason = decision.RecoveryReason
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "RecoveryRequired", decision.RecoveryReason, crd.Generation)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "RecoveryRequired", "Recovery required: %s", decision.RecoveryReason)
		}

	case "Rollback":
		crd.Status.Phase = string(conditions.PhaseDegraded) // RollingBack is not a distinct RFC 009 phase; map to Degraded
		crd.Status.BlockedReason = decision.RollbackReason
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "RollbackTriggered", fmt.Sprintf("Rollback to version %d: %s", decision.RollbackTarget, decision.RollbackReason), crd.Generation)
		opmetrics.RollbackTotal.WithLabelValues("SdkManagedNetworkFunction", "triggered").Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "RollbackTriggered", "Rollback to version %d: %s", decision.RollbackTarget, decision.RollbackReason)
		}

	case "WaitForDrain":
		crd.Status.Phase = string(conditions.PhaseDraining)
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, "WaitingForDrain", "Workload is draining before config application", crd.Generation)
	}

	// Workload synthesis (reference-grade, opt-in)
	if r.EnableWorkloadSynthesis {
		if err := r.reconcileWorkload(ctx, crd); err != nil {
			logger.Error(err, "Workload synthesis failed")
			_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, "WorkloadSynthesisFailed", err.Error(), crd.Generation)
		}
	}

	// Drain orchestration: if phase is Draining, coordinate with the runtime.
	if crd.Status.Phase == string(conditions.PhaseDraining) && r.Drainer != nil {
		res, err := r.orchestrateDrain(ctx, crd, cm)
		if err != nil {
			logger.Error(err, "Drain orchestration failed")
		}
		if res.Requeue || res.RequeueAfter > 0 {
			r.syncConditions(crd, cm)
			if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return res, nil
		}
	}

	// Collect evidence IDs if present
	if evidence != nil {
		crd.Status.EvidenceIDs = make([]string, len(evidence))
		for i, ev := range evidence {
			crd.Status.EvidenceIDs[i] = ev.EvidenceID
		}
	}

	r.syncConditions(crd, cm)

	// Write status back to API server
	if err := r.Client.Status().Update(ctx, crd); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SdkManagedNetworkFunctionReconciler) runDrain(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction, cm *conditions.ConditionManager) error {
	if r.Drainer == nil {
		return nil
	}
	target := fmt.Sprintf("http://%s:8080", crd.Name) // simplistic target
	if err := r.Drainer.Start(ctx, target); err != nil {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStartFailed", err.Error(), crd.Generation)
		return err
	}
	status, err := r.Drainer.Status(ctx, target)
	if err != nil {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStatusFailed", err.Error(), crd.Generation)
		return err
	}
	switch status.Phase {
	case drain.Complete:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionTrue, "DrainComplete", "Drain completed successfully", crd.Generation)
		return nil
	case drain.TimedOut:
		// The drainer's own bounded timeout elapsed. Treat this as terminal so
		// teardown is not blocked forever: deletion proceeds (bounded
		// force-delete) rather than retrying indefinitely.
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainTimedOut", "Drain timed out; proceeding with deletion", crd.Generation)
		return nil
	default:
		// Failed, in progress, or any other non-terminal phase: signal the
		// caller to requeue rather than remove the finalizer.
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainIncomplete", fmt.Sprintf("drain phase: %s", status.Phase), crd.Generation)
		return fmt.Errorf("drain incomplete: %s", status.Phase)
	}
}

func (r *SdkManagedNetworkFunctionReconciler) orchestrateDrain(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction, cm *conditions.ConditionManager) (ctrl.Result, error) {
	target := fmt.Sprintf("http://%s:8080", crd.Name)
	startedAtStr := crd.Annotations["openpacketcore.io/drain-started-at"]
	if startedAtStr == "" {
		if err := r.Drainer.Start(ctx, target); err != nil {
			_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStartFailed", err.Error(), crd.Generation)
			opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "start_failed").Inc()
			return ctrl.Result{}, err
		}
		if crd.Annotations == nil {
			crd.Annotations = make(map[string]string)
		}
		crd.Annotations["openpacketcore.io/drain-started-at"] = time.Now().UTC().Format(time.RFC3339)
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainInProgress", "Drain started", crd.Generation)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeNormal, "DrainStarted", "Drain started for %s", crd.Name)
		}
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	startedAt, err := time.Parse(time.RFC3339, startedAtStr)
	if err != nil {
		startedAt = time.Now().UTC()
	}
	if time.Since(startedAt) > 5*time.Minute {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainTimedOut", "Drain exceeded 5m timeout", crd.Generation)
		delete(crd.Annotations, "openpacketcore.io/drain-started-at")
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "timeout").Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "DrainTimedOut", "Drain exceeded 5m timeout for %s", crd.Name)
		}
		return ctrl.Result{}, nil
	}

	status, err := r.Drainer.Status(ctx, target)
	if err != nil {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStatusFailed", err.Error(), crd.Generation)
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "status_failed").Inc()
		return ctrl.Result{RequeueAfter: 10 * time.Second}, err
	}

	switch status.Phase {
	case drain.Complete:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionTrue, "DrainComplete", "Drain completed successfully", crd.Generation)
		delete(crd.Annotations, "openpacketcore.io/drain-started-at")
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "complete").Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeNormal, "DrainComplete", "Drain completed for %s", crd.Name)
		}
		return ctrl.Result{}, nil
	case drain.InProgress:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainInProgress", fmt.Sprintf("sessions remaining: %d", status.SessionsRemaining), crd.Generation)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	case drain.TimedOut, drain.Failed:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainFailed", fmt.Sprintf("drain phase: %s", status.Phase), crd.Generation)
		delete(crd.Annotations, "openpacketcore.io/drain-started-at")
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", string(status.Phase)).Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "DrainFailed", "Drain failed for %s: phase=%s", crd.Name, status.Phase)
		}
		return ctrl.Result{}, nil
	default:
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
}

func (r *SdkManagedNetworkFunctionReconciler) reconcileWorkload(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction) error {
	logger := log.FromContext(ctx)

	wSpec := workload.NetworkFunctionSpec{
		Name:         crd.Name,
		Namespace:    crd.Namespace,
		Version:      crd.Spec.Version,
		RuntimeMode:  crd.Spec.RuntimeMode,
		NodeSelector: crd.Spec.NodeSelector,
	}
	if crd.Spec.ResourceProfile != nil {
		prof := crd.Spec.ResourceProfile
		wSpec.ResourceProfile = &workload.ResourceProfile{
			NfKind:                    prof.NfKind,
			DataPlaneProfile:          prof.DataPlaneProfile,
			NumaPolicy:                prof.NumaPolicy,
			GenericXdpFallbackAllowed: prof.GenericXdpFallbackAllowed,
			IsolatedCores:             append([]uint16(nil), prof.IsolatedCores...),
			RequireExclusiveCores:     prof.RequireExclusiveCores,
			DataPlaneInterfaces:       append([]string(nil), prof.DataPlaneInterfaces...),
			DataPlaneNumaNode:         prof.DataPlaneNumaNode,
			HugepageNumaNode:          prof.HugepageNumaNode,
			PodSecurityEvidenceID:     prof.PodSecurityEvidenceID,
			SriovResourceName:         prof.SriovResourceName,
			SriovAllowedDeviceDrivers: append([]string(nil), prof.SriovAllowedDeviceDrivers...),
		}
		for _, ba := range prof.BpfArtifacts {
			wSpec.ResourceProfile.BpfArtifacts = append(wSpec.ResourceProfile.BpfArtifacts, workload.BpfArtifact{
				Name:                ba.Name,
				Digest:              ba.Digest,
				SignatureRef:        ba.SignatureRef,
				SignerIdentity:      ba.SignerIdentity,
				ProgramType:         ba.ProgramType,
				ExpectedAttachPoint: ba.ExpectedAttachPoint,
				AllowedCapabilities: append([]string(nil), ba.AllowedCapabilities...),
				EvidenceID:          ba.EvidenceID,
			})
		}
	}

	opts := workload.DefaultRenderOptions()
	owner := metav1.OwnerReference{
		APIVersion: crd.APIVersion,
		Kind:       crd.Kind,
		Name:       crd.Name,
		UID:        crd.UID,
		Controller: func() *bool { b := true; return &b }(),
	}

	dep, err := workload.BuildDeploymentWithOwnership(wSpec, opts, owner)
	if err != nil {
		return fmt.Errorf("render deployment: %w", err)
	}

	// Ensure the Deployment exists and is up to date
	existing := &appsv1.Deployment{}
	key := types.NamespacedName{Name: dep.Name, Namespace: dep.Namespace}
	if err := r.Client.Get(ctx, key, existing); err != nil {
		if k8serrors.IsNotFound(err) {
			logger.Info("Creating Deployment for CNF", "deployment", dep.Name)
			if createErr := r.Client.Create(ctx, dep); createErr != nil {
				return fmt.Errorf("create deployment: %w", createErr)
			}
			return nil
		}
		return fmt.Errorf("get deployment: %w", err)
	}

	// Update existing deployment spec
	existing.Spec = dep.Spec
	existing.Labels = dep.Labels
	logger.Info("Updating Deployment for CNF", "deployment", dep.Name)
	if updateErr := r.Client.Update(ctx, existing); updateErr != nil {
		return fmt.Errorf("update deployment: %w", updateErr)
	}
	return nil
}

func (r *SdkManagedNetworkFunctionReconciler) recordPhaseTransition(crd *v1beta1.SdkManagedNetworkFunction, oldPhase, newPhase string) {
	if oldPhase == newPhase {
		return
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(crd, corev1.EventTypeNormal, "PhaseTransition", "Phase changed from %s to %s", oldPhase, newPhase)
	}
}

func (r *SdkManagedNetworkFunctionReconciler) syncConditions(crd *v1beta1.SdkManagedNetworkFunction, cm *conditions.ConditionManager) {
	crd.Status.Conditions = cm.Conditions()
	crd.Status.ObservedGeneration = cm.ObservedGeneration()
}

func (r *SdkManagedNetworkFunctionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.SdkManagedNetworkFunction{}).
		Complete(r)
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

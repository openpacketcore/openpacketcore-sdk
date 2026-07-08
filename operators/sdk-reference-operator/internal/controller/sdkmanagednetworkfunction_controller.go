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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const drainFinalizer = "lifecycle.openpacketcore.io/drain"
const drainStartedAtAnnotation = "openpacketcore.io/drain-started-at"

// drainRetryInterval is how long to wait before retrying a drain that has not
// yet reached a terminal state during deletion.
const drainRetryInterval = 10 * time.Second
const drainTimeout = 5 * time.Minute

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
		if r.Drainer != nil && controllerutil.ContainsFinalizer(crd, drainFinalizer) {
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
		controllerutil.RemoveFinalizer(crd, drainFinalizer)
		if err := r.Client.Update(ctx, crd); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(crd, drainFinalizer) {
		controllerutil.AddFinalizer(crd, drainFinalizer)
		if err := r.Client.Update(ctx, crd); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 2. Fetch dependencies (NodeCapabilityReport, CompatibilityMatrix, ActiveAlarms)
	isProd := crd.Spec.RuntimeMode == "production"
	blockInvalidMetadata := func(reason, message string) (ctrl.Result, error) {
		crd.Status.Phase = string(conditions.PhaseDegraded)
		crd.Status.BlockedReason = message
		crd.Status.PreflightSummary = "Blocked: invalid metadata"
		_ = cm.Set(conditions.Ready, metav1.ConditionFalse, reason, message, crd.Generation)
		_ = cm.Set(conditions.Degraded, metav1.ConditionTrue, reason, message, crd.Generation)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, reason, "%s", message)
		}
		r.syncConditions(crd, cm)
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}
	warnInvalidMetadata := func(reason, message string, err error) {
		logger.Error(err, message)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, reason, "%s: %v", message, err)
		}
	}
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
			if err := json.Unmarshal([]byte(data), &report); err != nil {
				reason := "NodeCapabilitiesMetadataInvalid"
				message := fmt.Sprintf("%s: invalid report.json in ConfigMap %s/%s", reason, cfgMap.Namespace, cfgMap.Name)
				if isProd {
					return blockInvalidMetadata(reason, fmt.Sprintf("%s: %v", message, err))
				}
				warnInvalidMetadata(reason, message, err)
			} else {
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
				if err := json.Unmarshal([]byte(data), &matrix); err != nil {
					reason := "CompatibilityMetadataInvalid"
					message := fmt.Sprintf("%s: invalid matrix.json in ConfigMap %s/%s", reason, compatCM.Namespace, compatCM.Name)
					if isProd {
						return blockInvalidMetadata(reason, fmt.Sprintf("%s: %v", message, err))
					}
					warnInvalidMetadata(reason, message, err)
				} else {
					compatMatrix = &matrix
				}
			}
			if data, ok := compatCM.Data["evidence.json"]; ok {
				var ev []sdkbridge.CompatibilityEvidence
				if err := json.Unmarshal([]byte(data), &ev); err != nil {
					reason := "CompatibilityMetadataInvalid"
					message := fmt.Sprintf("%s: invalid evidence.json in ConfigMap %s/%s", reason, compatCM.Namespace, compatCM.Name)
					if isProd {
						return blockInvalidMetadata(reason, fmt.Sprintf("%s: %v", message, err))
					}
					warnInvalidMetadata(reason, message, err)
				} else {
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
			if err := json.Unmarshal([]byte(data), &parsed); err != nil {
				reason := "AlarmMetadataInvalid"
				message := fmt.Sprintf("%s: invalid alarms.json in ConfigMap %s/%s", reason, alarmCM.Namespace, alarmCM.Name)
				if isProd {
					return blockInvalidMetadata(reason, fmt.Sprintf("%s: %v", message, err))
				}
				warnInvalidMetadata(reason, message, err)
			} else {
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
				IpsecNetworkAttachments:   sdkbridgeIpsecNetworkAttachments(crd.Spec.ResourceProfile.IpsecNetworkAttachments),
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
		if res.RequeueAfter > 0 {
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

func sdkbridgeIpsecNetworkAttachments(in []v1beta1.IpsecNetworkAttachmentSpec) []sdkbridge.IpsecNetworkAttachmentSpec {
	if in == nil {
		return nil
	}
	out := make([]sdkbridge.IpsecNetworkAttachmentSpec, len(in))
	for i, attachment := range in {
		out[i] = sdkbridge.IpsecNetworkAttachmentSpec{
			InterfaceName:       attachment.InterfaceName,
			Plane:               attachment.Plane,
			CniType:             attachment.CniType,
			StaticIPRequired:    attachment.StaticIPRequired,
			StaticIP:            cloneStringPtr(attachment.StaticIP),
			MinimumMTU:          cloneUint16Ptr(attachment.MinimumMTU),
			MTU:                 cloneUint16Ptr(attachment.MTU),
			SourceRouteRequired: attachment.SourceRouteRequired,
			SourceRoute:         cloneStringPtr(attachment.SourceRoute),
			VlanID:              cloneUint16Ptr(attachment.VlanID),
		}
	}
	return out
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneUint16Ptr(in *uint16) *uint16 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func (r *SdkManagedNetworkFunctionReconciler) runDrain(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction, cm *conditions.ConditionManager) error {
	if r.Drainer == nil {
		return nil
	}
	if deletionDrainDeadlineExceeded(crd, time.Now()) {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainTimedOut", "Drain exceeded deletion deadline; proceeding with deletion", crd.Generation)
		return nil
	}
	target := fmt.Sprintf("http://%s:8080", crd.Name) // simplistic target
	if err := r.Drainer.Start(ctx, target); err != nil {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStartFailed", err.Error(), crd.Generation)
		return fmt.Errorf("starting drain for %s: %w", target, err)
	}
	status, err := r.Drainer.Status(ctx, target)
	if err != nil {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStatusFailed", err.Error(), crd.Generation)
		return fmt.Errorf("querying drain status for %s: %w", target, err)
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
	case drain.Failed:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainFailed", "Drain failed; proceeding with deletion", crd.Generation)
		return nil
	default:
		// In progress or any other non-terminal phase: signal the caller to
		// requeue rather than remove the finalizer.
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainIncomplete", fmt.Sprintf("drain phase: %s", status.Phase), crd.Generation)
		return fmt.Errorf("drain incomplete: %s", status.Phase)
	}
}

func deletionDrainDeadlineExceeded(crd *v1beta1.SdkManagedNetworkFunction, now time.Time) bool {
	return !crd.DeletionTimestamp.IsZero() && now.Sub(crd.DeletionTimestamp.Time) > drainTimeout
}

func (r *SdkManagedNetworkFunctionReconciler) orchestrateDrain(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction, cm *conditions.ConditionManager) (ctrl.Result, error) {
	target := fmt.Sprintf("http://%s:8080", crd.Name)
	startedAtStr := crd.Annotations[drainStartedAtAnnotation]
	if startedAtStr == "" {
		if err := r.Drainer.Start(ctx, target); err != nil {
			_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStartFailed", err.Error(), crd.Generation)
			opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "start_failed").Inc()
			return ctrl.Result{}, err
		}
		startedAt := time.Now().UTC().Format(time.RFC3339)
		if err := r.patchDrainStartedAtAnnotation(ctx, crd, startedAt); err != nil {
			_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainStartPersistenceFailed", err.Error(), crd.Generation)
			return ctrl.Result{RequeueAfter: drainRetryInterval}, err
		}
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainInProgress", "Drain started", crd.Generation)
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeNormal, "DrainStarted", "Drain started for %s", crd.Name)
		}
		return ctrl.Result{RequeueAfter: drainRetryInterval}, nil
	}

	startedAt, err := time.Parse(time.RFC3339, startedAtStr)
	if err != nil {
		startedAt = time.Now().UTC()
	}
	if time.Since(startedAt) > drainTimeout {
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainTimedOut", "Drain exceeded 5m timeout", crd.Generation)
		if err := r.clearDrainStartedAtAnnotation(ctx, crd); err != nil {
			return ctrl.Result{RequeueAfter: drainRetryInterval}, err
		}
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
		return ctrl.Result{RequeueAfter: drainRetryInterval}, err
	}

	switch status.Phase {
	case drain.Complete:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionTrue, "DrainComplete", "Drain completed successfully", crd.Generation)
		if err := r.clearDrainStartedAtAnnotation(ctx, crd); err != nil {
			return ctrl.Result{RequeueAfter: drainRetryInterval}, err
		}
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", "complete").Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeNormal, "DrainComplete", "Drain completed for %s", crd.Name)
		}
		return ctrl.Result{}, nil
	case drain.InProgress:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainInProgress", fmt.Sprintf("sessions remaining: %d", status.SessionsRemaining), crd.Generation)
		return ctrl.Result{RequeueAfter: drainRetryInterval}, nil
	case drain.TimedOut, drain.Failed:
		_ = cm.Set(conditions.DrainReady, metav1.ConditionFalse, "DrainFailed", fmt.Sprintf("drain phase: %s", status.Phase), crd.Generation)
		if err := r.clearDrainStartedAtAnnotation(ctx, crd); err != nil {
			return ctrl.Result{RequeueAfter: drainRetryInterval}, err
		}
		opmetrics.DrainTotal.WithLabelValues("SdkManagedNetworkFunction", string(status.Phase)).Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(crd, corev1.EventTypeWarning, "DrainFailed", "Drain failed for %s: phase=%s", crd.Name, status.Phase)
		}
		return ctrl.Result{}, nil
	default:
		return ctrl.Result{RequeueAfter: drainRetryInterval}, nil
	}
}

func (r *SdkManagedNetworkFunctionReconciler) patchDrainStartedAtAnnotation(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction, startedAt string) error {
	if crd.Annotations == nil {
		crd.Annotations = make(map[string]string)
	}
	crd.Annotations[drainStartedAtAnnotation] = startedAt

	patchBytes, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				drainStartedAtAnnotation: startedAt,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("encoding drain annotation patch: %w", err)
	}
	if err := r.Client.Patch(ctx, crd, client.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("persisting drain annotation: %w", err)
	}
	return nil
}

func (r *SdkManagedNetworkFunctionReconciler) clearDrainStartedAtAnnotation(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction) error {
	if crd.Annotations != nil {
		delete(crd.Annotations, drainStartedAtAnnotation)
	}

	patchBytes, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				drainStartedAtAnnotation: nil,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("encoding drain annotation clear patch: %w", err)
	}
	if err := r.Client.Patch(ctx, crd, client.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("clearing drain annotation: %w", err)
	}
	return nil
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
		BlockOwnerDeletion: func() *bool {
			b := true
			return &b
		}(),
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

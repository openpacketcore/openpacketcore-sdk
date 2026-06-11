package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SdkManagedNetworkFunctionReconciler reconciles SdkManagedNetworkFunction resources.
type SdkManagedNetworkFunctionReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
	Bridge *sdkbridge.Bridge
}

// +kubebuilder:rbac:groups=reference.openpacketcore.io,resources=sdkmanagednetworkfunctions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=reference.openpacketcore.io,resources=sdkmanagednetworkfunctions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch

func (r *SdkManagedNetworkFunctionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch SdkManagedNetworkFunction resource
	crd := &v1beta1.SdkManagedNetworkFunction{}
	err := r.Client.Get(ctx, req.NamespacedName, crd)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Monotonicity check: do not process stale generations
	if crd.Generation < crd.Status.ObservedGeneration {
		logger.Info("Skipping reconciliation of stale generation", "generation", crd.Generation, "observed", crd.Status.ObservedGeneration)
		return ctrl.Result{}, nil
	}

	// 2. Fetch dependencies (NodeCapabilityReport, CompatibilityMatrix, ActiveAlarms)
	isProd := crd.Spec.RuntimeMode == "production"
	if isProd && crd.Spec.ResourceProfile == nil {
		crd.Status.Phase = "Degraded"
		crd.Status.ObservedGeneration = crd.Generation
		crd.Status.BlockedReason = "Production references require a resource profile before rollout"
		crd.Status.PreflightSummary = "Blocked: resource profile missing"
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "ResourceProfileMissing", crd.Status.BlockedReason)
		r.setCondition(crd, "Degraded", metav1.ConditionTrue, "ResourceProfileMissing", crd.Status.BlockedReason)
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	var nodeCaps *sdkbridge.NodeCapabilityReport
	cm := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{
		Name:      "node-capability-report",
		Namespace: crd.Namespace,
	}, cm)
	if err == nil {
		if data, ok := cm.Data["report.json"]; ok {
			var report sdkbridge.NodeCapabilityReport
			if json.Unmarshal([]byte(data), &report) == nil {
				nodeCaps = &report
			}
		}
	}

	if isProd && crd.Spec.ResourceProfile != nil && nodeCaps == nil {
		crd.Status.Phase = "Degraded"
		crd.Status.ObservedGeneration = crd.Generation
		crd.Status.BlockedReason = "Production data-plane preflight requires a node capability report"
		crd.Status.PreflightSummary = "Blocked: node capability report missing"
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "NodeCapabilitiesMissing", crd.Status.BlockedReason)
		r.setCondition(crd, "Degraded", metav1.ConditionTrue, "NodeCapabilitiesMissing", crd.Status.BlockedReason)
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

		rep, err := r.Bridge.EvaluatePreflight(pReq)
		if err == nil {
			preflightReport = rep
		} else {
			logger.Error(err, "Failed to run preflight check during reconciliation")
			if isProd {
				crd.Status.Phase = "Degraded"
				crd.Status.ObservedGeneration = crd.Generation
				crd.Status.BlockedReason = "Production data-plane preflight evaluation failed"
				crd.Status.PreflightSummary = "Blocked: preflight evaluation failed"
				r.setCondition(crd, "Ready", metav1.ConditionFalse, "PreflightEvaluationFailed", crd.Status.BlockedReason)
				r.setCondition(crd, "Degraded", metav1.ConditionTrue, "PreflightEvaluationFailed", crd.Status.BlockedReason)
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
		CurrentVersion:            1, // simplifed reference model
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
	decision, err := r.Bridge.EvaluateConfigApply(applyReq)
	if err != nil {
		logger.Error(err, "Failed to evaluate config apply policy")
		// Update phase to Degraded on bridge failure
		crd.Status.Phase = "Degraded"
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "SdkBridgeFailure", err.Error())
		r.setCondition(crd, "Degraded", metav1.ConditionTrue, "SdkBridgeFailure", err.Error())
		if updateErr := r.Client.Status().Update(ctx, crd); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	logger.Info("Evaluated policy config-apply decision", "decision", decision.Type)

	// 7. Update CR status based on Decision
	switch decision.Type {
	case "Apply":
		crd.Status.Phase = "Ready"
		crd.Status.ObservedGeneration = crd.Generation
		crd.Status.LastAdmittedVersion = crd.Spec.Version
		crd.Status.CompatibilityDecision = "Allowed"
		crd.Status.BlockedReason = ""
		if preflightReport != nil && preflightReport.Passed {
			crd.Status.PreflightSummary = "Passed"
		} else {
			crd.Status.PreflightSummary = "Skipped"
		}

		// Update conditions
		r.setCondition(crd, "Ready", metav1.ConditionTrue, "ConfigApplied", "Configuration applied successfully")
		r.setCondition(crd, "Degraded", metav1.ConditionFalse, "ConfigApplied", "Configuration applied successfully")

	case "NoOp":
		crd.Status.ObservedGeneration = crd.Generation
		r.setCondition(crd, "Ready", metav1.ConditionTrue, "NoOp", "Configuration is already up to date")

	case "Reject":
		crd.Status.Phase = "Degraded"
		crd.Status.BlockedReason = decision.RejectReason
		crd.Status.CompatibilityDecision = "Rejected"

		r.setCondition(crd, "Ready", metav1.ConditionFalse, "ConfigRejected", decision.RejectReason)
		r.setCondition(crd, "Degraded", metav1.ConditionTrue, "ConfigRejected", decision.RejectReason)

	case "RecoveryRequired":
		crd.Status.Phase = "RecoveryRequired"
		crd.Status.BlockedReason = decision.RecoveryReason
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "RecoveryRequired", decision.RecoveryReason)

	case "Rollback":
		crd.Status.Phase = "RollingBack"
		crd.Status.BlockedReason = decision.RollbackReason
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "RollbackTriggered", fmt.Sprintf("Rollback to version %d: %s", decision.RollbackTarget, decision.RollbackReason))

	case "WaitForDrain":
		crd.Status.Phase = "Draining"
		r.setCondition(crd, "Ready", metav1.ConditionFalse, "WaitingForDrain", "Workload is draining before config application")
	}

	// Collect evidence IDs if present
	if evidence != nil {
		crd.Status.EvidenceIDs = make([]string, len(evidence))
		for i, ev := range evidence {
			crd.Status.EvidenceIDs[i] = ev.EvidenceID
		}
	}

	// Write status back to API server
	if err := r.Client.Status().Update(ctx, crd); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SdkManagedNetworkFunctionReconciler) setCondition(crd *v1beta1.SdkManagedNetworkFunction, cType string, status metav1.ConditionStatus, reason, message string) {
	for i, cond := range crd.Status.Conditions {
		if cond.Type == cType {
			if cond.Status != status || cond.Reason != reason || cond.Message != message {
				crd.Status.Conditions[i].Status = status
				crd.Status.Conditions[i].Reason = reason
				crd.Status.Conditions[i].Message = message
				crd.Status.Conditions[i].LastTransitionTime = metav1.NewTime(time.Now())
				crd.Status.Conditions[i].ObservedGeneration = crd.Generation
			}
			return
		}
	}

	crd.Status.Conditions = append(crd.Status.Conditions, metav1.Condition{
		Type:               cType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(time.Now()),
		ObservedGeneration: crd.Generation,
	})
}

func (r *SdkManagedNetworkFunctionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.SdkManagedNetworkFunction{}).
		Complete(r)
}

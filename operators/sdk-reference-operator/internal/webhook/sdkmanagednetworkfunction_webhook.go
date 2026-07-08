package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// SdkManagedNetworkFunctionValidator validates SdkManagedNetworkFunction resources.
type SdkManagedNetworkFunctionValidator struct {
	Client client.Client
	Bridge *sdkbridge.Bridge
}

func (v *SdkManagedNetworkFunctionValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1beta1.SdkManagedNetworkFunction{}).
		WithValidator(v).
		Complete()
}

var _ admission.Validator[*v1beta1.SdkManagedNetworkFunction] = &SdkManagedNetworkFunctionValidator{}

// ValidateCreate implements admission.CustomValidator.
func (v *SdkManagedNetworkFunctionValidator) ValidateCreate(ctx context.Context, obj *v1beta1.SdkManagedNetworkFunction) (admission.Warnings, error) {
	return v.validate(ctx, obj)
}

// ValidateUpdate implements admission.CustomValidator.
func (v *SdkManagedNetworkFunctionValidator) ValidateUpdate(ctx context.Context, oldObj *v1beta1.SdkManagedNetworkFunction, newObj *v1beta1.SdkManagedNetworkFunction) (admission.Warnings, error) {
	return v.validate(ctx, newObj)
}

// ValidateDelete implements admission.CustomValidator.
func (v *SdkManagedNetworkFunctionValidator) ValidateDelete(ctx context.Context, obj *v1beta1.SdkManagedNetworkFunction) (admission.Warnings, error) {
	return nil, nil
}

func (v *SdkManagedNetworkFunctionValidator) validate(ctx context.Context, crd *v1beta1.SdkManagedNetworkFunction) (admission.Warnings, error) {
	isProd := crd.Spec.RuntimeMode == "production"
	warnings := admission.Warnings{}
	handleInvalidMetadata := func(reason, message string, err error) (bool, admission.Warnings, error) {
		detail := fmt.Sprintf("%s: %s: %v", reason, message, err)
		if isProd {
			return true, nil, fmt.Errorf("admission validation failed: %s", detail)
		}
		warnings = append(warnings, detail)
		return false, warnings, nil
	}

	// 1. Fetch the admin token secret if specified
	var adminToken *string
	tokenEnabled := false
	if crd.Spec.AdminAuthRef.Name != "" {
		tokenEnabled = true
		secret := &corev1.Secret{}
		err := v.Client.Get(ctx, types.NamespacedName{
			Name:      crd.Spec.AdminAuthRef.Name,
			Namespace: crd.Namespace,
		}, secret)

		if err != nil {
			if errors.IsNotFound(err) {
				if isProd {
					return nil, fmt.Errorf("admission validation failed: adminAuthRef secret %s not found in namespace %s", crd.Spec.AdminAuthRef.Name, crd.Namespace)
				}
			} else {
				return nil, fmt.Errorf("failed to fetch adminAuthRef secret: %w", err)
			}
		} else {
			if tokenBytes, ok := secret.Data["admin-token"]; ok {
				str := string(tokenBytes)
				adminToken = &str
			} else if tokenBytes, ok = secret.Data["token"]; ok {
				str := string(tokenBytes)
				adminToken = &str
			}
		}
	}

	// 2. Fetch NodeCapabilityReport if ConfigMap is present
	var nodeCaps *sdkbridge.NodeCapabilityReport
	cm := &corev1.ConfigMap{}
	err := v.Client.Get(ctx, types.NamespacedName{
		Name:      "node-capability-report",
		Namespace: crd.Namespace,
	}, cm)
	if err == nil {
		if data, ok := cm.Data["report.json"]; ok {
			var report sdkbridge.NodeCapabilityReport
			if err := json.Unmarshal([]byte(data), &report); err != nil {
				stop, outWarnings, outErr := handleInvalidMetadata(
					"NodeCapabilitiesMetadataInvalid",
					fmt.Sprintf("invalid report.json in ConfigMap %s/%s", cm.Namespace, cm.Name),
					err,
				)
				if stop || outErr != nil {
					return outWarnings, outErr
				}
			} else {
				nodeCaps = &report
			}
		}
	}

	// 3. Fetch CompatibilityMatrix if compatibilityRef is set
	var compatMatrix *sdkbridge.CompatibilityMatrix
	var evidence []sdkbridge.CompatibilityEvidence
	if crd.Spec.CompatibilityRef != nil {
		compatCM := &corev1.ConfigMap{}
		err := v.Client.Get(ctx, types.NamespacedName{
			Name:      crd.Spec.CompatibilityRef.Name,
			Namespace: crd.Namespace,
		}, compatCM)
		if err == nil {
			if data, ok := compatCM.Data["matrix.json"]; ok {
				var matrix sdkbridge.CompatibilityMatrix
				if err := json.Unmarshal([]byte(data), &matrix); err != nil {
					stop, outWarnings, outErr := handleInvalidMetadata(
						"CompatibilityMetadataInvalid",
						fmt.Sprintf("invalid matrix.json in ConfigMap %s/%s", compatCM.Namespace, compatCM.Name),
						err,
					)
					if stop || outErr != nil {
						return outWarnings, outErr
					}
				} else {
					compatMatrix = &matrix
				}
			}
			if data, ok := compatCM.Data["evidence.json"]; ok {
				var ev []sdkbridge.CompatibilityEvidence
				if err := json.Unmarshal([]byte(data), &ev); err != nil {
					stop, outWarnings, outErr := handleInvalidMetadata(
						"CompatibilityMetadataInvalid",
						fmt.Sprintf("invalid evidence.json in ConfigMap %s/%s", compatCM.Namespace, compatCM.Name),
						err,
					)
					if stop || outErr != nil {
						return outWarnings, outErr
					}
				} else {
					evidence = ev
				}
			}
		}
	}

	// 4. Construct AdmissionRequest
	bridgeReq := &sdkbridge.AdmissionRequest{
		Uid:            string(crd.UID),
		RuntimeMode:    sdkbridge.RuntimeMode(crd.Spec.RuntimeMode),
		ClaimsHA:       crd.Spec.ClaimsHA,
		ConfigBackend:  crd.Spec.ConfigBackend,
		SessionBackend: crd.Spec.SessionBackend,
		AdminAuth: sdkbridge.AdminAuthSpec{
			TokenEnabled: tokenEnabled,
			AdminToken:   adminToken,
		},
		Identity: sdkbridge.IdentitySpec{
			KmsEnabled:    crd.Spec.Identity.KmsEnabled,
			SpiffeEnabled: crd.Spec.Identity.SpiffeEnabled,
		},
		NodeCapabilities:    nodeCaps,
		CompatibilityMatrix: compatMatrix,
		Evidence:            evidence,
	}

	if crd.Spec.ResourceProfile != nil {
		rp := crd.Spec.ResourceProfile
		bridgeReq.ResourceProfile = &sdkbridge.ResourceProfileSpec{
			NfKind:                    rp.NfKind,
			DataPlaneProfile:          rp.DataPlaneProfile,
			NumaPolicy:                rp.NumaPolicy,
			GenericXdpFallbackAllowed: rp.GenericXdpFallbackAllowed,
			IsolatedCores:             rp.IsolatedCores,
			RequireExclusiveCores:     rp.RequireExclusiveCores,
			DataPlaneInterfaces:       rp.DataPlaneInterfaces,
			DataPlaneNumaNode:         rp.DataPlaneNumaNode,
			HugepageNumaNode:          rp.HugepageNumaNode,
			PodSecurityEvidenceID:     rp.PodSecurityEvidenceID,
			SriovResourceName:         rp.SriovResourceName,
			SriovAllowedDeviceDrivers: rp.SriovAllowedDeviceDrivers,
			IpsecNetworkAttachments:   sdkbridgeIpsecNetworkAttachments(rp.IpsecNetworkAttachments),
		}
		if rp.BpfArtifacts != nil {
			bridgeReq.ResourceProfile.BpfArtifacts = make([]sdkbridge.BpfArtifact, len(rp.BpfArtifacts))
			for i, artifact := range rp.BpfArtifacts {
				bridgeReq.ResourceProfile.BpfArtifacts[i] = sdkbridge.BpfArtifact{
					Name:                artifact.Name,
					Digest:              artifact.Digest,
					SignatureRef:        artifact.SignatureRef,
					SignerIdentity:      artifact.SignerIdentity,
					ProgramType:         artifact.ProgramType,
					ExpectedAttachPoint: artifact.ExpectedAttachPoint,
					AllowedCapabilities: append([]string{}, artifact.AllowedCapabilities...),
					EvidenceID:          artifact.EvidenceID,
				}
			}
		}

		bridgeReq.NfRelease = &sdkbridge.NfReleaseDescriptor{
			NfKind:              rp.NfKind,
			NfVersion:           crd.Spec.Version,
			CrdApiVersion:       crd.APIVersion,
			ConfigSchemaVersion: crd.Spec.ConfigSchemaVersion,
			StateSchemaVersion:  crd.Spec.StateSchemaVersion,
		}
		bridgeReq.OperatorRelease = &sdkbridge.OperatorReleaseDescriptor{
			OperatorVersion: "0.1.0",
			SdkVersion:      "0.1.0",
		}
	}

	// 5. Invoke SDK bridge
	resp, err := v.Bridge.EvaluateAdmission(ctx, bridgeReq)
	if err != nil {
		if isProd {
			// Fail closed in production mode
			return nil, fmt.Errorf("admission validation rejected: SDK policy evaluation failure (failed closed): %w", err)
		}
		// Warn but allow in non-production modes
		return append(warnings, fmt.Sprintf("SDK policy evaluation error: %v", err)), nil
	}

	if !resp.Allowed {
		reason := "Rejected"
		msg := "Admission rejected by SDK policy"
		if resp.Status != nil {
			reason = resp.Status.Reason
			msg = resp.Status.Message
		}
		return nil, errors.NewBadRequest(fmt.Sprintf("admission validation rejected: reason=%s, message=%s", reason, msg))
	}

	return warnings, nil
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

package v1alpha1

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

// ConvertTo converts this SdkManagedNetworkFunction (v1alpha1) to the Hub version (v1beta1).
func (src *SdkManagedNetworkFunction) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*v1beta1.SdkManagedNetworkFunction)
	if !ok {
		return fmt.Errorf("expected *v1beta1.SdkManagedNetworkFunction, got %T", dstRaw)
	}

	// 1. Copy ObjectMeta
	dst.ObjectMeta = src.ObjectMeta

	// 2. Copy Spec
	dst.Spec.RuntimeMode = src.Spec.RuntimeMode
	dst.Spec.ClaimsHA = src.Spec.ClaimsHA
	dst.Spec.ConfigBackend = src.Spec.ConfigBackend
	dst.Spec.SessionBackend = src.Spec.SessionBackend

	// SecretReference -> LocalObjectReference conversion (dropping namespace if set, preserving name)
	dst.Spec.AdminAuthRef = corev1.LocalObjectReference{
		Name: src.Spec.AdminAuthRef.Name,
	}

	dst.Spec.Identity = v1beta1.IdentityRequirements{
		KmsEnabled:    src.Spec.Identity.KmsEnabled,
		SpiffeEnabled: src.Spec.Identity.SpiffeEnabled,
	}

	if src.Spec.ResourceProfile != nil {
		dst.Spec.ResourceProfile = &v1beta1.ResourceProfileSpec{
			NfKind:                    src.Spec.ResourceProfile.NfKind,
			DataPlaneProfile:          src.Spec.ResourceProfile.DataPlaneProfile,
			NumaPolicy:                src.Spec.ResourceProfile.NumaPolicy,
			GenericXdpFallbackAllowed: src.Spec.ResourceProfile.GenericXdpFallbackAllowed,
			IsolatedCores:             src.Spec.ResourceProfile.IsolatedCores,
			RequireExclusiveCores:     src.Spec.ResourceProfile.RequireExclusiveCores,
			DataPlaneInterfaces:       src.Spec.ResourceProfile.DataPlaneInterfaces,
			DataPlaneNumaNode:         src.Spec.ResourceProfile.DataPlaneNumaNode,
			HugepageNumaNode:          src.Spec.ResourceProfile.HugepageNumaNode,
			PodSecurityEvidenceID:     src.Spec.ResourceProfile.PodSecurityEvidenceID,
			SriovResourceName:         src.Spec.ResourceProfile.SriovResourceName,
			SriovAllowedDeviceDrivers: src.Spec.ResourceProfile.SriovAllowedDeviceDrivers,
		}
		if src.Spec.ResourceProfile.BpfArtifacts != nil {
			dst.Spec.ResourceProfile.BpfArtifacts = make([]v1beta1.BpfArtifact, len(src.Spec.ResourceProfile.BpfArtifacts))
			for i, artifact := range src.Spec.ResourceProfile.BpfArtifacts {
				dst.Spec.ResourceProfile.BpfArtifacts[i] = v1beta1.BpfArtifact{
					Name:                artifact.Name,
					Digest:              artifact.Digest,
					SignatureRef:        artifact.SignatureRef,
					SignerIdentity:      artifact.SignerIdentity,
					ProgramType:         artifact.ProgramType,
					ExpectedAttachPoint: artifact.ExpectedAttachPoint,
					AllowedCapabilities: append([]string(nil), artifact.AllowedCapabilities...),
					EvidenceID:          copyStringPtr(artifact.EvidenceID),
				}
			}
		}
		dst.Spec.ResourceProfile.IpsecNetworkAttachments =
			convertIpsecNetworkAttachmentsToHub(src.Spec.ResourceProfile.IpsecNetworkAttachments)
	} else {
		dst.Spec.ResourceProfile = nil
	}

	if src.Spec.CompatibilityRef != nil {
		dst.Spec.CompatibilityRef = &corev1.LocalObjectReference{
			Name: src.Spec.CompatibilityRef.Name,
		}
	} else {
		dst.Spec.CompatibilityRef = nil
	}

	dst.Spec.NodeSelector = src.Spec.NodeSelector
	dst.Spec.Version = src.Spec.Version
	dst.Spec.ConfigSchemaVersion = src.Spec.ConfigSchemaVersion
	dst.Spec.StateSchemaVersion = src.Spec.StateSchemaVersion

	// 3. Copy Status
	dst.Status.ObservedGeneration = src.Status.ObservedGeneration
	dst.Status.Phase = src.Status.Phase

	if src.Status.Conditions != nil {
		dst.Status.Conditions = make([]metav1.Condition, len(src.Status.Conditions))
		copy(dst.Status.Conditions, src.Status.Conditions)
	} else {
		dst.Status.Conditions = nil
	}

	dst.Status.CompatibilityDecision = src.Status.CompatibilityDecision
	dst.Status.PreflightSummary = src.Status.PreflightSummary
	dst.Status.LastAdmittedVersion = src.Status.LastAdmittedVersion
	dst.Status.BlockedReason = src.Status.BlockedReason

	if src.Status.EvidenceIDs != nil {
		dst.Status.EvidenceIDs = make([]string, len(src.Status.EvidenceIDs))
		copy(dst.Status.EvidenceIDs, src.Status.EvidenceIDs)
	} else {
		dst.Status.EvidenceIDs = nil
	}

	return nil
}

// ConvertFrom converts from the Hub version (v1beta1) to this SdkManagedNetworkFunction (v1alpha1).
func (dst *SdkManagedNetworkFunction) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*v1beta1.SdkManagedNetworkFunction)
	if !ok {
		return fmt.Errorf("expected *v1beta1.SdkManagedNetworkFunction, got %T", srcRaw)
	}

	// 1. Copy ObjectMeta
	dst.ObjectMeta = src.ObjectMeta

	// 2. Copy Spec
	dst.Spec.RuntimeMode = src.Spec.RuntimeMode
	dst.Spec.ClaimsHA = src.Spec.ClaimsHA
	dst.Spec.ConfigBackend = src.Spec.ConfigBackend
	dst.Spec.SessionBackend = src.Spec.SessionBackend

	// LocalObjectReference -> SecretReference conversion (using object namespace as default if namespace was empty)
	dst.Spec.AdminAuthRef = corev1.SecretReference{
		Name:      src.Spec.AdminAuthRef.Name,
		Namespace: src.Namespace,
	}

	dst.Spec.Identity = IdentityRequirements{
		KmsEnabled:    src.Spec.Identity.KmsEnabled,
		SpiffeEnabled: src.Spec.Identity.SpiffeEnabled,
	}

	if src.Spec.ResourceProfile != nil {
		dst.Spec.ResourceProfile = &ResourceProfileSpec{
			NfKind:                    src.Spec.ResourceProfile.NfKind,
			DataPlaneProfile:          src.Spec.ResourceProfile.DataPlaneProfile,
			NumaPolicy:                src.Spec.ResourceProfile.NumaPolicy,
			GenericXdpFallbackAllowed: src.Spec.ResourceProfile.GenericXdpFallbackAllowed,
			IsolatedCores:             src.Spec.ResourceProfile.IsolatedCores,
			RequireExclusiveCores:     src.Spec.ResourceProfile.RequireExclusiveCores,
			DataPlaneInterfaces:       src.Spec.ResourceProfile.DataPlaneInterfaces,
			DataPlaneNumaNode:         src.Spec.ResourceProfile.DataPlaneNumaNode,
			HugepageNumaNode:          src.Spec.ResourceProfile.HugepageNumaNode,
			PodSecurityEvidenceID:     src.Spec.ResourceProfile.PodSecurityEvidenceID,
			SriovResourceName:         src.Spec.ResourceProfile.SriovResourceName,
			SriovAllowedDeviceDrivers: src.Spec.ResourceProfile.SriovAllowedDeviceDrivers,
		}
		if src.Spec.ResourceProfile.BpfArtifacts != nil {
			dst.Spec.ResourceProfile.BpfArtifacts = make([]BpfArtifact, len(src.Spec.ResourceProfile.BpfArtifacts))
			for i, artifact := range src.Spec.ResourceProfile.BpfArtifacts {
				dst.Spec.ResourceProfile.BpfArtifacts[i] = BpfArtifact{
					Name:                artifact.Name,
					Digest:              artifact.Digest,
					SignatureRef:        artifact.SignatureRef,
					SignerIdentity:      artifact.SignerIdentity,
					ProgramType:         artifact.ProgramType,
					ExpectedAttachPoint: artifact.ExpectedAttachPoint,
					AllowedCapabilities: append([]string(nil), artifact.AllowedCapabilities...),
					EvidenceID:          copyStringPtr(artifact.EvidenceID),
				}
			}
		}
		dst.Spec.ResourceProfile.IpsecNetworkAttachments =
			convertIpsecNetworkAttachmentsFromHub(src.Spec.ResourceProfile.IpsecNetworkAttachments)
	} else {
		dst.Spec.ResourceProfile = nil
	}

	if src.Spec.CompatibilityRef != nil {
		dst.Spec.CompatibilityRef = &corev1.LocalObjectReference{
			Name: src.Spec.CompatibilityRef.Name,
		}
	} else {
		dst.Spec.CompatibilityRef = nil
	}

	dst.Spec.NodeSelector = src.Spec.NodeSelector
	dst.Spec.Version = src.Spec.Version
	dst.Spec.ConfigSchemaVersion = src.Spec.ConfigSchemaVersion
	dst.Spec.StateSchemaVersion = src.Spec.StateSchemaVersion

	// 3. Copy Status
	dst.Status.ObservedGeneration = src.Status.ObservedGeneration
	dst.Status.Phase = src.Status.Phase

	if src.Status.Conditions != nil {
		dst.Status.Conditions = make([]metav1.Condition, len(src.Status.Conditions))
		copy(dst.Status.Conditions, src.Status.Conditions)
	} else {
		dst.Status.Conditions = nil
	}

	dst.Status.CompatibilityDecision = src.Status.CompatibilityDecision
	dst.Status.PreflightSummary = src.Status.PreflightSummary
	dst.Status.LastAdmittedVersion = src.Status.LastAdmittedVersion
	dst.Status.BlockedReason = src.Status.BlockedReason

	if src.Status.EvidenceIDs != nil {
		dst.Status.EvidenceIDs = make([]string, len(src.Status.EvidenceIDs))
		copy(dst.Status.EvidenceIDs, src.Status.EvidenceIDs)
	} else {
		dst.Status.EvidenceIDs = nil
	}

	return nil
}

func convertIpsecNetworkAttachmentsToHub(in []IpsecNetworkAttachmentSpec) []v1beta1.IpsecNetworkAttachmentSpec {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.IpsecNetworkAttachmentSpec, len(in))
	for i, attachment := range in {
		out[i] = v1beta1.IpsecNetworkAttachmentSpec{
			InterfaceName:       attachment.InterfaceName,
			Plane:               attachment.Plane,
			CniType:             attachment.CniType,
			StaticIPRequired:    attachment.StaticIPRequired,
			StaticIP:            copyStringPtr(attachment.StaticIP),
			MinimumMTU:          cloneUint16Ptr(attachment.MinimumMTU),
			MTU:                 cloneUint16Ptr(attachment.MTU),
			SourceRouteRequired: attachment.SourceRouteRequired,
			SourceRoute:         copyStringPtr(attachment.SourceRoute),
			VlanID:              cloneUint16Ptr(attachment.VlanID),
		}
	}
	return out
}

func convertIpsecNetworkAttachmentsFromHub(in []v1beta1.IpsecNetworkAttachmentSpec) []IpsecNetworkAttachmentSpec {
	if in == nil {
		return nil
	}
	out := make([]IpsecNetworkAttachmentSpec, len(in))
	for i, attachment := range in {
		out[i] = IpsecNetworkAttachmentSpec{
			InterfaceName:       attachment.InterfaceName,
			Plane:               attachment.Plane,
			CniType:             attachment.CniType,
			StaticIPRequired:    attachment.StaticIPRequired,
			StaticIP:            copyStringPtr(attachment.StaticIP),
			MinimumMTU:          cloneUint16Ptr(attachment.MinimumMTU),
			MTU:                 cloneUint16Ptr(attachment.MTU),
			SourceRouteRequired: attachment.SourceRouteRequired,
			SourceRoute:         copyStringPtr(attachment.SourceRoute),
			VlanID:              cloneUint16Ptr(attachment.VlanID),
		}
	}
	return out
}

func cloneUint16Ptr(in *uint16) *uint16 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

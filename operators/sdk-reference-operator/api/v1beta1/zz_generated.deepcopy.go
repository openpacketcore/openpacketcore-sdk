package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies all properties of this object to another instance.
func (in *SdkManagedNetworkFunction) DeepCopyInto(out *SdkManagedNetworkFunction) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)

	// Copy Spec
	out.Spec = in.Spec
	if in.Spec.ResourceProfile != nil {
		out.Spec.ResourceProfile = &ResourceProfileSpec{
			NfKind:                    in.Spec.ResourceProfile.NfKind,
			DataPlaneProfile:          in.Spec.ResourceProfile.DataPlaneProfile,
			NumaPolicy:                in.Spec.ResourceProfile.NumaPolicy,
			GenericXdpFallbackAllowed: in.Spec.ResourceProfile.GenericXdpFallbackAllowed,
			RequireExclusiveCores:     in.Spec.ResourceProfile.RequireExclusiveCores,
		}
		if in.Spec.ResourceProfile.IsolatedCores != nil {
			out.Spec.ResourceProfile.IsolatedCores = make([]uint16, len(in.Spec.ResourceProfile.IsolatedCores))
			copy(out.Spec.ResourceProfile.IsolatedCores, in.Spec.ResourceProfile.IsolatedCores)
		}
		if in.Spec.ResourceProfile.DataPlaneInterfaces != nil {
			out.Spec.ResourceProfile.DataPlaneInterfaces = make([]string, len(in.Spec.ResourceProfile.DataPlaneInterfaces))
			copy(out.Spec.ResourceProfile.DataPlaneInterfaces, in.Spec.ResourceProfile.DataPlaneInterfaces)
		}
		if in.Spec.ResourceProfile.DataPlaneNumaNode != nil {
			val := *in.Spec.ResourceProfile.DataPlaneNumaNode
			out.Spec.ResourceProfile.DataPlaneNumaNode = &val
		}
		if in.Spec.ResourceProfile.HugepageNumaNode != nil {
			val := *in.Spec.ResourceProfile.HugepageNumaNode
			out.Spec.ResourceProfile.HugepageNumaNode = &val
		}
		if in.Spec.ResourceProfile.PodSecurityEvidenceID != nil {
			val := *in.Spec.ResourceProfile.PodSecurityEvidenceID
			out.Spec.ResourceProfile.PodSecurityEvidenceID = &val
		}
		if in.Spec.ResourceProfile.SriovResourceName != nil {
			val := *in.Spec.ResourceProfile.SriovResourceName
			out.Spec.ResourceProfile.SriovResourceName = &val
		}
		if in.Spec.ResourceProfile.SriovAllowedDeviceDrivers != nil {
			out.Spec.ResourceProfile.SriovAllowedDeviceDrivers = make([]string, len(in.Spec.ResourceProfile.SriovAllowedDeviceDrivers))
			copy(out.Spec.ResourceProfile.SriovAllowedDeviceDrivers, in.Spec.ResourceProfile.SriovAllowedDeviceDrivers)
		}
		if in.Spec.ResourceProfile.IpsecNetworkAttachments != nil {
			out.Spec.ResourceProfile.IpsecNetworkAttachments = make([]IpsecNetworkAttachmentSpec, len(in.Spec.ResourceProfile.IpsecNetworkAttachments))
			for i := range in.Spec.ResourceProfile.IpsecNetworkAttachments {
				in.Spec.ResourceProfile.IpsecNetworkAttachments[i].DeepCopyInto(&out.Spec.ResourceProfile.IpsecNetworkAttachments[i])
			}
		}
		if in.Spec.ResourceProfile.BpfArtifacts != nil {
			out.Spec.ResourceProfile.BpfArtifacts = make([]BpfArtifact, len(in.Spec.ResourceProfile.BpfArtifacts))
			for i := range in.Spec.ResourceProfile.BpfArtifacts {
				in.Spec.ResourceProfile.BpfArtifacts[i].DeepCopyInto(&out.Spec.ResourceProfile.BpfArtifacts[i])
			}
		}
	}
	if in.Spec.CompatibilityRef != nil {
		out.Spec.CompatibilityRef = in.Spec.CompatibilityRef
	}
	if in.Spec.NodeSelector != nil {
		out.Spec.NodeSelector = make(map[string]string, len(in.Spec.NodeSelector))
		for k, v := range in.Spec.NodeSelector {
			out.Spec.NodeSelector[k] = v
		}
	}

	// Copy Status
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = make([]metav1.Condition, len(in.Status.Conditions))
		copy(out.Status.Conditions, in.Status.Conditions)
	}
	if in.Status.EvidenceIDs != nil {
		out.Status.EvidenceIDs = make([]string, len(in.Status.EvidenceIDs))
		copy(out.Status.EvidenceIDs, in.Status.EvidenceIDs)
	}
}

// DeepCopy copies this object to a new instance.
func (in *SdkManagedNetworkFunction) DeepCopy() *SdkManagedNetworkFunction {
	if in == nil {
		return nil
	}
	out := new(SdkManagedNetworkFunction)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies this object to a runtime.Object.
func (in *SdkManagedNetworkFunction) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *BpfArtifact) DeepCopyInto(out *BpfArtifact) {
	*out = *in
	if in.AllowedCapabilities != nil {
		out.AllowedCapabilities = make([]string, len(in.AllowedCapabilities))
		copy(out.AllowedCapabilities, in.AllowedCapabilities)
	}
	if in.EvidenceID != nil {
		val := *in.EvidenceID
		out.EvidenceID = &val
	}
}

func (in *IpsecNetworkAttachmentSpec) DeepCopyInto(out *IpsecNetworkAttachmentSpec) {
	*out = *in
	if in.StaticIP != nil {
		val := *in.StaticIP
		out.StaticIP = &val
	}
	if in.MinimumMTU != nil {
		val := *in.MinimumMTU
		out.MinimumMTU = &val
	}
	if in.MTU != nil {
		val := *in.MTU
		out.MTU = &val
	}
	if in.SourceRoute != nil {
		val := *in.SourceRoute
		out.SourceRoute = &val
	}
	if in.VlanID != nil {
		val := *in.VlanID
		out.VlanID = &val
	}
}

// DeepCopyInto copies all properties of this SdkManagedNetworkFunctionList to another instance.
func (in *SdkManagedNetworkFunctionList) DeepCopyInto(out *SdkManagedNetworkFunctionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SdkManagedNetworkFunction, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy copies this list to a new instance.
func (in *SdkManagedNetworkFunctionList) DeepCopy() *SdkManagedNetworkFunctionList {
	if in == nil {
		return nil
	}
	out := new(SdkManagedNetworkFunctionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies this list to a runtime.Object.
func (in *SdkManagedNetworkFunctionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

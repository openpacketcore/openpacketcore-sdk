package workload

// ResourceProfile mirrors the relevant fields from the CRD resource profile
// so the workload package does not depend on any specific operator API module.
type ResourceProfile struct {
	NfKind                    string
	DataPlaneProfile          string
	NumaPolicy                string
	GenericXdpFallbackAllowed bool
	IsolatedCores             []uint16
	RequireExclusiveCores     bool
	DataPlaneInterfaces       []string
	DataPlaneNumaNode         *uint16
	HugepageNumaNode          *uint16
	PodSecurityEvidenceID     *string
	BpfArtifacts              []BpfArtifact
	SriovResourceName         *string
	SriovAllowedDeviceDrivers []string
}

// BpfArtifact describes a signed BPF program artifact.
type BpfArtifact struct {
	Name                string
	Digest              string
	SignatureRef        string
	SignerIdentity      string
	ProgramType         string
	ExpectedAttachPoint string
	AllowedCapabilities []string
	EvidenceID          *string
}

// PortSpec describes an additional workload port. The Protocol field accepts
// "TCP", "UDP", and "SCTP" (case-insensitive); it defaults to TCP when empty.
type PortSpec struct {
	Name     string
	Port     int32
	Protocol string
}

// MultusAttachment describes a single Multus network attachment for a pod.
type MultusAttachment struct {
	Name           string
	NetworkName    string
	Namespace      string
	InterfaceName  string
	AttachmentType NetworkAttachmentType
}

// NetworkAttachmentType identifies the CNI attachment mechanism.
type NetworkAttachmentType string

const (
	// NetworkAttachmentTypeSRIOV uses an SR-IOV CNI via a device resource.
	NetworkAttachmentTypeSRIOV NetworkAttachmentType = "sriov"
	// NetworkAttachmentTypeMacvlan uses a macvlan CNI.
	NetworkAttachmentTypeMacvlan NetworkAttachmentType = "macvlan"
)

// NetworkFunctionSpec is the operator-agnostic input to RenderDeployment.
type NetworkFunctionSpec struct {
	Name            string
	Namespace       string
	Version         string
	RuntimeMode     string
	ResourceProfile *ResourceProfile
	NodeSelector    map[string]string
	// AdditionalPorts are product-specific service ports exposed by the NF.
	AdditionalPorts []PortSpec
	// MultusAttachments configure Multus network attachments on the pod.
	MultusAttachments []MultusAttachment
	// ConfigPushObservedGeneration records the last spec generation whose
	// config was successfully pushed to the workload. It is part of the
	// immutable-image-tag / observed-generation status surface.
	ConfigPushObservedGeneration int64
	// ImageTag is an optional immutable image tag. When set, RenderDeployment
	// validates that it matches the tag portion of opts.Image so operators can
	// fail closed on accidental mutable-tag updates.
	ImageTag string
}

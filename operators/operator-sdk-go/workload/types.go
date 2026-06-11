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

// NetworkFunctionSpec is the operator-agnostic input to RenderDeployment.
type NetworkFunctionSpec struct {
	Name            string
	Namespace       string
	Version         string
	RuntimeMode     string
	ResourceProfile *ResourceProfile
	NodeSelector    map[string]string
}

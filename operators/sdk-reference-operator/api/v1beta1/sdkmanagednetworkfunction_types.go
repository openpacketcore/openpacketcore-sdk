package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: This is a Go reference operator harness API for demonstration/reference.
// It is explicitly NOT a product CNF API (such as a production AMF/SMF/UPF operator API).

type BpfArtifact struct {
	Name                string   `json:"name"`
	Digest              string   `json:"digest"`
	SignatureRef        string   `json:"signatureRef"`
	SignerIdentity      string   `json:"signerIdentity"`
	ProgramType         string   `json:"programType"`
	ExpectedAttachPoint string   `json:"expectedAttachPoint"`
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
	EvidenceID          *string  `json:"evidenceId,omitempty"`
}

type ResourceProfileSpec struct {
	NfKind                    string                       `json:"nfKind"`
	DataPlaneProfile          string                       `json:"dataPlaneProfile"`
	NumaPolicy                string                       `json:"numaPolicy"`
	GenericXdpFallbackAllowed bool                         `json:"genericXdpFallbackAllowed"`
	IsolatedCores             []uint16                     `json:"isolatedCores"`
	RequireExclusiveCores     bool                         `json:"requireExclusiveCores"`
	DataPlaneInterfaces       []string                     `json:"dataPlaneInterfaces,omitempty"`
	DataPlaneNumaNode         *uint16                      `json:"dataPlaneNumaNode,omitempty"`
	HugepageNumaNode          *uint16                      `json:"hugepageNumaNode,omitempty"`
	PodSecurityEvidenceID     *string                      `json:"podSecurityEvidenceId,omitempty"`
	BpfArtifacts              []BpfArtifact                `json:"bpfArtifacts,omitempty"`
	SriovResourceName         *string                      `json:"sriovResourceName,omitempty"`
	SriovAllowedDeviceDrivers []string                     `json:"sriovAllowedDeviceDrivers,omitempty"`
	IpsecNetworkAttachments   []IpsecNetworkAttachmentSpec `json:"ipsecNetworkAttachments,omitempty"`
}

type IpsecNetworkAttachmentSpec struct {
	InterfaceName       string  `json:"interfaceName"`
	Plane               string  `json:"plane"`
	CniType             string  `json:"cniType"`
	StaticIPRequired    bool    `json:"staticIpRequired,omitempty"`
	StaticIP            *string `json:"staticIp,omitempty"`
	MinimumMTU          *uint16 `json:"minimumMtu,omitempty"`
	MTU                 *uint16 `json:"mtu,omitempty"`
	SourceRouteRequired bool    `json:"sourceRouteRequired,omitempty"`
	SourceRoute         *string `json:"sourceRoute,omitempty"`
	VlanID              *uint16 `json:"vlanId,omitempty"`
}

type IdentityRequirements struct {
	KmsEnabled    bool `json:"kmsEnabled"`
	SpiffeEnabled bool `json:"spiffeEnabled"`
}

// SdkManagedNetworkFunctionSpec defines the desired state of SdkManagedNetworkFunction
type SdkManagedNetworkFunctionSpec struct {
	// +kubebuilder:validation:Enum=production;dev;lab;conformance;perf
	RuntimeMode         string                       `json:"runtimeMode"`
	ClaimsHA            bool                         `json:"claimsHA"`
	ConfigBackend       string                       `json:"configBackend"`
	SessionBackend      string                       `json:"sessionBackend"`
	AdminAuthRef        corev1.LocalObjectReference  `json:"adminAuthRef"`
	Identity            IdentityRequirements         `json:"identity"`
	ResourceProfile     *ResourceProfileSpec         `json:"resourceProfile,omitempty"`
	CompatibilityRef    *corev1.LocalObjectReference `json:"compatibilityRef,omitempty"`
	NodeSelector        map[string]string            `json:"nodeSelector,omitempty"`
	Version             string                       `json:"version"`
	ConfigSchemaVersion string                       `json:"configSchemaVersion"`
	StateSchemaVersion  string                       `json:"stateSchemaVersion"`
}

// SdkManagedNetworkFunctionStatus defines the observed state of SdkManagedNetworkFunction
type SdkManagedNetworkFunctionStatus struct {
	ObservedGeneration    int64              `json:"observedGeneration,omitempty"`
	Phase                 string             `json:"phase,omitempty"`
	Conditions            []metav1.Condition `json:"conditions,omitempty"`
	CompatibilityDecision string             `json:"compatibilityDecision,omitempty"`
	PreflightSummary      string             `json:"preflightSummary,omitempty"`
	LastAdmittedVersion   string             `json:"lastAdmittedVersion,omitempty"`
	BlockedReason         string             `json:"blockedReason,omitempty"`
	EvidenceIDs           []string           `json:"evidenceIds,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SdkManagedNetworkFunction is the Schema for the sdkmanagednetworkfunctions API
type SdkManagedNetworkFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SdkManagedNetworkFunctionSpec   `json:"spec,omitempty"`
	Status SdkManagedNetworkFunctionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SdkManagedNetworkFunctionList contains a list of SdkManagedNetworkFunction
type SdkManagedNetworkFunctionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SdkManagedNetworkFunction `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SdkManagedNetworkFunction{}, &SdkManagedNetworkFunctionList{})
}

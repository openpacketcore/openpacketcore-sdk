package sdkbridge

import (
	"encoding/json"
	"fmt"
)

type RuntimeMode string

const (
	RuntimeModeProduction RuntimeMode = "production"
	RuntimeModeTesting    RuntimeMode = "dev"
)

type AdminAuthSpec struct {
	TokenEnabled bool    `json:"token_enabled"`
	AdminToken   *string `json:"admin_token"`
}

type IdentitySpec struct {
	KmsEnabled    bool `json:"kms_enabled"`
	SpiffeEnabled bool `json:"spiffe_enabled"`
}

type BpfArtifact struct {
	Name                string   `json:"name"`
	Digest              string   `json:"digest"`
	SignatureRef        string   `json:"signature_ref"`
	SignerIdentity      string   `json:"signer_identity"`
	ProgramType         string   `json:"program_type"`
	ExpectedAttachPoint string   `json:"expected_attach_point"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	EvidenceID          *string  `json:"evidence_id,omitempty"`
}

type ResourceProfileSpec struct {
	NfKind                    string        `json:"nf_kind"`
	DataPlaneProfile          string        `json:"data_plane_profile"`
	NumaPolicy                string        `json:"numa_policy"`
	GenericXdpFallbackAllowed bool          `json:"generic_xdp_fallback_allowed"`
	IsolatedCores             []uint16      `json:"isolated_cores"`
	RequireExclusiveCores     bool          `json:"require_exclusive_cores"`
	DataPlaneInterfaces       []string      `json:"data_plane_interfaces,omitempty"`
	DataPlaneNumaNode         *uint16       `json:"data_plane_numa_node,omitempty"`
	HugepageNumaNode          *uint16       `json:"hugepage_numa_node,omitempty"`
	PodSecurityEvidenceID     *string       `json:"pod_security_evidence_id,omitempty"`
	BpfArtifacts              []BpfArtifact `json:"bpf_artifacts,omitempty"`
	SriovResourceName         *string       `json:"sriov_resource_name,omitempty"`
	SriovAllowedDeviceDrivers []string      `json:"sriov_allowed_device_drivers,omitempty"`
}

type KernelVersion struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
	Patch uint16 `json:"patch"`
}

type BpfCapabilities struct {
	CapBpf              bool     `json:"cap_bpf"`
	XdpSupported        bool     `json:"xdp_supported"`
	BtfAvailable        bool     `json:"btf_available"`
	CapSysAdminRequired bool     `json:"cap_sys_admin_required"`
	AvailableXdpModes   []string `json:"available_xdp_modes"`
}

type HugepagePool struct {
	NumaNode uint16 `json:"numa_node"`
	Size     string `json:"size"`
	Total    uint64 `json:"total"`
	Free     uint64 `json:"free"`
}

type NodeCpuCapabilities struct {
	ManagerPolicy         string            `json:"manager_policy"`
	IsolatedCores         []uint16          `json:"isolated_cores"`
	NumaNodes             uint16            `json:"numa_nodes"`
	CpuIDs                []uint16          `json:"cpu_ids"`
	ReservedCores         []uint16          `json:"reserved_cores"`
	TopologyManagerPolicy string            `json:"topology_manager_policy"`
	CpuNumaMap            map[uint16]uint16 `json:"cpu_numa_map"`
}

type NodeMemoryCapabilities struct {
	Hugepages2Mi  uint64         `json:"hugepages_2mi"`
	Hugepages1Gi  uint64         `json:"hugepages_1gi"`
	HugepagePools []HugepagePool `json:"hugepage_pools"`
}

type NicCapability struct {
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	SriovVfs uint16   `json:"sriov_vfs"`
	XdpModes []string `json:"xdp_modes"`
	Queues   uint16   `json:"queues"`
	NumaNode *uint16  `json:"numa_node,omitempty"`
}

type NodeCapabilityReport struct {
	Kernel KernelVersion          `json:"kernel"`
	Bpf    BpfCapabilities        `json:"bpf"`
	Cpu    NodeCpuCapabilities    `json:"cpu"`
	Memory NodeMemoryCapabilities `json:"memory"`
	Nics   []NicCapability        `json:"nics"`
}

type OperatorReleaseDescriptor struct {
	OperatorVersion string `json:"operator_version"`
	SdkVersion      string `json:"sdk_version"`
}

type NfReleaseDescriptor struct {
	NfKind              string `json:"nf_kind"`
	NfVersion           string `json:"nf_version"`
	CrdApiVersion       string `json:"crd_api_version"`
	ConfigSchemaVersion string `json:"config_schema_version"`
	StateSchemaVersion  string `json:"state_schema_version"`
}

type MigrationCompatibility struct {
	SourceVersionRange string `json:"source_version_range"`
	TargetVersionRange string `json:"target_version_range"`
	AllowedRollback    bool   `json:"allowed_rollback"`
}

type CompatibilityRule struct {
	RuleID                      string                   `json:"rule_id"`
	OperatorVersionRange        string                   `json:"operator_version_range"`
	SdkVersionRange             string                   `json:"sdk_version_range"`
	NfKind                      string                   `json:"nf_kind"`
	NfVersionRange              string                   `json:"nf_version_range"`
	CrdApiVersionRange          string                   `json:"crd_api_version_range"`
	ConfigSchemaVersionRange    string                   `json:"config_schema_version_range"`
	StateSchemaVersionRange     string                   `json:"state_schema_version_range"`
	RequiredFeatures            []string                 `json:"required_features"`
	RequiredRuntimeModes        []RuntimeMode            `json:"required_runtime_modes"`
	RequiredPersistenceProfiles []string                 `json:"required_persistence_profiles"`
	AllowedMigrations           []MigrationCompatibility `json:"allowed_migrations"`
}

type CompatibilityMatrix struct {
	Rules []CompatibilityRule `json:"rules"`
}

type CompatibilityEvidence struct {
	EvidenceID string `json:"evidence_id"`
	ApprovedBy string `json:"approved_by"`
	Timestamp  string `json:"timestamp"`
}

type AdmissionRequest struct {
	Uid                 string                     `json:"uid"`
	RuntimeMode         RuntimeMode                `json:"runtime_mode"`
	ClaimsHA            bool                       `json:"claims_ha"`
	ConfigBackend       string                     `json:"config_backend"`
	SessionBackend      string                     `json:"session_backend"`
	AdminAuth           AdminAuthSpec              `json:"admin_auth"`
	Identity            IdentitySpec               `json:"identity"`
	ResourceProfile     *ResourceProfileSpec       `json:"resource_profile"`
	NodeCapabilities    *NodeCapabilityReport      `json:"node_capabilities"`
	OperatorRelease     *OperatorReleaseDescriptor `json:"operator_release"`
	NfRelease           *NfReleaseDescriptor       `json:"nf_release"`
	CompatibilityMatrix *CompatibilityMatrix       `json:"compatibility_matrix"`
	Evidence            []CompatibilityEvidence    `json:"evidence"`
}

type AdmissionStatus struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

type AdmissionResponse struct {
	Uid     string           `json:"uid"`
	Allowed bool             `json:"allowed"`
	Status  *AdmissionStatus `json:"status"`
}

type CompatibilityRequest struct {
	Operator            OperatorReleaseDescriptor `json:"operator"`
	Nf                  NfReleaseDescriptor       `json:"nf"`
	RuntimeMode         RuntimeMode               `json:"runtime_mode"`
	ConfigBackend       string                    `json:"config_backend"`
	SessionBackend      string                    `json:"session_backend"`
	IdentityKms         bool                      `json:"identity_kms"`
	IdentitySpiffe      bool                      `json:"identity_spiffe"`
	HasResourceProfile  bool                      `json:"has_resource_profile"`
	CompatibilityMatrix CompatibilityMatrix       `json:"compatibility_matrix"`
	Evidence            []CompatibilityEvidence   `json:"evidence"`
}

type CompatibilityDecision struct {
	Type          string // "Allowed" or "Blocked"
	BlockedReason string // String description of Blocked reason
}

func (c *CompatibilityDecision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil && s == "Allowed" {
		c.Type = "Allowed"
		return nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err == nil {
		if blockObj, exists := m["Blocked"]; exists {
			c.Type = "Blocked"
			if blockBytes, err := json.Marshal(blockObj); err == nil {
				c.BlockedReason = string(blockBytes)
			}
			return nil
		}
	}
	return json.Unmarshal(data, &c.Type) // fallback
}

type ConfigApplyDecision struct {
	Type           string // "Apply", "NoOp", "Reject", "Rollback", "RecoveryRequired", "WaitForDrain"
	RejectReason   string
	RollbackTarget uint64
	RollbackReason string
	RecoveryReason string
}

func (c *ConfigApplyDecision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		c.Type = s
		return nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err == nil {
		if val, ok := m["Reject"]; ok {
			c.Type = "Reject"
			c.RejectReason, _ = val.(string)
			return nil
		}
		if val, ok := m["RecoveryRequired"]; ok {
			c.Type = "RecoveryRequired"
			c.RecoveryReason, _ = val.(string)
			return nil
		}
		if val, ok := m["Rollback"]; ok {
			c.Type = "Rollback"
			if rollbackMap, ok := val.(map[string]interface{}); ok {
				if tv, ok := rollbackMap["target_version"]; ok {
					if num, ok := tv.(float64); ok {
						c.RollbackTarget = uint64(num)
					}
				}
				if r, ok := rollbackMap["reason"]; ok {
					c.RollbackReason, _ = r.(string)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("unknown ConfigApplyDecision payload: %s", string(data))
}

type PreflightRequest struct {
	ResourceProfile  ResourceProfileSpec  `json:"resource_profile"`
	NodeCapabilities NodeCapabilityReport `json:"node_capabilities"`
}

type PreflightCheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DataPlanePreflightReport struct {
	Passed            bool                   `json:"passed"`
	BlocksReadiness   bool                   `json:"blocks_readiness"`
	Messages          []string               `json:"messages"`
	EvidenceIDs       []string               `json:"evidence_ids"`
	LabFallbackActive bool                   `json:"lab_fallback_active"`
	Checks            []PreflightCheckResult `json:"checks"`
}

type CandidateMetadata struct {
	Version             uint64                     `json:"version"`
	SchemaDigest        string                     `json:"schema_digest"`
	IsCommitConfirmed   bool                       `json:"is_commit_confirmed"`
	ConfirmTimeoutSecs  *uint64                    `json:"confirm_timeout_secs,omitempty"`
	OperatorRelease     *OperatorReleaseDescriptor `json:"operator_release,omitempty"`
	NfRelease           *NfReleaseDescriptor       `json:"nf_release,omitempty"`
	CompatibilityMatrix *CompatibilityMatrix       `json:"compatibility_matrix,omitempty"`
	Evidence            []CompatibilityEvidence    `json:"evidence,omitempty"`
}

type LifecycleCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"` // "True", "False", "Unknown"
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionTime string `json:"lastTransitionTime"`
	Severity           string `json:"severity"` // "info", "warning", "error"
	RedactionSafeText  bool   `json:"redactionSafeText"`
}

type LifecycleStatus struct {
	Phase              string               `json:"phase"` // "Pending", "Installing", "Starting", "Ready", etc.
	Conditions         []LifecycleCondition `json:"conditions"`
	ObservedGeneration int64                `json:"observedGeneration"`
}

type Alarm struct {
	AlarmID        string                 `json:"alarm_id"`
	AlarmType      string                 `json:"alarm_type"`
	Severity       string                 `json:"severity"`
	ProbableCause  string                 `json:"probable_cause"`
	AffectedObject map[string]interface{} `json:"affected_object"`
	Tenant         *string                `json:"tenant,omitempty"`
	Slice          *string                `json:"slice,omitempty"`
	Region         *string                `json:"region,omitempty"`
	Text           string                 `json:"text"`
	Details        map[string]interface{} `json:"details,omitempty"`
	State          string                 `json:"state"`
	RaisedAt       string                 `json:"raised_at"`
	UpdatedAt      string                 `json:"updated_at"`
	ClearedAt      *string                `json:"cleared_at,omitempty"`
	CorrelationID  *string                `json:"correlation_id,omitempty"`
}

type PendingConfirmationState struct {
	Version                  uint64 `json:"version"`
	PreviousConfirmedVersion uint64 `json:"previous_confirmed_version"`
	AppliedAt                string `json:"applied_at"`
	TimeoutSecs              uint64 `json:"timeout_secs"`
}

type ConfigApplyRequest struct {
	DesiredGeneration         int64                     `json:"desired_generation"`
	CurrentObservedGeneration int64                     `json:"current_observed_generation"`
	CurrentVersion            uint64                    `json:"current_version"`
	CurrentDigest             string                    `json:"current_digest"`
	Candidate                 *CandidateMetadata        `json:"candidate,omitempty"`
	LifecycleStatus           LifecycleStatus           `json:"lifecycle_status"`
	ActiveAlarms              []Alarm                   `json:"active_alarms"`
	PendingConfirmation       *PendingConfirmationState `json:"pending_confirmation,omitempty"`
	PreflightReport           *DataPlanePreflightReport `json:"preflight_report,omitempty"`
	CurrentTime               *string                   `json:"current_time,omitempty"`
}

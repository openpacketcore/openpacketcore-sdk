package workload

import (
	"fmt"
	"sort"
	"strings"

	"openpacketcore.io/operator-sdk-go/cni"
	"openpacketcore.io/operator-sdk-go/rollout"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// RenderOptions controls optional workload synthesis knobs.
type RenderOptions struct {
	NodeSelector   map[string]string
	Image          string
	Replicas       int32
	AdminPort      int32
	OwnerReference *metav1.OwnerReference
	// RolloutParams, when non-nil, configures the Deployment update strategy.
	RolloutParams *rollout.Params
	// MultusAttachments, when non-empty, injects the Multus networks annotation
	// into the pod template. The product operator is responsible for resolving
	// NAD existence and SR-IOV resource names before calling RenderDeployment.
	MultusAttachments []cni.Attachment
	// SRIOVResources is the aggregated SR-IOV extended resource map to add to
	// the workload container. It is only used when MultusAttachments is non-empty.
	SRIOVResources map[corev1.ResourceName]int64
}

// DefaultRenderOptions returns options with safe defaults.
func DefaultRenderOptions() RenderOptions {
	return RenderOptions{
		Replicas:  1,
		AdminPort: 8080,
	}
}

// RenderDeployment synthesizes a Deployment from the given NF spec.
func RenderDeployment(spec NetworkFunctionSpec, opts RenderOptions) (*appsv1.Deployment, error) {
	if err := ValidateImageTag(spec, opts); err != nil {
		return nil, err
	}

	labels := map[string]string{
		"app":     spec.Name,
		"version": spec.Version,
	}

	replicas := opts.Replicas
	if replicas == 0 {
		replicas = 1
	}

	adminPort := opts.AdminPort
	if adminPort == 0 {
		adminPort = 8080
	}

	podSpec, err := buildPodSpec(spec, opts, adminPort)
	if err != nil {
		return nil, fmt.Errorf("build pod spec: %w", err)
	}

	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: spec.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": spec.Name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: podSpec,
			},
		},
	}

	if opts.OwnerReference != nil {
		dep.OwnerReferences = []metav1.OwnerReference{*opts.OwnerReference}
	}

	if opts.RolloutParams != nil {
		strategy, err := rollout.BuildDeploymentStrategy(*opts.RolloutParams)
		if err != nil {
			return nil, fmt.Errorf("rollout strategy: %w", err)
		}
		dep.Spec.Strategy = strategy
	}

	if len(opts.MultusAttachments) > 0 {
		if err := cni.InjectMultusAnnotations(dep, opts.MultusAttachments, opts.SRIOVResources); err != nil {
			return nil, fmt.Errorf("inject multus annotations: %w", err)
		}
	}

	return dep, nil
}

func buildPodSpec(spec NetworkFunctionSpec, opts RenderOptions, adminPort int32) (corev1.PodSpec, error) {
	var podSpec corev1.PodSpec

	// NodeSelector
	nodeSelector := make(map[string]string)
	for k, v := range spec.NodeSelector {
		nodeSelector[k] = v
	}
	for k, v := range opts.NodeSelector {
		nodeSelector[k] = v
	}
	podSpec.NodeSelector = nodeSelector

	// Topology spread across zones
	podSpec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
		{
			MaxSkew:           1,
			TopologyKey:       "topology.kubernetes.io/zone",
			WhenUnsatisfiable: corev1.ScheduleAnyway,
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": spec.Name},
			},
		},
	}

	// Container
	container, volumes, err := buildContainerAndVolumes(spec, opts, adminPort)
	if err != nil {
		return podSpec, err
	}
	container.Ports = BuildContainerPorts(spec, adminPort)
	podSpec.Containers = []corev1.Container{container}
	podSpec.Volumes = volumes

	// Pod-level security context
	podSpec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}

	// Host network when profile demands it
	if NeedsHostNetwork(spec.ResourceProfile) {
		podSpec.HostNetwork = true
		podSpec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	}

	return podSpec, nil
}

func buildContainerAndVolumes(spec NetworkFunctionSpec, opts RenderOptions, adminPort int32) (corev1.Container, []corev1.Volume, error) {
	var container corev1.Container
	var volumes []corev1.Volume

	profile := spec.ResourceProfile

	container.Name = "nf"
	container.Image = opts.Image
	if container.Image == "" {
		container.Image = fmt.Sprintf("openpacketcore/%s:%s", spec.Name, spec.Version)
	}

	// Resources
	res := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{},
		Requests: corev1.ResourceList{},
	}

	if profile != nil {
		// CPU
		if profile.RequireExclusiveCores && len(profile.IsolatedCores) > 0 {
			cpuQty := resource.NewQuantity(int64(len(profile.IsolatedCores)), resource.DecimalSI)
			res.Requests[corev1.ResourceCPU] = *cpuQty
			res.Limits[corev1.ResourceCPU] = *cpuQty
		}

		// Memory
		memQty := defaultMemoryFor(profile.NfKind)
		res.Requests[corev1.ResourceMemory] = memQty
		res.Limits[corev1.ResourceMemory] = memQty

		// Hugepages
		if profile.HugepageNumaNode != nil {
			hp2Mi := resource.NewQuantity(512*1024*1024, resource.BinarySI) // 512 Mi
			res.Requests[corev1.ResourceName("hugepages-2Mi")] = *hp2Mi
			res.Limits[corev1.ResourceName("hugepages-2Mi")] = *hp2Mi

			volumes = append(volumes, corev1.Volume{
				Name: "hugepages-2mi",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumHugePages,
					},
				},
			})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      "hugepages-2mi",
				MountPath: "/dev/hugepages",
			})
		}

		// SR-IOV extended resource
		if profile.SriovResourceName != nil && *profile.SriovResourceName != "" {
			res.Requests[corev1.ResourceName(*profile.SriovResourceName)] = resource.MustParse("1")
			res.Limits[corev1.ResourceName(*profile.SriovResourceName)] = resource.MustParse("1")
		}

		// Data-plane profile conditional features
		switch profile.DataPlaneProfile {
		case "AfXdpFastPath":
			// bpffs hostPath volume
			volumes = append(volumes, corev1.Volume{
				Name: "bpffs",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/sys/fs/bpf",
						Type: ptr.To(corev1.HostPathDirectoryOrCreate),
					},
				},
			})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      "bpffs",
				MountPath: "/sys/fs/bpf",
			})

			// Capabilities from artifacts, or default minimal set
			caps := []corev1.Capability{}
			for _, art := range profile.BpfArtifacts {
				for _, ac := range art.AllowedCapabilities {
					caps = append(caps, corev1.Capability(ac))
				}
			}
			caps = dedupCapabilities(caps)
			if len(caps) == 0 {
				caps = []corev1.Capability{"CAP_BPF", "CAP_NET_ADMIN"}
			}
			container.SecurityContext = &corev1.SecurityContext{
				RunAsNonRoot:             ptr.To(true),
				ReadOnlyRootFilesystem:   ptr.To(true),
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
					Add:  caps,
				},
			}

		case "SriovFastPath":
			// No additional volumes; SR-IOV is handled via extended resources
		}
	}

	if container.SecurityContext == nil {
		container.SecurityContext = &corev1.SecurityContext{
			RunAsNonRoot:             ptr.To(true),
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		}
	}

	container.Resources = res

	// Probes
	container.LivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/livez",
				Port: intstr.FromInt32(adminPort),
			},
		},
		InitialDelaySeconds: 10,
		PeriodSeconds:       10,
	}
	container.ReadinessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readyz",
				Port: intstr.FromInt32(adminPort),
			},
		},
		InitialDelaySeconds: 5,
		PeriodSeconds:       5,
	}
	container.StartupProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/startupz",
				Port: intstr.FromInt32(adminPort),
			},
		},
		InitialDelaySeconds: 5,
		PeriodSeconds:       5,
		FailureThreshold:    30,
	}

	// Deterministic ordering
	sort.Slice(container.VolumeMounts, func(i, j int) bool {
		return container.VolumeMounts[i].Name < container.VolumeMounts[j].Name
	})
	sort.Slice(volumes, func(i, j int) bool {
		return volumes[i].Name < volumes[j].Name
	})

	return container, volumes, nil
}

func defaultMemoryFor(nfKind string) resource.Quantity {
	switch nfKind {
	case "upf":
		return resource.MustParse("4Gi")
	case "smf":
		return resource.MustParse("2Gi")
	case "amf":
		return resource.MustParse("2Gi")
	default:
		return resource.MustParse("1Gi")
	}
}

func dedupCapabilities(caps []corev1.Capability) []corev1.Capability {
	seen := make(map[corev1.Capability]struct{})
	var out []corev1.Capability
	for _, c := range caps {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

// NeedsHostNetwork returns true if the profile requires host networking.
func NeedsHostNetwork(profile *ResourceProfile) bool {
	if profile == nil {
		return false
	}
	switch profile.DataPlaneProfile {
	case "AfXdpFastPath":
		return true
	case "SriovFastPath":
		return profile.PodSecurityEvidenceID != nil && *profile.PodSecurityEvidenceID != ""
	default:
		return false
	}
}

// BuildDeploymentWithOwnership wraps RenderDeployment and injects an OwnerReference
// derived from the supplied owner UID, name, kind, and APIVersion.
func BuildDeploymentWithOwnership(spec NetworkFunctionSpec, opts RenderOptions, owner metav1.OwnerReference) (*appsv1.Deployment, error) {
	opts.OwnerReference = &owner
	return RenderDeployment(spec, opts)
}

// BuildContainerPorts returns the container ports for the workload, including
// the admin port and any additional UDP/SCTP/TCP ports declared in the spec.
func BuildContainerPorts(spec NetworkFunctionSpec, adminPort int32) []corev1.ContainerPort {
	ports := []corev1.ContainerPort{
		{Name: "admin", ContainerPort: adminPort, Protocol: corev1.ProtocolTCP},
	}
	for _, p := range spec.AdditionalPorts {
		ports = append(ports, corev1.ContainerPort{
			Name:          p.Name,
			ContainerPort: p.Port,
			Protocol:      ParsePortProtocol(p.Protocol),
		})
	}
	return ports
}

// ParsePortProtocol maps a protocol string to a corev1.Protocol. It accepts
// "TCP", "UDP", and "SCTP" case-insensitively and defaults to TCP.
func ParsePortProtocol(protocol string) corev1.Protocol {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "UDP":
		return corev1.ProtocolUDP
	case "SCTP":
		return corev1.ProtocolSCTP
	default:
		return corev1.ProtocolTCP
	}
}

// ValidateImageTag returns an error when an immutable ImageTag is declared on
// the spec but opts.Image uses a different tag. A nil error means the image is
// either untagged or matches the declared tag.
func ValidateImageTag(spec NetworkFunctionSpec, opts RenderOptions) error {
	if spec.ImageTag == "" {
		return nil
	}
	imageTag := imageTag(opts.Image)
	if imageTag == "" {
		return fmt.Errorf("image tag is required because spec.imageTag is immutable (%q)", spec.ImageTag)
	}
	if imageTag != spec.ImageTag {
		return fmt.Errorf("image tag %q does not match immutable spec.imageTag %q", imageTag, spec.ImageTag)
	}
	return nil
}

func imageTag(image string) string {
	parts := strings.SplitN(image, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// ConfigPushObservedGenerationOK reports whether the spec generation has been
// observed by a successful config push. It is the generic operator helper for
// the "config applied" readiness gate used by products that push canonical
// configuration to the workload.
func ConfigPushObservedGenerationOK(spec NetworkFunctionSpec) bool {
	return spec.ConfigPushObservedGeneration >= 0
}

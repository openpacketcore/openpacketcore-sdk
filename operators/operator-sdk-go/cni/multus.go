package cni

import (
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// MultusNetworkAnnotationKey is the canonical pod annotation used by Multus to
// declare additional network attachments.
const MultusNetworkAnnotationKey = "k8s.v1.cni.cncf.io/networks"

// MultusAnnotation models one attachment entry in the Multus networks
// annotation. It is the public serialization format defined by the Multus CNI.
type MultusAnnotation struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// Attachment describes a single Multus attachment request in product-neutral
// terms. Products translate their own CRD types into this struct.
type Attachment struct {
	Name          string
	NetworkName   string
	Namespace     string
	InterfaceName string
}

// InjectMultusAnnotations writes the Multus networks annotation into the pod
// template and aggregates SR-IOV resource requests when the attachment list is
// non-empty. It is a no-op when attachments is empty and removes any stale
// annotation in that case.
//
// SR-IOV resource requests are merged into the first container only
// (deployment.Spec.Template.Spec.Containers[0]). Sidecars or additional
// workload containers must request SR-IOV resources separately.
func InjectMultusAnnotations(deployment *appsv1.Deployment, attachments []Attachment, sriovResources map[corev1.ResourceName]int64) error {
	if deployment == nil {
		return fmt.Errorf("deployment is nil")
	}
	if len(deployment.Spec.Template.Spec.Containers) == 0 {
		return nil
	}

	container := &deployment.Spec.Template.Spec.Containers[0]

	if len(attachments) == 0 {
		if deployment.Spec.Template.Annotations != nil {
			delete(deployment.Spec.Template.Annotations, MultusNetworkAnnotationKey)
		}
		return nil
	}

	annotations := make([]MultusAnnotation, 0, len(attachments))
	for _, at := range attachments {
		ns, name := resolveAttachmentNamespacedName(deployment.Namespace, at)
		annotations = append(annotations, MultusAnnotation{
			Name:      name,
			Namespace: ns,
			Interface: strings.TrimSpace(at.InterfaceName),
		})
	}

	payload, err := json.Marshal(annotations)
	if err != nil {
		return fmt.Errorf("marshal multus annotations: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[MultusNetworkAnnotationKey] = string(payload)

	if len(sriovResources) > 0 {
		mergeSRIOVResources(&container.Resources, sriovResources)
	}

	return nil
}

// BuildAttachments converts product-specific Multus attachment structs into the
// generic Attachment slice expected by InjectMultusAnnotations. The supplied
// resolve function is responsible for namespace defaulting and interface naming
// conventions.
func BuildAttachments[T any](inputs []T, resolve func(T) Attachment) []Attachment {
	out := make([]Attachment, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, resolve(in))
	}
	return out
}

// ResolveAttachmentNamespacedName parses a Multus network name that may be
// qualified as "namespace/name" and returns the namespace and name. When no
// namespace is present, defaultNamespace is returned.
func ResolveAttachmentNamespacedName(defaultNamespace, attachment string) (namespace, name string) {
	attachment = strings.TrimSpace(attachment)
	parts := strings.SplitN(attachment, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return defaultNamespace, attachment
}

func resolveAttachmentNamespacedName(defaultNamespace string, at Attachment) (namespace, name string) {
	if strings.TrimSpace(at.Namespace) != "" {
		return strings.TrimSpace(at.Namespace), strings.TrimSpace(at.NetworkName)
	}
	return ResolveAttachmentNamespacedName(defaultNamespace, at.NetworkName)
}

// MergeSRIOVResources adds SR-IOV extended resource requests/limits to the
// container's resource requirements. It is exported so that products with
// pre-resolved resource counts can use the same merge logic.
func MergeSRIOVResources(resources *corev1.ResourceRequirements, aggregated map[corev1.ResourceName]int64) {
	mergeSRIOVResources(resources, aggregated)
}

func mergeSRIOVResources(resources *corev1.ResourceRequirements, aggregated map[corev1.ResourceName]int64) {
	if resources.Requests == nil {
		resources.Requests = corev1.ResourceList{}
	}
	if resources.Limits == nil {
		resources.Limits = corev1.ResourceList{}
	}
	for resourceName, count := range aggregated {
		qty := *resource.NewQuantity(count, resource.DecimalSI)
		resources.Requests[resourceName] = qty
		resources.Limits[resourceName] = qty
	}
}

// BuildSRIOVResourceMap aggregates SR-IOV resource names by count for the given
// attachments. The extract function returns the corev1.ResourceName for an
// attachment, or a zero value if the attachment does not request an SR-IOV
// resource.
func BuildSRIOVResourceMap[T any](attachments []T, extract func(T) corev1.ResourceName) map[corev1.ResourceName]int64 {
	aggregated := make(map[corev1.ResourceName]int64, len(attachments))
	for _, at := range attachments {
		name := extract(at)
		if name != "" {
			aggregated[name]++
		}
	}
	return aggregated
}

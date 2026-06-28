package cni

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInjectMultusAnnotations(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nf",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "nf"}},
				},
			},
		},
	}

	attachments := []Attachment{
		{Name: "sriov0", NetworkName: "nad-a", InterfaceName: "net0"},
		{Name: "mgmt0", NetworkName: "other-ns/nad-b", InterfaceName: "net1"},
	}

	if err := InjectMultusAnnotations(dep, attachments, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, ok := dep.Spec.Template.Annotations[MultusNetworkAnnotationKey]
	if !ok {
		t.Fatal("expected multus annotation to be set")
	}

	var got []MultusAnnotation
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal annotation: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 annotations, got %d", len(got))
	}
	if got[0].Name != "nad-a" || got[0].Namespace != "default" || got[0].Interface != "net0" {
		t.Errorf("unexpected first annotation: %+v", got[0])
	}
	if got[1].Name != "nad-b" || got[1].Namespace != "other-ns" || got[1].Interface != "net1" {
		t.Errorf("unexpected second annotation: %+v", got[1])
	}
}

func TestInjectMultusAnnotationsEmptyRemovesStale(t *testing.T) {
	dep := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						MultusNetworkAnnotationKey: "stale",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "nf"}},
				},
			},
		},
	}

	if err := InjectMultusAnnotations(dep, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := dep.Spec.Template.Annotations[MultusNetworkAnnotationKey]; ok {
		t.Error("expected stale multus annotation to be removed")
	}
}

func TestInjectMultusAnnotationsAggregatesSRIOV(t *testing.T) {
	dep := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "nf"}},
				},
			},
		},
	}

	resources := map[corev1.ResourceName]int64{
		"intel.com/ice_sriov": 2,
	}
	if err := InjectMultusAnnotations(dep, []Attachment{{Name: "sriov0"}}, resources); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	container := dep.Spec.Template.Spec.Containers[0]
	if got := container.Resources.Requests["intel.com/ice_sriov"]; got.Value() != 2 {
		t.Errorf("expected SR-IOV request 2, got %v", got.Value())
	}
}

func TestResolveAttachmentNamespacedName(t *testing.T) {
	ns, name := ResolveAttachmentNamespacedName("default", "other-ns/nad-a")
	if ns != "other-ns" || name != "nad-a" {
		t.Errorf("ResolveAttachmentNamespacedName() = %s/%s, want other-ns/nad-a", ns, name)
	}
	ns, name = ResolveAttachmentNamespacedName("default", "nad-a")
	if ns != "default" || name != "nad-a" {
		t.Errorf("ResolveAttachmentNamespacedName() = %s/%s, want default/nad-a", ns, name)
	}
}

func TestInjectMultusAnnotationsExplicitNamespace(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nf",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "nf"}},
				},
			},
		},
	}

	attachments := []Attachment{
		{Name: "net0", Namespace: "other-ns", NetworkName: "nad-a", InterfaceName: "net0"},
	}

	if err := InjectMultusAnnotations(dep, attachments, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw := dep.Spec.Template.Annotations[MultusNetworkAnnotationKey]
	var got []MultusAnnotation
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal annotation: %v", err)
	}
	if len(got) != 1 || got[0].Namespace != "other-ns" || got[0].Name != "nad-a" {
		t.Errorf("expected explicit namespace to be honored, got %+v", got)
	}
}

func TestInjectMultusAnnotationsTrimsInterfaceName(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nf",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "nf"}},
				},
			},
		},
	}

	attachments := []Attachment{
		{Name: "net0", NetworkName: "nad-a", InterfaceName: "  net0  "},
	}

	if err := InjectMultusAnnotations(dep, attachments, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw := dep.Spec.Template.Annotations[MultusNetworkAnnotationKey]
	var got []MultusAnnotation
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal annotation: %v", err)
	}
	if len(got) != 1 || got[0].Interface != "net0" {
		t.Errorf("expected trimmed interface name net0, got %+v", got)
	}
}

func TestBuildSRIOVResourceMap(t *testing.T) {
	type item struct {
		resource string
	}
	items := []item{
		{"intel.com/ice_sriov"},
		{"intel.com/ice_sriov"},
		{""},
	}
	got := BuildSRIOVResourceMap(items, func(i item) corev1.ResourceName {
		return corev1.ResourceName(i.resource)
	})
	if got["intel.com/ice_sriov"] != 2 {
		t.Errorf("expected count 2, got %d", got["intel.com/ice_sriov"])
	}
}

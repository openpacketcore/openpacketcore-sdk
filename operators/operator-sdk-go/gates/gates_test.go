package gates

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestDeploymentIsReady(t *testing.T) {
	tests := []struct {
		name            string
		desiredReplicas int32
		deployment      *appsv1.Deployment
		want            bool
	}{
		{
			name:            "nil deployment is not ready",
			desiredReplicas: 1,
			deployment:      nil,
			want:            false,
		},
		{
			name:            "zero desired replicas is not ready",
			desiredReplicas: 0,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 1},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					UpdatedReplicas:    1,
					ReadyReplicas:      1,
					AvailableReplicas:  1,
				},
			},
			want: false,
		},
		{
			name:            "negative desired replicas is not ready",
			desiredReplicas: -1,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 1},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					UpdatedReplicas:    1,
					ReadyReplicas:      1,
					AvailableReplicas:  1,
				},
			},
			want: false,
		},
		{
			name:            "stale observed generation is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 2,
					UpdatedReplicas:    2,
					ReadyReplicas:      2,
					AvailableReplicas:  2,
				},
			},
			want: false,
		},
		{
			name:            "insufficient updated replicas is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 3,
					UpdatedReplicas:    1,
					ReadyReplicas:      2,
					AvailableReplicas:  2,
				},
			},
			want: false,
		},
		{
			name:            "insufficient ready replicas is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 3,
					UpdatedReplicas:    2,
					ReadyReplicas:      1,
					AvailableReplicas:  2,
				},
			},
			want: false,
		},
		{
			name:            "insufficient available replicas is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 3,
					UpdatedReplicas:    2,
					ReadyReplicas:      2,
					AvailableReplicas:  1,
				},
			},
			want: false,
		},
		{
			name:            "all gates satisfied is ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  3,
					UpdatedReplicas:     2,
					ReadyReplicas:       2,
					AvailableReplicas:   2,
					Replicas:            2,
					UnavailableReplicas: 0,
				},
			},
			want: true,
		},
		{
			name:            "extra old replica during rollout is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  3,
					UpdatedReplicas:     2,
					ReadyReplicas:       2,
					AvailableReplicas:   2,
					Replicas:            3,
					UnavailableReplicas: 0,
				},
			},
			want: false,
		},
		{
			name:            "surge pod raises total above desired is not ready",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  3,
					UpdatedReplicas:     2,
					ReadyReplicas:       2,
					AvailableReplicas:   2,
					Replicas:            3,
					UnavailableReplicas: 0,
				},
			},
			want: false,
		},
		{
			name:            "unavailable replicas block readiness",
			desiredReplicas: 2,
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  3,
					UpdatedReplicas:     2,
					ReadyReplicas:       2,
					AvailableReplicas:   2,
					Replicas:            2,
					UnavailableReplicas: 1,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeploymentIsReady(tt.deployment, tt.desiredReplicas)
			if got != tt.want {
				t.Errorf("DeploymentIsReady() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestPodIsReady(t *testing.T) {
	tests := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{
			name: "running and ready",
			pod: corev1.Pod{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIP: "10.0.0.1",
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionTrue},
					},
				},
			},
			want: true,
		},
		{
			name: "running but not ready",
			pod: corev1.Pod{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIP: "10.0.0.1",
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionFalse},
					},
				},
			},
			want: false,
		},
		{
			name: "pending phase",
			pod: corev1.Pod{
				Status: corev1.PodStatus{
					Phase: corev1.PodPending,
					PodIP: "10.0.0.1",
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionTrue},
					},
				},
			},
			want: false,
		},
		{
			name: "running but no IP",
			pod: corev1.Pod{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionTrue},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PodIsReady(tt.pod)
			if got != tt.want {
				t.Errorf("PodIsReady() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestCurrentDeploymentReplicaSetUIDs(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "nf",
			Namespace:  "default",
			UID:        types.UID("deploy-uid"),
			Generation: 1,
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": "8",
			},
		},
	}
	oldRS := replicaSetForDeployment(deployment, "nf-old", types.UID("old-rs-uid"), "7")
	currentRS := replicaSetForDeployment(deployment, "nf-current", types.UID("current-rs-uid"), "8")

	got := CurrentDeploymentReplicaSetUIDs(deployment, []appsv1.ReplicaSet{oldRS, currentRS})
	if _, ok := got[types.UID("current-rs-uid")]; !ok {
		t.Errorf("expected current ReplicaSet UID to be selected, got %#v", got)
	}
	if _, ok := got[types.UID("old-rs-uid")]; ok {
		t.Errorf("did not expect stale ReplicaSet UID from older Deployment revision, got %#v", got)
	}
}

func TestHasCurrentEndpointOwnerReference(t *testing.T) {
	currentUIDs := map[types.UID]struct{}{
		types.UID("current-rs-uid"): {},
	}
	tests := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{
			name: "current replicaset owner",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ReplicaSet", Name: "nf-rs", UID: types.UID("current-rs-uid"), Controller: ptr(true)},
					},
				},
			},
			want: true,
		},
		{
			name: "stale replicaset owner",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "ReplicaSet", Name: "nf-old-rs", UID: types.UID("old-rs-uid"), Controller: ptr(true)},
					},
				},
			},
			want: false,
		},
		{
			name: "statefulset owner rejected",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet", Name: "nf", UID: types.UID("sts-uid"), Controller: ptr(true)},
					},
				},
			},
			want: false,
		},
		{
			name: "direct cr owner rejected",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{APIVersion: "core.example.com/v1", Kind: "NetworkFunction", Name: "nf", UID: types.UID("nf-uid"), Controller: ptr(true)},
					},
				},
			},
			want: false,
		},
		{
			name: "no owner",
			pod:  corev1.Pod{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasCurrentEndpointOwnerReference(currentUIDs, tt.pod)
			if got != tt.want {
				t.Errorf("HasCurrentEndpointOwnerReference() = %t, want %t", got, tt.want)
			}
		})
	}
}

func replicaSetForDeployment(deployment *appsv1.Deployment, name string, uid types.UID, revision string) appsv1.ReplicaSet {
	return appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: deployment.Namespace,
			UID:       uid,
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": revision,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       "Deployment",
					Name:       deployment.Name,
					UID:        deployment.UID,
					Controller: ptr(true),
				},
			},
		},
	}
}

func ptr[T any](v T) *T { return &v }

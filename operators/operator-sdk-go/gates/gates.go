package gates

import (
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// DeploymentIsReady reports whether the supplied Deployment has fully rolled
// out the desired number of replicas and the current revision is converged.
// Convergence requires the controller to have observed the current spec and
// for updated, ready, available, and total replica counts to exactly equal the
// desired count with no unavailable replicas. This prevents the helper from
// reporting readiness during a rolling update while an old ReplicaSet or surge
// pod is still present.
// A nil deployment or a non-positive desired replica count is never ready,
// because it cannot serve traffic.
func DeploymentIsReady(deployment *appsv1.Deployment, desiredReplicas int32) bool {
	if deployment == nil || desiredReplicas <= 0 {
		return false
	}
	observedCurrent := deployment.Status.ObservedGeneration >= deployment.Generation
	updatedExact := deployment.Status.UpdatedReplicas == desiredReplicas
	readyExact := deployment.Status.ReadyReplicas == desiredReplicas
	availableExact := deployment.Status.AvailableReplicas == desiredReplicas
	totalExact := deployment.Status.Replicas == desiredReplicas
	noUnavailable := deployment.Status.UnavailableReplicas == 0
	return observedCurrent && updatedExact && readyExact && availableExact && totalExact && noUnavailable
}

// PodIsReady reports whether the pod is Running, has a pod IP, and its PodReady
// condition is True. It is the standard endpoint eligibility check for
// serving traffic.
func PodIsReady(pod corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
		return false
	}
	return podConditionTrue(pod.Status.Conditions, corev1.PodReady)
}

// PodHasNetworkIdentity reports whether the pod is Running and has a pod IP.
// It is useful for bootstrap endpoints (e.g. gNMI config push) that need a
// network identity before the readiness probe flips true.
func PodHasNetworkIdentity(pod corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" && pod.UID != ""
}

// CurrentDeploymentReplicaSetUIDs returns the UIDs of ReplicaSets that belong
// to the current Deployment revision. If the Deployment carries the standard
// "deployment.kubernetes.io/revision" annotation, only ReplicaSets with the
// same revision are considered current. Otherwise the highest revision among
// owned ReplicaSets is used as a best-effort fallback.
func CurrentDeploymentReplicaSetUIDs(deployment *appsv1.Deployment, replicaSets []appsv1.ReplicaSet) map[types.UID]struct{} {
	current := make(map[types.UID]struct{}, len(replicaSets))
	if deployment == nil {
		return current
	}
	currentRevision := deploymentRevision(deployment)
	if currentRevision == 0 {
		currentRevision = highestOwnedReplicaSetRevision(deployment, replicaSets)
	}
	for i := range replicaSets {
		rs := &replicaSets[i]
		if !isReplicaSetOwnedByDeployment(rs, deployment) || rs.UID == "" {
			continue
		}
		if currentRevision > 0 && replicaSetRevision(rs) != currentRevision {
			continue
		}
		current[rs.UID] = struct{}{}
	}
	return current
}

// HasCurrentEndpointOwnerReference verifies that the pod has a controller owner
// reference matching the current Deployment-owned ReplicaSet lineage. This
// prevents stale or manually created pods from being projected as serving
// endpoints. StatefulSet-owned and direct CR-owned pods are rejected because
// their lineage is not represented in the supplied ReplicaSet set.
func HasCurrentEndpointOwnerReference(currentReplicaSetUIDs map[types.UID]struct{}, pod corev1.Pod) bool {
	controllerRef := metav1.GetControllerOfNoCopy(&pod)
	if controllerRef == nil || controllerRef.UID == "" {
		return false
	}
	switch controllerRef.Kind {
	case "ReplicaSet":
		if controllerRef.APIVersion != appsv1.SchemeGroupVersion.String() {
			return false
		}
		_, ok := currentReplicaSetUIDs[controllerRef.UID]
		return ok
	case "StatefulSet", "NetworkFunction":
		// Reject until current lineage is verified the same way as ReplicaSets.
		return false
	default:
		return false
	}
}

func deploymentRevision(deployment *appsv1.Deployment) int64 {
	if deployment == nil {
		return 0
	}
	return parseDeploymentRevision(deployment.Annotations)
}

func replicaSetRevision(replicaSet *appsv1.ReplicaSet) int64 {
	if replicaSet == nil {
		return 0
	}
	return parseDeploymentRevision(replicaSet.Annotations)
}

func parseDeploymentRevision(annotations map[string]string) int64 {
	raw := strings.TrimSpace(annotations["deployment.kubernetes.io/revision"])
	if raw == "" {
		return 0
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 0 {
		return 0
	}
	return revision
}

func highestOwnedReplicaSetRevision(deployment *appsv1.Deployment, replicaSets []appsv1.ReplicaSet) int64 {
	var highest int64
	for i := range replicaSets {
		rs := &replicaSets[i]
		if !isReplicaSetOwnedByDeployment(rs, deployment) {
			continue
		}
		if rev := replicaSetRevision(rs); rev > highest {
			highest = rev
		}
	}
	return highest
}

func isReplicaSetOwnedByDeployment(replicaSet *appsv1.ReplicaSet, deployment *appsv1.Deployment) bool {
	if replicaSet == nil || deployment == nil {
		return false
	}
	controllerRef := metav1.GetControllerOfNoCopy(replicaSet)
	if controllerRef == nil || controllerRef.UID == "" {
		return false
	}
	if controllerRef.Kind != "Deployment" || controllerRef.APIVersion != appsv1.SchemeGroupVersion.String() {
		return false
	}
	if controllerRef.Name != deployment.Name {
		return false
	}
	// controller-runtime's fake client does not default metadata.uid on create.
	// In tests where deployment UID is empty, fall back to the stable name check.
	if deployment.UID == "" {
		return true
	}
	return controllerRef.UID == deployment.UID
}

func podConditionTrue(conditions []corev1.PodCondition, conditionType corev1.PodConditionType) bool {
	for _, c := range conditions {
		if c.Type == conditionType {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

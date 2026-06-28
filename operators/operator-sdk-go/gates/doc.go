// Package gates provides product-neutral helpers for evaluating Kubernetes
// workload readiness and endpoint lineage as part of the OpenPacketCore
// operator condition model.
//
// These helpers operate on standard Kubernetes API objects (Deployments,
// ReplicaSets, Pods) so that product operators can compute RFC 009 conditions
// such as DeploymentReady and EndpointsDiscovered without importing product
// specific controller code.
package gates

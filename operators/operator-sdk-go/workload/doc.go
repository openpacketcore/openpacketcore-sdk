// Package workload synthesizes Kubernetes Deployment manifests from
// SdkManagedNetworkFunction custom resources.
//
// It maps resource profiles (CPU, memory, hugepages, SR-IOV, BPF) to
// container specs, volumes, probes, and topology constraints with
// deterministic, byte-stable output.
package workload

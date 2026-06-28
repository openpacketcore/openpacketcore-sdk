// Package cni provides product-neutral helpers for Kubernetes CNI
// integrations used by OpenPacketCore operators.
//
// The initial surface covers Multus network attachment annotations and
// SR-IOV resource aggregation. Products supply their own network attachment
// definitions and validation; this package only builds the pod-level
// Kubernetes objects.
package cni

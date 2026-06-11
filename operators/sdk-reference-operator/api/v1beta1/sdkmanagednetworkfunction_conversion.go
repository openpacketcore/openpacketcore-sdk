package v1beta1

import (
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

// Hub marks this type as a conversion hub.
func (src *SdkManagedNetworkFunction) Hub() {}

var _ conversion.Hub = &SdkManagedNetworkFunction{}

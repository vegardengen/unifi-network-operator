/*
Copyright 2025 Vegard Engen.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FirewallGroupSpec defines the desired state of FirewallGroup.

type FirewallGroupSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of FirewallGroup. Edit firewallgroup_types.go to remove/update
	// Description is a human-readable explanation for the object
	Name string `json:"name,omitempty"`

	MatchServicesInAllNamespaces bool `json:"matchServicesInAllNamespaces,omitempty"`
	// ManualAddresses is a list of manual IPs or CIDRs (IPv4 or IPv6)
	// +optional
	ManualAddresses []string `json:"manualAddresses,omitempty"`
	ManualPorts     []string `json:"manualPorts,omitempty"`

	AutoCreatedFrom ServiceSpec `json:"auto_created_from,omitempty"`

	// AutoIncludeSelector defines which services to extract addresses from
	// +optional
	AutoIncludeSelector *metav1.LabelSelector `json:"autoIncludeSelector,omitempty"`
}

// FirewallGroupStatus defines the observed state of FirewallGroup.
type FirewallGroupStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	ResolvedAddresses []string `json:"resolvedAddresses,omitempty"`

	// SyncedWithUnifi indicates whether the addresses are successfully pushed
	// +optional
	SyncedWithUnifi bool `json:"syncedWithUnifi,omitempty"`

	// LastSyncTime is the last time the object was synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// FirewallGroup is the Schema for the firewallgroups API.
type FirewallGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallGroupSpec   `json:"spec,omitempty"`
	Status FirewallGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FirewallGroupList contains a list of FirewallGroup.
type FirewallGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FirewallGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FirewallGroup{}, &FirewallGroupList{})
}

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

// NetworkconfigurationSpec defines the desired state of Networkconfiguration.
type NetworkconfigurationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of Networkconfiguration. Edit networkconfiguration_types.go to remove/update
	Enabled                   bool   `json:"enabled,omitempty"`
	FirewallZoneID            string `json:"firewall_zone_id,omitempty"`
	GatewayType               string `json:"gateway_type,omitempty"`
	IPSubnet                  string `json:"ip_subnet,omitempty"`
	Ipv6InterfaceType         string `json:"ipv6_interface_type,omitempty"`
	Ipv6PdAutoPrefixidEnabled bool   `json:"ipv6_pd_auto_prefixid_enabled,omitempty"`
	Ipv6RaEnabled             bool   `json:"ipv6_ra_enabled,omitempty"`
	Ipv6SettingPreference     string `json:"ipv6_setting_preference,omitempty"`
	Ipv6Subnet                string `json:"ipv6_subnet,omitempty"`
	Name                      string `json:"name"`
	Networkname               string `json:"network_name"`
	NetworkID                 string `json:"network_id,omitempty"`
	Networkgroup              string `json:"networkgroup,omitempty"`
	Purpose                   string `json:"purpose,omitempty"`
	SettingPreference         string `json:"setting_preference,omitempty"`
	Vlan                      int64  `json:"vlan,omitempty"`
	VlanEnabled               bool   `json:"vlan_enabled,omitempty"`
}

// NetworkconfigurationStatus defines the observed state of Networkconfiguration.
type NetworkconfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Ipv6SubnetStatus string `json:"ipv6_subnet_status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Networkconfiguration is the Schema for the networkconfigurations API.
type Networkconfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkconfigurationSpec   `json:"spec,omitempty"`
	Status NetworkconfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkconfigurationList contains a list of Networkconfiguration.
type NetworkconfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Networkconfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Networkconfiguration{}, &NetworkconfigurationList{})
}

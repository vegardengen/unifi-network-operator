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

// FirewallRuleSpec defines the desired state of FirewallRule.
// type ServiceSpec struct {
// 	Namespace string `json:"namespace,omitempty"`
// 	Name      string `json:"name,omitempty"`
// }

// type FirewallSource struct {
//	Zones    []string `json:"from_zones,omitempty"`
//	Networks []string `json:"from_networks,omitempty"`
//}

//type FirewallDestination struct {
//	FirewallGroups []string      `json:"firewall_group,omitempty"`
//	Services       []ServiceSpec `json:"service,omitempty"`
//}

type FirewallRuleSpec struct {
	Name                               string              `json:"name"`
	Source                             FirewallSource      `json:"source"`
	Destination                        FirewallDestination `json:"destination"`
	MatchFirewallGroupsInAllNamespaces bool                `json:"match_firewall_groups_in_all_namespaces,omitempty"`
	MatchServicesInAllNamespaces       bool                `json:"match_services_in_all_namespaces,omitempty"`
}

// FirewallRuleStatus defines the observed state of FirewallRule.
type FirewallRuleStatus struct {
	ResourcesManaged *FirewallRuleResourcesManaged `json:"resources_managed,omitempty"`
}

type FirewallRuleResourcesManaged struct {
	UnifiFirewallRules []UnifiFirewallRuleEntry `json:"firewall_rules_managed,omitempty"`
	FirewallGroups     []FirewallGroupEntry     `json:"firewall_groups_managed,omitempty"`
}

type UnifiFirewallRuleEntry struct {
	From      string `json:"from"`
	To        string `json:"to"`
	TcpIpv4ID string `json:"tcpipv4_id"`
	UdpIpv4ID string `json:"udpipv4_id"`
	TcpIpv6ID string `json:"tcpipv6_id"`
	UdpIpv6ID string `json:"udpipv6_id"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// FirewallRule is the Schema for the firewallrules API.
type FirewallRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallRuleSpec   `json:"spec,omitempty"`
	Status FirewallRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FirewallRuleList contains a list of FirewallRule.
type FirewallRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FirewallRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FirewallRule{}, &FirewallRuleList{})
}

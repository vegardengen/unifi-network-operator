package v1beta1

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FirewallRuleSpec defines the desired state of FirewallRule.
type ServiceSpec struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

type FirewallSource struct {
	Zones    []string `json:"from_zones,omitempty"`
	Networks []string `json:"from_networks,omitempty"`
}

type FirewallDestination struct {
	FirewallGroups []string      `json:"firewall_group,omitempty"`
	Services       []ServiceSpec `json:"service,omitempty"`
}

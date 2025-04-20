package v1beta1

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type NamedUnifiResource struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

type ServiceEntry struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

type FirewallGroupEntry struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}
type FirewallZoneEntry struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}
type FirewallPolicyEntry struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}
type NetworkEntry struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}
type FirewallSource struct {
	FirewallZones []FirewallZoneEntry `json:"from_zones,omitempty"`
	Networks      []NetworkEntry      `json:"from_networks,omitempty"`
}

type FirewallDestination struct {
	FirewallGroups []FirewallGroupEntry `json:"firewall_groups,omitempty"`
	Services       []ServiceEntry       `json:"services,omitempty"`
}

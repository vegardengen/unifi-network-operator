//go:generate go run generate_spec.go

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"reflect"
	"strings"
	"text/template"

	"github.com/ubiquiti-community/go-unifi/unifi"
)

// Map Go types to Kubernetes types
var goTypeToK8s = map[string]string{
	"string":  "string",
	"int":     "int",
	"int32":   "int",
	"int64":   "int",
	"float32": "float64",
	"float64": "float64",
	"bool":    "bool",
}

// Extract fields from unifi.Network and format them as Go struct fields
func extractFields(t reflect.Type) string {
	var fields []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldName := field.Name
		fieldType := field.Type.String()

		// Convert Go types to Kubernetes CRD types
		k8sType, exists := goTypeToK8s[fieldType]
		if !exists {
			k8sType = "string" // Default fallback type
		}

		// Add kubebuilder validation tag
		jsonTag := strings.ToLower(fieldName)
		fields = append(fields, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldName, k8sType, jsonTag))
	}
	return strings.Join(fields, "\n")
}

// Define the `UnifiNetworkSpec` struct template
const specTemplate = `package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UnifiNetworkSpec defines the desired state of UnifiNetwork
type UnifiNetworkSpec struct {
{{.Fields}}
}

// UnifiNetworkStatus defines the observed state of UnifiNetwork
type UnifiNetworkStatus struct {
	LastUpdated metav1.Time \`\`json:"lastUpdated,omitempty"\`\`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type UnifiNetwork struct {
	metav1.TypeMeta   \`\`json:",inline"\`\`
	metav1.ObjectMeta \`\`json:"metadata,omitempty"\`\`

	Spec   UnifiNetworkSpec   \`\`json:"spec,omitempty"\`\`
	Status UnifiNetworkStatus \`\`json:"status,omitempty"\`\`
}

// +kubebuilder:object:root=true
type UnifiNetworkList struct {
	metav1.TypeMeta \`\`json:",inline"\`\`
	metav1.ListMeta \`\`json:"metadata,omitempty"\`\`
	Items           []UnifiNetwork \`\`json:"items"\`\`
}
`

func main() {
	// Extract fields from `unifi.Network`
	fields := extractFields(reflect.TypeOf(unifi.Network{}))

	// Generate Go code from template
	tmpl, err := template.New("spec").Parse(specTemplate)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		return
	}

	var output bytes.Buffer
	err = tmpl.Execute(&output, struct {
		Fields string
	}{Fields: fields})

	if err != nil {
		fmt.Println("Error executing template:", err)
		return
	}

	// Format Go code
	formatted, err := format.Source(output.Bytes())
	if err != nil {
		fmt.Println("Error formatting code:", err)
		return
	}

	// Write to `api/v1/unifinetwork_types.go`
	err = os.WriteFile("api/v1/unifinetwork_types.go", formatted, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Println("✅ UnifiNetworkSpec generated successfully in api/v1/unifinetwork_types.go")
}

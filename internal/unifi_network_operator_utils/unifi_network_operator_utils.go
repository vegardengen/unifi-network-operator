/* https://github.com/clbx/kube-port-forward-controller */

package unifi_network_operator_utils

import (
	"regexp"
	"strings"
)

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func toKubeName(input string) string {
	// Lowercase the input
	name := strings.ToLower(input)

	// Replace any non-alphanumeric characters with dashes
	re := regexp.MustCompile(`[^a-z0-9\-\.]+`)
	name = re.ReplaceAllString(name, "-")

	// Trim leading and trailing non-alphanumerics
	name = strings.Trim(name, "-.")

	// Ensure it's not empty and doesn't exceed 253 characters
	if len(name) == 0 {
		name = "default"
	} else if len(name) > 253 {
		name = name[:253]
	}

	return name
}

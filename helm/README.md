# UniFi Network Operator - Helm Chart

This directory contains the Helm chart for deploying the UniFi Network Operator to Kubernetes.

## Quick Links

- **[Installation Guide](./INSTALL.md)** - Detailed installation instructions and examples
- **[Chart Documentation](./unifi-network-operator/README.md)** - Full configuration reference
- **[Values Reference](./unifi-network-operator/values.yaml)** - All configurable values

## Quick Start

```bash
# Install with minimal configuration
helm install unifi-network-operator ./helm/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://your-unifi-controller:8443" \
  --set unifi.password="your-password"
```

## Chart Structure

```
helm/unifi-network-operator/
├── Chart.yaml                 # Chart metadata
├── values.yaml               # Default configuration values
├── README.md                 # Detailed chart documentation
├── .helmignore              # Files to ignore when packaging
├── crds/                    # Custom Resource Definitions
│   ├── unifi.engen.priv.no_firewallgroups.yaml
│   ├── unifi.engen.priv.no_firewallpolicies.yaml
│   ├── unifi.engen.priv.no_firewallzones.yaml
│   ├── unifi.engen.priv.no_networkconfigurations.yaml
│   └── unifi.engen.priv.no_portforwards.yaml
└── templates/               # Kubernetes resource templates
    ├── NOTES.txt           # Post-installation notes
    ├── _helpers.tpl        # Template helpers
    ├── deployment.yaml     # Operator deployment
    ├── serviceaccount.yaml # Service account
    ├── clusterrole.yaml    # Cluster-level permissions
    ├── clusterrolebinding.yaml
    ├── role.yaml           # Namespace-level permissions
    ├── rolebinding.yaml
    ├── configmap.yaml      # Operator configuration
    ├── secret.yaml         # UniFi credentials
    ├── service.yaml        # Metrics service
    └── servicemonitor.yaml # Prometheus integration
```

## Features

- **Secure by Default**: Runs with restricted security context and non-root user
- **Flexible Configuration**: Extensive values for customization
- **Production Ready**: Leader election, resource limits, health checks
- **Monitoring**: Built-in Prometheus ServiceMonitor support
- **GitOps Friendly**: Works with ArgoCD, Flux, and other GitOps tools
- **Credential Management**: Support for external secrets

## Key Configuration Options

### Required Settings

- `unifi.url` - UniFi controller URL (e.g., `https://unifi.example.com:8443`)
- `unifi.password` - UniFi password (or use `unifi.existingSecret`)

### Common Optional Settings

- `unifi.site` - UniFi site ID (default: `default`)
- `unifi.username` - UniFi username (default: `admin`)
- `config.fullSyncZone` - Zone name for bidirectional sync
- `config.fullSyncNetwork` - Network name for bidirectional sync
- `metrics.serviceMonitor.enabled` - Enable Prometheus monitoring
- `resources.*` - Resource limits and requests

## Using Make Targets

The project Makefile includes helpful Helm targets:

```bash
# Lint the chart
make helm-lint

# Render templates (for debugging)
make helm-template

# Install (requires env vars)
export UNIFI_URL="https://unifi.example.com:8443"
export UNIFI_PASSWORD="your-password"
make helm-install

# Upgrade
make helm-upgrade

# Uninstall
make helm-uninstall

# Package the chart
make helm-package

# Dry run
make helm-dry-run
```

## Examples

### Development Installation

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://192.168.1.1:8443" \
  --set unifi.password="admin"
```

### Production with Existing Secret

```bash
# Create secret
kubectl create secret generic unifi-creds \
  --from-literal=UNIFI_URL="https://unifi.example.com:8443" \
  --from-literal=UNIFI_SITE="default" \
  --from-literal=UNIFI_USERNAME="operator" \
  --from-literal=UNIFI_PASSWORD="secure-password" \
  -n unifi-network-operator-system

# Install with secret reference
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --set unifi.existingSecret="unifi-creds"
```

### With Full Sync and Monitoring

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://unifi.example.com:8443" \
  --set unifi.password="password" \
  --set config.fullSyncZone="gateway" \
  --set config.fullSyncNetwork="core" \
  --set metrics.serviceMonitor.enabled=true
```

## Upgrading

To upgrade the operator:

```bash
helm upgrade unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system
```

## Uninstalling

```bash
# Remove the operator (CRDs remain)
helm uninstall unifi-network-operator -n unifi-network-operator-system

# Also remove CRDs (WARNING: deletes all custom resources)
kubectl delete crds \
  firewallgroups.unifi.engen.priv.no \
  firewallpolicies.unifi.engen.priv.no \
  firewallzones.unifi.engen.priv.no \
  networkconfigurations.unifi.engen.priv.no \
  portforwards.unifi.engen.priv.no
```

## Customization

Create a `custom-values.yaml` file:

```yaml
image:
  tag: "v1.0.0"

replicaCount: 1

unifi:
  existingSecret: "my-unifi-secret"

config:
  fullSyncZone: "gateway"
  fullSyncNetwork: "core"
  kubernetesUnifiZone: "k8s"

resources:
  limits:
    memory: 256Mi
  requests:
    memory: 128Mi

metrics:
  serviceMonitor:
    enabled: true
    additionalLabels:
      prometheus: kube-prometheus

nodeSelector:
  kubernetes.io/os: linux

tolerations:
  - key: "node-role.kubernetes.io/control-plane"
    operator: "Exists"
    effect: "NoSchedule"
```

Install with:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  -f custom-values.yaml
```

## Documentation

- **[INSTALL.md](./INSTALL.md)** - Complete installation guide with examples
- **[Chart README](./unifi-network-operator/README.md)** - Full configuration reference
- **[values.yaml](./unifi-network-operator/values.yaml)** - Commented default values

## Support

For issues and questions:
- Check the [Installation Guide](./INSTALL.md)
- Review the [Chart Documentation](./unifi-network-operator/README.md)
- Check operator logs: `kubectl logs -n unifi-network-operator-system -l app.kubernetes.io/name=unifi-network-operator`

## License

This Helm chart is provided under the same license as the UniFi Network Operator project.

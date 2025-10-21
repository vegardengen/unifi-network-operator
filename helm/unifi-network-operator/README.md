# UniFi Network Operator Helm Chart

A Kubernetes operator for managing UniFi network configurations declaratively through Kubernetes Custom Resources.

## Introduction

This Helm chart deploys the UniFi Network Operator on a Kubernetes cluster. The operator enables you to manage UniFi network infrastructure (firewall zones, groups, policies, networks, and port forwards) using Kubernetes resources.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Access to a UniFi Network Controller
- UniFi controller credentials (URL, username, password)

## Installing the Chart

To install the chart with the release name `unifi-network-operator`:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://unifi.example.com:8443" \
  --set unifi.username="admin" \
  --set unifi.password="your-password" \
  --set unifi.site="default"
```

## Uninstalling the Chart

To uninstall/delete the `unifi-network-operator` deployment:

```bash
helm uninstall unifi-network-operator -n unifi-network-operator-system
```

This command removes all the Kubernetes components associated with the chart. Note that CRDs are not deleted by default to prevent data loss.

## Configuration

The following table lists the configurable parameters of the UniFi Network Operator chart and their default values.

### General Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Operator image repository | `gitea.engen.priv.no/klauvsteinen/unifi-network-operator-controller` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag (overrides appVersion) | `latest` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full chart name | `""` |

### Service Account Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.automount` | Auto-mount service account token | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |

### Security Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root user | `true` |
| `podSecurityContext.seccompProfile.type` | Seccomp profile type | `RuntimeDefault` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.capabilities.drop` | Dropped capabilities | `["ALL"]` |

### Resource Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |

### UniFi Controller Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `unifi.url` | UniFi controller URL | `""` (required) |
| `unifi.site` | UniFi site ID | `"default"` |
| `unifi.username` | UniFi username | `"admin"` |
| `unifi.password` | UniFi password | `""` (required) |
| `unifi.existingSecret` | Use existing secret for credentials | `""` |
| `unifi.existingSecretKeys.url` | Key for URL in existing secret | `UNIFI_URL` |
| `unifi.existingSecretKeys.site` | Key for site in existing secret | `UNIFI_SITE` |
| `unifi.existingSecretKeys.username` | Key for username in existing secret | `UNIFI_USERNAME` |
| `unifi.existingSecretKeys.password` | Key for password in existing secret | `UNIFI_PASSWORD` |

### Operator Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.create` | Create ConfigMap for operator config | `true` |
| `config.defaultNamespace` | Default namespace for resources | `"default"` |
| `config.fullSyncZone` | Full sync zone name | `""` |
| `config.fullSyncNetwork` | Full sync network name | `""` |
| `config.kubernetesUnifiZone` | Kubernetes UniFi zone name | `""` |
| `config.existingConfigMap` | Use existing ConfigMap | `""` |

### RBAC Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rbac.create` | Create RBAC resources | `true` |

### CRD Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `crds.install` | Install CRDs | `true` |
| `crds.keep` | Keep CRDs on uninstall | `true` |

### Service Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.enabled` | Enable metrics service | `true` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8443` |
| `service.annotations` | Service annotations | `{}` |

### Metrics Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.serviceMonitor.enabled` | Enable Prometheus ServiceMonitor | `false` |
| `metrics.serviceMonitor.additionalLabels` | Additional labels for ServiceMonitor | `{}` |
| `metrics.serviceMonitor.interval` | Scrape interval | `30s` |
| `metrics.serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |

### Other Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `leaderElection.enabled` | Enable leader election | `true` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `podAnnotations` | Pod annotations | `{"kubectl.kubernetes.io/default-container": "manager"}` |
| `podLabels` | Pod labels | `{"control-plane": "controller-manager"}` |

## Using an Existing Secret

If you prefer to manage the UniFi credentials separately, you can create a secret manually and reference it:

```bash
kubectl create secret generic my-unifi-secret \
  --from-literal=UNIFI_URL="https://unifi.example.com:8443" \
  --from-literal=UNIFI_SITE="default" \
  --from-literal=UNIFI_USERNAME="admin" \
  --from-literal=UNIFI_PASSWORD="your-password" \
  -n unifi-network-operator-system
```

Then install the chart with:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.existingSecret="my-unifi-secret"
```

## Examples

### Basic Installation

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://192.168.1.1:8443" \
  --set unifi.password="mypassword"
```

### Installation with Custom Configuration

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://unifi.example.com:8443" \
  --set unifi.username="operator" \
  --set unifi.password="secure-password" \
  --set unifi.site="main" \
  --set config.defaultNamespace="production" \
  --set config.fullSyncZone="gateway" \
  --set config.fullSyncNetwork="core" \
  --set resources.limits.memory="256Mi" \
  --set metrics.serviceMonitor.enabled=true
```

### Using a Values File

Create a `my-values.yaml` file:

```yaml
unifi:
  url: "https://unifi.example.com:8443"
  username: "operator"
  password: "my-secure-password"
  site: "default"

config:
  defaultNamespace: "default"
  fullSyncZone: "gateway"
  fullSyncNetwork: "core"

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
```

Install with:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  -f my-values.yaml
```

## Custom Resources

After installing the operator, you can create the following custom resources:

### FirewallZone

```yaml
apiVersion: unifi.engen.priv.no/v1beta1
kind: FirewallZone
metadata:
  name: my-zone
spec:
  zoneName: "my-zone"
```

### FirewallGroup

```yaml
apiVersion: unifi.engen.priv.no/v1beta1
kind: FirewallGroup
metadata:
  name: web-servers
spec:
  addresses:
    - "10.0.1.100/32"
    - "10.0.1.101/32"
  ports:
    - "80/tcp"
    - "443/tcp"
```

### FirewallPolicy

```yaml
apiVersion: unifi.engen.priv.no/v1beta1
kind: FirewallPolicy
metadata:
  name: allow-web
spec:
  sourceZone: "wan"
  destinationGroup: "web-servers"
```

### Networkconfiguration

```yaml
apiVersion: unifi.engen.priv.no/v1beta1
kind: Networkconfiguration
metadata:
  name: vlan10
spec:
  networkName: "VLAN10"
```

## Upgrading

To upgrade the operator to a new version:

```bash
helm upgrade unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system
```

## Troubleshooting

### Check Operator Logs

```bash
kubectl logs -n unifi-network-operator-system -l app.kubernetes.io/name=unifi-network-operator -f
```

### Check Operator Status

```bash
kubectl get deployment -n unifi-network-operator-system
kubectl get pods -n unifi-network-operator-system
```

### Verify CRDs are Installed

```bash
kubectl get crds | grep unifi.engen.priv.no
```

### Common Issues

1. **Authentication Failures**: Verify your UniFi credentials and URL are correct
2. **CRD Not Found**: Ensure CRDs are installed with `crds.install=true`
3. **Operator Not Starting**: Check resource limits and image pull secrets

## License

This chart is provided as-is under the same license as the UniFi Network Operator project.

## Support

For issues and questions, please refer to the project repository.

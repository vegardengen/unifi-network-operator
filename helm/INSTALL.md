# UniFi Network Operator - Helm Installation Guide

## Quick Start

### 1. Install the Helm Chart

The simplest way to install the operator:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://your-unifi-controller:8443" \
  --set unifi.password="your-password"
```

### 2. Verify Installation

```bash
# Check if the operator is running
kubectl get pods -n unifi-network-operator-system

# Check the operator logs
kubectl logs -n unifi-network-operator-system -l app.kubernetes.io/name=unifi-network-operator -f

# Verify CRDs are installed
kubectl get crds | grep unifi.engen.priv.no
```

### 3. Create Your First Resource

Create a FirewallZone:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: unifi.engen.priv.no/v1beta1
kind: FirewallZone
metadata:
  name: test-zone
  namespace: default
spec:
  zoneName: "test-zone"
EOF
```

## Production Installation

For production deployments, create a `values.yaml` file:

```yaml
# production-values.yaml
replicaCount: 1

image:
  repository: gitea.engen.priv.no/klauvsteinen/unifi-network-operator-controller
  tag: "latest"
  pullPolicy: IfNotPresent

unifi:
  url: "https://unifi.example.com:8443"
  site: "default"
  username: "operator-user"
  # Use existingSecret in production!
  existingSecret: "unifi-credentials"

config:
  defaultNamespace: "default"
  fullSyncZone: "gateway"
  fullSyncNetwork: "core"
  kubernetesUnifiZone: "kubernetes"

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 50m
    memory: 128Mi

metrics:
  serviceMonitor:
    enabled: true
    additionalLabels:
      prometheus: kube-prometheus

leaderElection:
  enabled: true

nodeSelector:
  kubernetes.io/os: linux

tolerations: []

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - unifi-network-operator
        topologyKey: kubernetes.io/hostname
```

Create the secret first:

```bash
kubectl create namespace unifi-network-operator-system

kubectl create secret generic unifi-credentials \
  --from-literal=UNIFI_URL="https://unifi.example.com:8443" \
  --from-literal=UNIFI_SITE="default" \
  --from-literal=UNIFI_USERNAME="operator-user" \
  --from-literal=UNIFI_PASSWORD="your-secure-password" \
  -n unifi-network-operator-system
```

Then install with the values file:

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  -f production-values.yaml
```

## Upgrading

```bash
helm upgrade unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  -f production-values.yaml
```

## Uninstalling

```bash
# Remove the operator (keeps CRDs and CRs by default)
helm uninstall unifi-network-operator -n unifi-network-operator-system

# To also remove CRDs (this will delete all custom resources!)
kubectl delete crds -l app.kubernetes.io/name=unifi-network-operator
```

## Testing Locally

You can test the chart rendering without installing:

```bash
# Render templates
helm template unifi-network-operator ./helm/unifi-network-operator \
  --set unifi.url="https://test.local" \
  --set unifi.password="test" \
  --debug

# Lint the chart
helm lint ./helm/unifi-network-operator \
  --set unifi.url="https://test.local" \
  --set unifi.password="test"

# Dry run installation
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://test.local" \
  --set unifi.password="test" \
  --dry-run --debug
```

## Packaging for Distribution

To package the chart for distribution:

```bash
# Package the chart
helm package helm/unifi-network-operator

# This creates: unifi-network-operator-0.1.0.tgz

# Generate index (if hosting a chart repository)
helm repo index .
```

## Common Configuration Scenarios

### Scenario 1: Development Environment

```bash
helm install unifi-network-operator ./helm/unifi-network-operator \
  -n unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://192.168.1.1:8443" \
  --set unifi.password="admin" \
  --set resources.limits.memory="128Mi" \
  --set resources.requests.memory="64Mi"
```

### Scenario 2: Multiple Sites

For managing multiple UniFi sites, deploy separate instances:

```bash
# Site 1
helm install unifi-operator-site1 ./helm/unifi-network-operator \
  -n unifi-site1 \
  --create-namespace \
  --set unifi.url="https://unifi-site1.example.com:8443" \
  --set unifi.site="site1" \
  --set unifi.password="password1"

# Site 2
helm install unifi-operator-site2 ./helm/unifi-network-operator \
  -n unifi-site2 \
  --create-namespace \
  --set unifi.url="https://unifi-site2.example.com:8443" \
  --set unifi.site="site2" \
  --set unifi.password="password2"
```

### Scenario 3: Using with ArgoCD

Create an ArgoCD Application:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: unifi-network-operator
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/yourusername/unifi-network-operator
    targetRevision: main
    path: helm/unifi-network-operator
    helm:
      values: |
        unifi:
          existingSecret: unifi-credentials
        config:
          fullSyncZone: "gateway"
          fullSyncNetwork: "core"
        metrics:
          serviceMonitor:
            enabled: true
  destination:
    server: https://kubernetes.default.svc
    namespace: unifi-network-operator-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

## Troubleshooting

### Operator Won't Start

Check the logs:
```bash
kubectl logs -n unifi-network-operator-system \
  -l app.kubernetes.io/name=unifi-network-operator
```

### Connection Issues to UniFi Controller

Verify the secret:
```bash
kubectl get secret -n unifi-network-operator-system
kubectl describe secret unifi-network-operator-unifi \
  -n unifi-network-operator-system
```

### CRDs Not Installing

Manually install CRDs:
```bash
kubectl apply -f helm/unifi-network-operator/crds/
```

### Resources Not Syncing

Check operator configuration:
```bash
kubectl get configmap -n unifi-network-operator-system
kubectl describe configmap unifi-network-operator-config \
  -n unifi-network-operator-system
```

## Additional Resources

- [Helm Chart README](./unifi-network-operator/README.md)
- [Values Reference](./unifi-network-operator/values.yaml)
- [Custom Resource Examples](../config/samples/)

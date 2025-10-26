# E2E Test Safety Mechanisms

## Overview

The E2E tests in this project include multiple safety mechanisms to prevent accidental execution against production or development Kubernetes clusters. These tests are designed to **only run against Kind (Kubernetes in Docker) clusters**.

## Safety Checks

### 1. Makefile Safety Check

When you run `make test-e2e`, the Makefile performs the following checks:

- ✅ Verifies that `kind` is installed
- ✅ Verifies that a Kind cluster is running
- ✅ **Verifies that kubectl context starts with `kind-`** (new safety feature)

If any of these checks fail, the tests will not run.

### 2. Test Suite Safety Checks

The test suite itself (in `e2e_suite_test.go`) performs additional checks:

- ✅ Verifies that a Kind cluster is running using `kind get clusters`
- ✅ Ensures kubectl context is pointing to the correct Kind cluster
- ✅ Automatically switches to the Kind context if needed (only if already on a Kind context)
- ✅ **Fails immediately if kubectl is pointing to a non-Kind cluster**

### 3. Context Validation

The `EnsureKindContext()` function in `test/utils/utils.go`:

- Gets the current kubectl context
- Verifies it starts with `kind-` prefix
- Switches to the correct Kind cluster if `KIND_CLUSTER` env var is set
- **Fails with a clear error message if context is not a Kind cluster**

## Why These Safety Checks Matter

**Without these checks, E2E tests could:**
- Delete cert-manager from your production cluster
- Remove CRDs from your development cluster
- Delete namespaces and resources from any cluster kubectl is pointing to

**The tests perform destructive cleanup operations including:**
- `kubectl delete -f <cert-manager-url>` (if cert-manager was installed by tests)
- `kubectl delete ns unifi-network-operator-system`
- `make undeploy` (removes operator resources)
- `make uninstall` (removes CRDs)

## How to Run E2E Tests Safely

### Prerequisites

1. Install Kind:
   ```bash
   # macOS
   brew install kind

   # Linux
   curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
   chmod +x ./kind
   sudo mv ./kind /usr/local/bin/kind
   ```

2. Create a Kind cluster:
   ```bash
   kind create cluster
   ```

3. Verify kubectl context:
   ```bash
   kubectl config current-context
   # Should output something like: kind-kind
   ```

### Running the Tests

```bash
# Ensure you're on the Kind context
kubectl config use-context kind-kind

# Run the tests
make test-e2e
```

### Using a Named Kind Cluster

If you have multiple Kind clusters:

```bash
# Create a named cluster
kind create cluster --name my-test-cluster

# Set the KIND_CLUSTER environment variable
export KIND_CLUSTER=my-test-cluster

# Run the tests (will automatically use kind-my-test-cluster context)
make test-e2e
```

## What If I See a Safety Check Error?

### Example Error

```
╔════════════════════════════════════════════════════════════════╗
║              SAFETY CHECK FAILED                               ║
╠════════════════════════════════════════════════════════════════╣
║ Current kubectl context: production-cluster
║
║ E2E tests can ONLY run against Kind clusters to prevent       ║
║ accidental damage to production or development clusters.      ║
...
╚════════════════════════════════════════════════════════════════╝
```

### How to Fix

1. Check available contexts:
   ```bash
   kubectl config get-contexts
   ```

2. Switch to a Kind context:
   ```bash
   kubectl config use-context kind-kind
   ```

3. If you don't have a Kind cluster, create one:
   ```bash
   kind create cluster
   ```

## Skipping Cert-Manager Installation

If cert-manager is already installed in your Kind cluster and you want to keep it:

```bash
export CERT_MANAGER_INSTALL_SKIP=true
make test-e2e
```

This will:
- Skip installing cert-manager if it's already present
- Skip uninstalling cert-manager after tests complete
- Preserve any existing cert-manager installation

## CI/CD Integration

In GitHub Actions or other CI systems, ensure:

1. A Kind cluster is created before tests run
2. The kubectl context is set to the Kind cluster
3. The `KIND_CLUSTER` environment variable matches your cluster name

Example GitHub Actions workflow:
```yaml
- name: Create Kind cluster
  run: kind create cluster

- name: Run E2E tests
  run: make test-e2e
```

## Incident Response

If E2E tests were accidentally run against a non-Kind cluster and cert-manager was deleted:

### Restore Cert-Manager

```bash
# Verify current context
kubectl config current-context

# Switch to the affected cluster if needed
kubectl config use-context <your-cluster-context>

# Reinstall cert-manager (version matches test suite)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.3/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=Available --timeout=5m \
  deployment.apps/cert-manager-webhook -n cert-manager

# Verify installation
kubectl get pods -n cert-manager
```

### Check for Other Damage

```bash
# Check if operator namespace was deleted
kubectl get ns unifi-network-operator-system

# Check if CRDs were removed
kubectl get crds | grep unifi-network-operator

# Restore from backups if needed
```

## Questions?

If you have questions about these safety mechanisms or encounter issues, please file an issue in the project repository.

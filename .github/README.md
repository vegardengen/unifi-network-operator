# GitHub Workflows Documentation

This directory contains GitHub Actions workflows for automating the build, test, and release process of the UniFi Network Operator.

## Workflows Overview

### 1. Docker Build and Push (`docker-build-push.yaml`)

**Triggers:**
- Push to `main` branch
- Push to `feature/**` branches
- Push of tags starting with `v*`
- Pull requests to `main`
- Manual dispatch

**What it does:**
- Runs Go tests with coverage
- Builds multi-architecture Docker images (amd64, arm64)
- Pushes images to GitHub Container Registry (ghcr.io)
- Creates tags based on branch/tag names

**Image naming:**
- `ghcr.io/vegardengen/unifi-network-operator:main` - Latest from main branch
- `ghcr.io/vegardengen/unifi-network-operator:feature-xyz` - Feature branch builds
- `ghcr.io/vegardengen/unifi-network-operator:v1.0.0` - Version tags
- `ghcr.io/vegardengen/unifi-network-operator:latest` - Latest stable release

### 2. Helm Chart Release (`helm-release.yaml`)

**Triggers:**
- Push to `main` branch with changes in `helm/` directory
- Manual dispatch

**What it does:**
- Packages the Helm chart
- Creates GitHub releases for chart versions
- Publishes chart to GitHub Pages
- Updates the Helm repository index

**Chart repository:** https://vegardengen.github.io/unifi-network-operator

### 3. Full Release (`release.yaml`)

**Triggers:**
- Push of version tags (e.g., `v1.0.0`, `v1.2.3`)
- Manual dispatch with version input

**What it does:**
1. Builds and pushes multi-arch Docker images
2. Updates Chart.yaml and values.yaml with release version
3. Packages and releases Helm chart
4. Creates GitHub release with release notes
5. Attaches Helm chart package to release

**Pre-release detection:** Automatically marks releases as pre-release if tag contains `alpha`, `beta`, or `rc`

### 4. PR Validation (`pr-validation.yaml`)

**Triggers:**
- Pull requests to `main` branch
- Manual dispatch

**What it does:**
- Validates Go code formatting
- Runs `go vet`
- Executes tests with race detection
- Uploads coverage to Codecov
- Lints Helm chart
- Validates rendered Kubernetes manifests
- Test builds Docker image

## Setup Requirements

### 1. Enable GitHub Pages

1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: `gh-pages` / `/ (root)`
4. Save

The Helm chart will be available at: https://vegardengen.github.io/unifi-network-operator

### 2. Enable GitHub Packages

GitHub Container Registry is enabled by default. Images are automatically pushed to:
`ghcr.io/vegardengen/unifi-network-operator`

To pull images:
```bash
docker pull ghcr.io/vegardengen/unifi-network-operator:latest
```

### 3. Configure Secrets (Optional)

The workflows use `GITHUB_TOKEN` which is automatically provided. Additional secrets you might want to add:

- `CODECOV_TOKEN` - For uploading coverage reports (optional)

### 4. Branch Protection (Recommended)

Configure branch protection for `main`:
1. Go to Settings → Branches → Branch protection rules
2. Add rule for `main`
3. Enable:
   - Require pull request reviews
   - Require status checks to pass (select PR Validation workflow)
   - Require branches to be up to date

## Usage

### Creating a Release

#### Method 1: Using Git Tags (Recommended)

```bash
# Create and push a version tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push github v1.0.0
```

This automatically:
1. Builds Docker images for `v1.0.0` and `latest`
2. Packages Helm chart with version `1.0.0`
3. Creates GitHub release
4. Publishes to Helm repository

#### Method 2: Manual Dispatch

1. Go to Actions → Release workflow
2. Click "Run workflow"
3. Enter the version tag (e.g., `v1.0.0`)
4. Click "Run workflow"

### Installing from the Helm Repository

Once the release workflow completes:

```bash
# Add the Helm repository
helm repo add unifi-network-operator https://vegardengen.github.io/unifi-network-operator

# Update repository cache
helm repo update

# Install the operator
helm install unifi-network-operator unifi-network-operator/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://your-unifi-controller:8443" \
  --set unifi.password="your-password"
```

### Using Development Builds

Feature branch builds are automatically pushed:

```bash
# Use a specific feature branch build
helm install unifi-network-operator ./helm/unifi-network-operator \
  --set image.repository=ghcr.io/vegardengen/unifi-network-operator \
  --set image.tag=feature-xyz
```

## Workflow Files

- [`docker-build-push.yaml`](workflows/docker-build-push.yaml) - Docker image CI/CD
- [`helm-release.yaml`](workflows/helm-release.yaml) - Helm chart publishing
- [`release.yaml`](workflows/release.yaml) - Complete release process
- [`pr-validation.yaml`](workflows/pr-validation.yaml) - PR checks
- [`cr.yaml`](cr.yaml) - Chart Releaser configuration

## Versioning Strategy

### Docker Images

- `latest` - Latest stable release from main branch
- `vX.Y.Z` - Specific version tag
- `X.Y.Z` - Version without 'v' prefix
- `X.Y` - Major.minor version
- `X` - Major version only
- `main` - Latest commit on main branch
- `feature-name` - Feature branch builds

### Helm Charts

- Chart version follows semantic versioning (X.Y.Z)
- AppVersion matches Docker image tag
- Both are automatically updated during release

## Troubleshooting

### Docker Build Fails

Check:
- Dockerfile syntax
- Go dependencies in go.mod
- Build context includes all necessary files

### Helm Release Fails

Check:
- Chart.yaml is valid
- All template files are valid YAML
- No syntax errors in templates
- Version in Chart.yaml is unique

### GitHub Pages Not Updating

1. Check workflow completed successfully
2. Verify `gh-pages` branch exists
3. Check Pages is enabled in repository settings
4. Wait a few minutes for CDN propagation

### Images Not Accessible

Public images require:
1. Repository → Settings → Packages
2. Find the package
3. Package settings → Change visibility → Public

## Best Practices

1. **Always test locally first:**
   ```bash
   make helm-lint
   make helm-template
   docker build -t test .
   ```

2. **Use semantic versioning:**
   - Major (X): Breaking changes
   - Minor (Y): New features, backward compatible
   - Patch (Z): Bug fixes

3. **Create release notes:**
   - Describe what changed
   - Highlight breaking changes
   - Document upgrade path

4. **Test releases in a dev environment:**
   - Use pre-release tags (`v1.0.0-beta1`)
   - Validate before promoting to stable

## Monitoring

### Check Workflow Status

- Go to repository → Actions
- View workflow runs
- Check logs for failures

### View Published Artifacts

- **Docker images:** https://github.com/vegardengen/unifi-network-operator/pkgs/container/unifi-network-operator
- **Helm charts:** https://github.com/vegardengen/unifi-network-operator/releases
- **Chart repository:** https://vegardengen.github.io/unifi-network-operator

## Support

For issues with workflows:
1. Check the Actions tab for detailed logs
2. Review the workflow YAML files
3. Consult GitHub Actions documentation
4. Open an issue in the repository

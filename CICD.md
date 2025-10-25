# CI/CD Pipeline Documentation

This document describes the continuous integration and deployment pipeline for the UniFi Network Operator.

## Overview

The CI/CD pipeline is built using GitHub Actions and provides:

- **Automated testing** on every pull request
- **Multi-architecture Docker image builds** (amd64, arm64)
- **Automated Helm chart releases** to GitHub Pages
- **Complete release automation** with version tagging
- **Public Docker images** via GitHub Container Registry

## Quick Start

### For Users

**Install the operator using Helm:**

```bash
# Add the Helm repository
helm repo add unifi-network-operator https://vegardengen.github.io/unifi-network-operator
helm repo update

# Install
helm install unifi-network-operator unifi-network-operator/unifi-network-operator \
  --namespace unifi-network-operator-system \
  --create-namespace \
  --set unifi.url="https://your-unifi-controller:8443" \
  --set unifi.password="your-password"
```

**Or use Docker directly:**

```bash
docker pull ghcr.io/vegardengen/unifi-network-operator:latest
```

### For Contributors

**Run checks locally before pushing:**

```bash
# Format code
make fmt

# Run linters
make vet

# Run tests
make test

# Lint Helm chart
make helm-lint

# Test Docker build
docker build -t test .
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         GitHub Repository                        │
│                  vegardengen/unifi-network-operator              │
└─────────────────────────────────────────────────────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
                ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌─────────────┐
        │ Pull Request │ │ Push to Main │ │  Tag Push   │
        │  Validation  │ │              │ │   (v*.*)    │
        └──────────────┘ └──────────────┘ └─────────────┘
                │                │                │
                ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌─────────────┐
        │   • Go Fmt   │ │ Docker Build │ │   Release   │
        │   • Go Vet   │ │   & Push     │ │  Workflow   │
        │   • Tests    │ │              │ │             │
        │   • Helm     │ │ Helm Chart   │ │  • Docker   │
        │     Lint     │ │   Release    │ │  • Helm     │
        │   • Docker   │ │              │ │  • GitHub   │
        │     Build    │ │              │ │    Release  │
        └──────────────┘ └──────────────┘ └─────────────┘
                                 │                │
                                 ▼                ▼
                         ┌───────────────────────────┐
                         │  GitHub Container Registry │
                         │  ghcr.io/vegardengen/...  │
                         └───────────────────────────┘
                                 │
                                 ▼
                         ┌───────────────────────────┐
                         │    GitHub Pages (Helm)    │
                         │  vegardengen.github.io/   │
                         └───────────────────────────┘
```

## Workflows

### 1. PR Validation (`pr-validation.yaml`)

**Triggers:** Pull requests to `main`

**Steps:**
1. Code formatting check (`go fmt`)
2. Static analysis (`go vet`)
3. Unit tests with race detection
4. Coverage upload to Codecov
5. Helm chart linting
6. Template rendering validation
7. Test Docker build

**Purpose:** Ensure code quality before merging

### 2. Docker Build & Push (`docker-build-push.yaml`)

**Triggers:**
- Push to `main` or `feature/**` branches
- Push of tags starting with `v*`
- Pull requests (build only, no push)

**Steps:**
1. Run tests
2. Set up QEMU for cross-compilation
3. Set up Docker Buildx
4. Extract metadata for tags
5. Build for multiple architectures
6. Push to GitHub Container Registry

**Image Tags Created:**
- Branch builds: `main`, `feature-xyz`
- Version tags: `v1.0.0`, `1.0.0`, `1.0`, `1`
- Latest: `latest` (from main branch)
- Commit SHA: `main-abc1234`

### 3. Helm Chart Release (`helm-release.yaml`)

**Triggers:**
- Push to `main` with changes in `helm/` directory
- Manual workflow dispatch

**Steps:**
1. Package Helm chart
2. Create GitHub release for chart
3. Update Helm repository index
4. Publish to GitHub Pages

**Output:** Helm repository at `https://vegardengen.github.io/unifi-network-operator`

### 4. Complete Release (`release.yaml`)

**Triggers:**
- Push of version tags (e.g., `v1.0.0`)
- Manual workflow dispatch with version input

**Steps:**
1. **Build Phase:**
   - Run tests
   - Build multi-arch Docker images
   - Push with version tags and `latest`

2. **Chart Phase:**
   - Update Chart.yaml with version
   - Update values.yaml with image tag
   - Package Helm chart
   - Release chart to repository

3. **Release Phase:**
   - Generate release notes
   - Create GitHub release
   - Attach Helm chart package
   - Mark as pre-release if needed

**Pre-release Detection:** Tags containing `alpha`, `beta`, or `rc` are marked as pre-releases

## Release Process

### Creating a New Release

1. **Prepare the release:**
   ```bash
   # Ensure you're on main and up to date
   git checkout main
   git pull github main

   # Update CHANGELOG.md with release notes
   # Commit any final changes
   ```

2. **Create and push the tag:**
   ```bash
   # Create an annotated tag
   git tag -a v1.0.0 -m "Release v1.0.0: Description of changes"

   # Push the tag
   git push github v1.0.0
   ```

3. **Monitor the release:**
   - Go to Actions tab on GitHub
   - Watch the "Release" workflow
   - Check for any errors

4. **Verify the release:**
   ```bash
   # Check Docker image
   docker pull ghcr.io/vegardengen/unifi-network-operator:v1.0.0

   # Check Helm chart
   helm repo update
   helm search repo unifi-network-operator

   # Check GitHub release page
   # https://github.com/vegardengen/unifi-network-operator/releases
   ```

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes, backward compatible

**Pre-release tags:**
- `v1.0.0-alpha.1` - Early preview
- `v1.0.0-beta.1` - Feature complete, testing
- `v1.0.0-rc.1` - Release candidate

## Artifact Locations

### Docker Images

**Repository:** `ghcr.io/vegardengen/unifi-network-operator`

**Access:**
```bash
# Pull latest
docker pull ghcr.io/vegardengen/unifi-network-operator:latest

# Pull specific version
docker pull ghcr.io/vegardengen/unifi-network-operator:v1.0.0
```

**Platforms:** `linux/amd64`, `linux/arm64`

### Helm Charts

**Repository:** `https://vegardengen.github.io/unifi-network-operator`

**Access:**
```bash
# Add repository
helm repo add unifi-network-operator https://vegardengen.github.io/unifi-network-operator

# Search charts
helm search repo unifi-network-operator

# Install
helm install my-release unifi-network-operator/unifi-network-operator
```

**Also available:** As attachments on GitHub Releases

## Configuration

### Repository Settings Required

1. **Actions Permissions:**
   - Settings → Actions → General
   - Workflow permissions: Read and write
   - Allow GitHub Actions to create releases: ✓

2. **GitHub Pages:**
   - Settings → Pages
   - Source: Deploy from branch
   - Branch: `gh-pages` / `/ (root)`

3. **Package Visibility (After First Push):**
   - Profile → Packages → unifi-network-operator
   - Package settings → Change visibility → Public

### Branch Protection (Recommended)

- Settings → Branches → Add rule for `main`
- Require pull request reviews
- Require status checks: `lint-and-test`, `helm-lint`, `docker-build`
- Require branches to be up to date

## Troubleshooting

### Common Issues

**"Resource not accessible by integration"**
- Fix: Enable read/write permissions in repository settings

**Docker push fails**
- Check package visibility settings
- Verify GITHUB_TOKEN permissions

**Helm chart not updating**
- Ensure gh-pages branch exists
- Check GitHub Pages is enabled
- Wait 5-10 minutes for CDN propagation

**Release workflow fails**
- Check Chart.yaml version is unique
- Verify all templates are valid YAML
- Review workflow logs for specific error

### Debug Locally

```bash
# Test Helm rendering
make helm-template

# Lint Helm chart
make helm-lint

# Build Docker image
docker build -t test:latest .

# Run tests
make test

# Check formatting
make fmt
make vet
```

## Monitoring

### Workflow Status

Check at: https://github.com/vegardengen/unifi-network-operator/actions

### Artifacts

- **Docker Images:** https://github.com/vegardengen/unifi-network-operator/pkgs/container/unifi-network-operator
- **Releases:** https://github.com/vegardengen/unifi-network-operator/releases
- **Helm Repository:** https://vegardengen.github.io/unifi-network-operator

### Metrics

- Build success rate
- Test coverage (via Codecov)
- Release frequency
- Download statistics (via GitHub Insights)

## Security

### Container Scanning

Consider adding:
- Trivy vulnerability scanning
- Dependabot alerts
- SBOM generation

### Secrets Management

- Use GitHub Secrets for sensitive data
- Never commit credentials
- Rotate tokens regularly

### Supply Chain Security

- Images built from source
- Signed releases (future enhancement)
- SBOM attached to releases (future enhancement)

## Future Enhancements

- [ ] Automated vulnerability scanning
- [ ] Signed container images (cosign)
- [ ] SBOM generation
- [ ] Automated changelog generation
- [ ] Release drafter for draft releases
- [ ] Automated version bumping
- [ ] Integration tests in CI
- [ ] Performance benchmarking
- [ ] Automated security scanning

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Helm Chart Best Practices](https://helm.sh/docs/chart_best_practices/)
- [Container Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Semantic Versioning](https://semver.org/)

## Support

For CI/CD issues:
1. Check workflow logs in Actions tab
2. Review [.github/README.md](.github/README.md) for detailed docs
3. See [.github/SETUP.md](.github/SETUP.md) for setup instructions
4. Open an issue with workflow logs attached

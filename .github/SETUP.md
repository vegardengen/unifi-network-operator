# GitHub Actions Setup Guide

Quick guide to get the CI/CD workflows running for the UniFi Network Operator.

## Prerequisites

- Repository pushed to GitHub
- Admin access to the repository

## Step-by-Step Setup

### 1. Enable GitHub Container Registry

Images will be pushed to `ghcr.io/vegardengen/unifi-network-operator`

**Make the package public (after first push):**

1. Go to your GitHub profile → Packages
2. Find `unifi-network-operator`
3. Package settings → Change visibility → Public
4. Confirm by typing the package name

### 2. Enable GitHub Pages

**Set up GitHub Pages for Helm chart hosting:**

1. Go to repository **Settings** → **Pages**
2. Under "Build and deployment":
   - **Source:** Deploy from a branch
   - **Branch:** `gh-pages` / `/ (root)`
   - Click **Save**

3. Wait for initial deployment (workflow will create the branch)

Your Helm repository will be available at:
```
https://vegardengen.github.io/unifi-network-operator
```

### 3. Configure Repository Permissions

**Allow workflows to create releases:**

1. Go to **Settings** → **Actions** → **General**
2. Scroll to "Workflow permissions"
3. Select **Read and write permissions**
4. Check **Allow GitHub Actions to create and approve pull requests**
5. Click **Save**

### 4. Set Up Branch Protection (Optional but Recommended)

**Protect the main branch:**

1. Go to **Settings** → **Branches**
2. Click **Add branch protection rule**
3. Branch name pattern: `main`
4. Enable:
   - ☑ Require a pull request before merging
   - ☑ Require status checks to pass before merging
     - Search and select: `lint-and-test`, `helm-lint`, `docker-build`
   - ☑ Require branches to be up to date before merging
5. Click **Create** or **Save changes**

### 5. Test the Workflows

**Test PR validation:**

```bash
# Create a test branch
git checkout -b test-workflows

# Make a small change
echo "# Test" >> README.md

# Commit and push
git add README.md
git commit -m "Test workflows"
git push github test-workflows

# Create a PR on GitHub
# Check Actions tab to see PR validation running
```

**Test Docker build:**

```bash
# Push to main branch (after PR is merged)
git checkout main
git pull github main
git push github main

# Check Actions → Docker Build and Push workflow
```

**Test full release:**

```bash
# Create and push a version tag
git tag -a v0.1.0 -m "First release"
git push github v0.1.0

# Check Actions → Release workflow
# This will:
# 1. Build Docker images
# 2. Package Helm chart
# 3. Create GitHub release
# 4. Publish to Helm repository
```

### 6. Verify Everything Works

**Check Docker image:**

```bash
# Pull the image
docker pull ghcr.io/vegardengen/unifi-network-operator:v0.1.0

# Verify it works
docker run --rm ghcr.io/vegardengen/unifi-network-operator:v0.1.0 --version
```

**Check Helm repository:**

```bash
# Add the Helm repo
helm repo add unifi-network-operator https://vegardengen.github.io/unifi-network-operator

# Update
helm repo update

# Search for charts
helm search repo unifi-network-operator

# Show chart info
helm show chart unifi-network-operator/unifi-network-operator
```

## Optional: Add Codecov Integration

**For test coverage reports:**

1. Go to https://codecov.io
2. Sign in with GitHub
3. Add your repository
4. Copy the token
5. Go to repository **Settings** → **Secrets and variables** → **Actions**
6. Click **New repository secret**
   - Name: `CODECOV_TOKEN`
   - Value: [paste token]
7. Click **Add secret**

## Troubleshooting

### Workflow Fails with "Resource not accessible by integration"

**Fix:** Enable read and write permissions (see Step 3 above)

### Docker Image Push Fails with "Permission denied"

**Fix:**
1. Go to package settings
2. Add repository access
3. Or change package visibility to public

### Helm Chart Not Appearing on GitHub Pages

**Check:**
1. `gh-pages` branch was created
2. Pages is enabled in settings
3. Workflow completed successfully
4. Wait 5-10 minutes for CDN

**Manually create gh-pages branch if needed:**
```bash
git checkout --orphan gh-pages
git rm -rf .
echo "# Helm Charts" > README.md
git add README.md
git commit -m "Initialize gh-pages"
git push github gh-pages
```

### Release Workflow Fails

**Common issues:**
- Chart version already exists → Bump version in Chart.yaml
- Invalid YAML → Run `make helm-lint` locally first
- Missing permissions → Check Step 3

## Next Steps

Once everything is working:

1. **Update README.md** with installation instructions:
   ```markdown
   ## Installation

   ### Using Helm

   ```bash
   helm repo add unifi-network-operator https://vegardengen.github.io/unifi-network-operator
   helm repo update
   helm install unifi-network-operator unifi-network-operator/unifi-network-operator \
     --namespace unifi-network-operator-system \
     --create-namespace \
     --set unifi.url="https://your-controller:8443" \
     --set unifi.password="your-password"
   ```
   ```

2. **Add badges to README.md:**
   ```markdown
   ![Build Status](https://github.com/vegardengen/unifi-network-operator/workflows/Build%20and%20Push%20Docker%20Image/badge.svg)
   ![Helm Release](https://github.com/vegardengen/unifi-network-operator/workflows/Release%20Helm%20Chart/badge.svg)
   ```

3. **Create your first official release:**
   ```bash
   git tag -a v0.1.0 -m "Initial release"
   git push github v0.1.0
   ```

4. **Monitor the Actions tab** to ensure everything completes successfully

## Workflow Files Summary

| File | Purpose | Trigger |
|------|---------|---------|
| `docker-build-push.yaml` | Build and push Docker images | Push to main, tags, PRs |
| `helm-release.yaml` | Publish Helm chart to GitHub Pages | Push to main (helm changes) |
| `release.yaml` | Complete release process | Version tags (v*) |
| `pr-validation.yaml` | Validate PRs | Pull requests to main |

## Getting Help

- **GitHub Actions Docs:** https://docs.github.com/en/actions
- **Helm Chart Releaser:** https://github.com/helm/chart-releaser-action
- **GitHub Container Registry:** https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry

## Configuration Files

- [`.github/cr.yaml`](cr.yaml) - Chart Releaser configuration
- [`.github/README.md`](README.md) - Detailed workflow documentation
- [`workflows/`](workflows/) - All workflow definitions

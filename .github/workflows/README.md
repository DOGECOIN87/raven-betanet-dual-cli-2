# GitHub Actions Workflows

This directory contains the CI/CD workflows for the Raven Betanet 1.1 Dual CLI project.

## Workflows Overview

### 1. `spec-linter.yml` - Spec-Compliance Linter CI/CD

**Purpose**: Builds, tests, and validates the `raven-linter` CLI tool.

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual dispatch

**Key Features**:
- Unit and integration testing
- Compliance check execution on sample binaries
- SBOM generation and validation
- Cross-platform binary builds (Linux, macOS, Windows)
- Security scanning with Gosec and govulncheck
- Artifact upload for compliance results and SBOM files

**Failure Handling**:
- Fails if any compliance checks fail
- Provides detailed error messages for debugging
- Uploads test artifacts for analysis

### 2. `chrome-utls-gen.yml` - Chrome uTLS Generator CI/CD

**Purpose**: Builds, tests, and validates the `chrome-utls-gen` CLI tool.

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual dispatch

**Key Features**:
- Unit and integration testing
- ClientHello generation testing
- JA3 fingerprint validation
- Template generation and validation
- Cross-platform binary builds
- Security scanning

**Failure Handling**:
- Fails if JA3 fingerprints don't match expected Chrome signatures
- Provides specific guidance for TLS-related failures
- Handles network issues gracefully in JA3 tests

### 3. `auto-refresh.yml` - Chrome Template Auto-Refresh

**Purpose**: Automatically updates Chrome uTLS templates when new Chrome versions are released.

**Triggers**:
- Scheduled: Every Sunday at 02:00 UTC
- Manual dispatch with optional force update

**Key Features**:
- Fetches latest Chrome version from Chromium API
- Updates templates if new version detected
- Validates generated templates
- Creates pull requests for template updates
- Commits changes directly to main branch

**Workflow**:
1. Check current vs latest Chrome version
2. Update templates if version changed
3. Validate updated templates
4. Test ClientHello generation and JA3 fingerprints
5. Commit changes or create PR (configurable)

### 4. `validate-workflows.yml` - Workflow Validation

**Purpose**: Validates the syntax and structure of all GitHub Actions workflows.

**Triggers**:
- Pull requests that modify workflow files
- Manual dispatch

**Key Features**:
- YAML syntax validation
- Workflow structure validation
- Trigger condition analysis
- Cron schedule validation

## Usage in CI/CD Pipeline

### For Development

1. **Feature Development**: 
   - Create feature branch
   - Make changes to CLI tools
   - Push changes (triggers appropriate workflow)
   - Review workflow results and artifacts

2. **Pull Request Process**:
   - Create PR to `main` or `develop`
   - Workflows run automatically
   - Review compliance results and test coverage
   - Merge after all checks pass

### For Production

1. **Release Process**:
   - Push to `main` branch
   - Cross-platform builds are created
   - Binaries are uploaded as artifacts
   - Security scans are performed

2. **Automated Maintenance**:
   - Chrome templates are updated weekly
   - PRs are created for template updates
   - Manual review and merge of template updates

## Secrets and Configuration

### Required Secrets

- `GITHUB_TOKEN`: Automatically provided by GitHub Actions
- No additional secrets required for basic functionality

### Optional Configuration

- Modify cron schedules in `auto-refresh.yml` for different update frequencies
- Adjust target test endpoints in JA3 tests
- Configure notification settings for failures

## Monitoring and Maintenance

### Workflow Health

- Monitor workflow run history in GitHub Actions tab
- Check for recurring failures in specific jobs
- Review artifact uploads for completeness

### Template Updates

- Monitor auto-refresh workflow for Chrome version updates
- Review generated PRs for template updates
- Manually test JA3 fingerprints after major Chrome updates

### Security

- Review security scan results regularly
- Update action versions periodically
- Monitor for new vulnerabilities in dependencies

## Troubleshooting

### Common Issues

1. **JA3 Test Failures**:
   - May indicate Chrome TLS behavior changes
   - Check network connectivity to test endpoints
   - Manually run `chrome-utls-gen ja3-test` locally

2. **Template Generation Failures**:
   - Check Chrome API endpoint availability
   - Verify uTLS library compatibility
   - Review Chrome version parsing logic

3. **Build Failures**:
   - Check Go version compatibility
   - Review dependency updates
   - Verify cross-compilation settings

### Manual Intervention

- Use `workflow_dispatch` triggers for manual runs
- Check workflow logs for detailed error messages
- Review uploaded artifacts for debugging information

## Contributing

When modifying workflows:

1. Test changes in a fork first
2. Use `validate-workflows.yml` to check syntax
3. Document any new secrets or configuration requirements
4. Update this README with workflow changes
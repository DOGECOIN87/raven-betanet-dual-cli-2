# Contributing to Raven Betanet Dual CLI Tools

We welcome contributions to the Raven Betanet Dual CLI Tools project! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for convenience)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/raven-betanet-dual-cli.git
cd raven-betanet-dual-cli

# Install dependencies
go mod download

# Install development tools
make install-tools

# Build the tools
make build

# Run tests
make test

# Run linting
make lint
```

## 🛠️ Development Workflow

### 1. Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/raven-betanet-dual-cli.git
   ```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Write clean, well-documented code
- Follow Go conventions and best practices
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run all tests
make test

# Run linting
make lint

# Run security scan
make security

# Test cross-platform builds
make build-all
```

### 5. Commit and Push

```bash
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature-name
```

### 6. Create Pull Request

1. Go to GitHub and create a pull request
2. Provide a clear description of your changes
3. Link any related issues
4. Wait for review and address feedback

## 📝 Code Style Guidelines

### Go Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Write clear, descriptive variable and function names
- Add comments for exported functions and complex logic

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Maintenance tasks

Examples:
```
feat(raven-linter): add new compliance check for license validation
fix(chrome-utls-gen): handle timeout errors gracefully
docs: update installation instructions for macOS
```

## 🧪 Testing Guidelines

### Test Types

1. **Unit Tests** - Test individual functions and components
2. **Integration Tests** - Test component interactions
3. **End-to-End Tests** - Test complete workflows
4. **CLI Tests** - Test command-line interfaces

### Writing Tests

- Place tests in the same package as the code being tested
- Use descriptive test names that explain what is being tested
- Follow the Arrange-Act-Assert pattern
- Use table-driven tests for multiple test cases
- Mock external dependencies

### Test Coverage

- Aim for >80% test coverage
- Focus on critical paths and edge cases
- Include both positive and negative test cases

## 🏗️ Architecture Guidelines

### Project Structure

```
├── cmd/                    # CLI applications
│   ├── raven-linter/      # Spec compliance linter
│   └── chrome-utls-gen/   # Chrome uTLS generator
├── internal/              # Private application code
│   ├── checks/           # Compliance check framework
│   ├── sbom/             # SBOM generation
│   ├── tlsgen/           # TLS template generation
│   └── utils/            # Shared utilities
├── tests/                # Test files and fixtures
├── .github/workflows/    # CI/CD workflows
└── docs/                 # Additional documentation
```

### Design Principles

- **Modularity** - Keep components loosely coupled
- **Testability** - Design for easy testing
- **Error Handling** - Provide clear, actionable error messages
- **Performance** - Optimize for reasonable performance
- **Security** - Follow security best practices

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Description** - Clear description of the issue
2. **Steps to Reproduce** - Detailed steps to reproduce the bug
3. **Expected Behavior** - What you expected to happen
4. **Actual Behavior** - What actually happened
5. **Environment** - OS, Go version, tool version
6. **Logs** - Relevant log output or error messages

## 💡 Feature Requests

When requesting features, please include:

1. **Use Case** - Why is this feature needed?
2. **Description** - Detailed description of the feature
3. **Acceptance Criteria** - How will we know it's complete?
4. **Alternatives** - Any alternative solutions considered

## 📋 Pull Request Guidelines

### Before Submitting

- [ ] Tests pass locally
- [ ] Code is properly formatted
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] No merge conflicts

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added for new functionality
```

## 🔒 Security

### Reporting Security Issues

Please do not report security vulnerabilities through public GitHub issues. Instead:

1. Email security concerns to the maintainers
2. Provide detailed information about the vulnerability
3. Allow time for the issue to be addressed before public disclosure

### Security Guidelines

- Validate all inputs
- Use secure coding practices
- Keep dependencies updated
- Follow principle of least privilege
- Sanitize sensitive data in logs

## 📚 Documentation

### Types of Documentation

1. **Code Comments** - Explain complex logic
2. **README** - Project overview and quick start
3. **API Documentation** - Function and method documentation
4. **User Guides** - Detailed usage instructions
5. **Developer Guides** - Architecture and development info

### Documentation Standards

- Write clear, concise documentation
- Include examples where helpful
- Keep documentation up to date with code changes
- Use proper markdown formatting

## 🎯 Release Process

Releases are handled by maintainers and follow semantic versioning:

- **Major** (x.0.0) - Breaking changes
- **Minor** (0.x.0) - New features, backward compatible
- **Patch** (0.0.x) - Bug fixes, backward compatible

## 🤝 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Assume good intentions

### Getting Help

- Check existing documentation first
- Search existing issues and discussions
- Ask questions in GitHub discussions
- Be specific and provide context

## 📞 Contact

- **Issues** - GitHub Issues for bugs and feature requests
- **Discussions** - GitHub Discussions for questions and ideas
- **Email** - Contact maintainers for security issues

Thank you for contributing to Raven Betanet Dual CLI Tools!
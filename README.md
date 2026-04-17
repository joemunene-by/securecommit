# SecureCommit

**Pre-commit security hooks and AI code review tool** -- catches secrets and security bugs before they reach the repo.

[![CI](https://github.com/joemunene/securecommit/actions/workflows/ci.yml/badge.svg)](https://github.com/joemunene/securecommit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What It Does

SecureCommit scans your code for:

- **Secrets and credentials**: AWS keys, GitHub/GitLab tokens, private keys, database connection strings, Stripe/Twilio/SendGrid keys, JWTs, Slack webhooks, and more
- **Security anti-patterns**: SQL injection, XSS, command injection, insecure deserialization, hardcoded passwords, weak crypto, path traversal, SSRF
- **High-entropy strings**: Shannon entropy analysis to catch random tokens assigned near secret-related keywords

It works as a **pre-commit hook**, a **GitHub Action**, or a standalone **CLI tool**.

---

## Quick Start

### Install

```bash
pip install securecommit
```

### Scan a directory

```bash
securecommit scan .
```

### Scan a single file

```bash
securecommit scan path/to/file.py
```

### Output formats

```bash
securecommit scan . --format json
securecommit scan . --format sarif --output results.sarif
securecommit scan . --format markdown
```

---

## Pre-commit Hook Setup

### Option 1: pre-commit framework

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/joemunene/securecommit
    rev: v0.1.0
    hooks:
      - id: securecommit
```

Then run:

```bash
pre-commit install
pre-commit run --all-files
```

### Option 2: Direct git hook

```bash
# Install as a git hook directly
securecommit hook
```

Or manually add to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
securecommit hook
```

---

## GitHub Action Setup

Add to `.github/workflows/security.yml`:

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  securecommit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: joemunene/securecommit@v0.1.0
        with:
          severity_threshold: high
          sarif_output: securecommit.sarif
```

This will:
1. Scan the PR diff for security issues
2. Post a comment on the PR with findings
3. Upload SARIF results to GitHub Code Scanning

---

## Configuration

Create a `.securecommit.yaml` in your project root:

```yaml
severity_threshold: high  # block on high + critical
detectors:
  secrets: true
  patterns: true
  entropy: true
allowlist:
  - "test_*.py"   # skip test files for some checks
  - "*.md"        # skip markdown
custom_patterns:
  - name: "internal_token"
    pattern: "INTERNAL_[A-Z0-9]{32}"
    severity: critical
    description: "Internal service token detected"
```

### Inline Suppression

Add `# securecommit:ignore` to any line to suppress findings on that line:

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"  # securecommit:ignore
```

### Allowlist File

Create a `.securecommit-allowlist` file:

```
# Skip all test files
file:test_*.py

# Suppress a specific rule globally
rule:SC-S013

# Allowlist a specific snippet by hash
hash:abc123def456
```

---

## Sample Output

### Console

```
                     SecureCommit Scan Results
+----------+--------+--------------------------+-----------+------+
| Severity | Rule   | Title                    | File      | Line |
+----------+--------+--------------------------+-----------+------+
| CRITICAL | SC-S001| AWS Access Key ID        | config.py |   12 |
| CRITICAL | SC-P005| Command Injection via... | utils.py  |   45 |
| HIGH     | SC-P010| Hardcoded Password       | auth.py   |    8 |
| MEDIUM   | SC-P011| Insecure Hash (MD5)      | crypto.py |   22 |
+----------+--------+--------------------------+-----------+------+
4 finding(s) | 12 file(s) scanned | Status: FAILED
```

### SARIF (GitHub Code Scanning)

SecureCommit produces SARIF v2.1.0 output compatible with GitHub Code Scanning:

```bash
securecommit scan . --format sarif --output results.sarif
```

Upload it with `github/codeql-action/upload-sarif@v3` to see results in the Security tab.

---

## Detectors

### Secret Detector (`SC-S*`)

| Rule     | Description                  | Severity |
|----------|------------------------------|----------|
| SC-S001  | AWS Access Key ID            | Critical |
| SC-S002  | AWS Secret Access Key        | Critical |
| SC-S003  | GCP Service Account Key      | Critical |
| SC-S004  | Azure Secret / Connection    | High     |
| SC-S005  | GitHub PAT (ghp_)            | Critical |
| SC-S006  | GitLab PAT (glpat-)          | Critical |
| SC-S007  | Generic API Key Assignment   | High     |
| SC-S008  | Private Key (PEM)            | Critical |
| SC-S009  | Database Connection String   | High     |
| SC-S010  | JWT Token                    | Medium   |
| SC-S011  | Slack Webhook URL            | High     |
| SC-S012  | Stripe Secret Key            | Critical |
| SC-S013  | Stripe Publishable Key       | Low      |
| SC-S014  | Twilio Auth Token            | High     |
| SC-S015  | SendGrid API Key             | High     |
| SC-S016  | Password in URL              | High     |

### Pattern Detector (`SC-P*`)

| Rule     | Description                          | Severity |
|----------|--------------------------------------|----------|
| SC-P001  | SQL Injection (string formatting)    | High     |
| SC-P002  | SQL Injection (concatenation with +) | High     |
| SC-P003  | XSS via innerHTML                    | High     |
| SC-P004  | XSS via dangerouslySetInnerHTML      | Medium   |
| SC-P005  | Command Injection via os.system      | Critical |
| SC-P006  | subprocess with shell=True           | High     |
| SC-P007  | exec/eval usage                      | High     |
| SC-P008  | Insecure Deserialization (pickle)    | Critical |
| SC-P009  | Insecure YAML Loading                | High     |
| SC-P010  | Hardcoded Password / Secret          | High     |
| SC-P011  | Insecure Hash (MD5)                  | Medium   |
| SC-P012  | Insecure Hash (SHA1)                 | Medium   |
| SC-P013  | ECB Mode Usage                       | High     |
| SC-P014  | Path Traversal                       | High     |
| SC-P015  | SSRF Indicator                       | High     |
| SC-P016  | TLS Verification Disabled            | Medium   |

### Entropy Detector (`SC-E*`)

| Rule     | Description              | Severity |
|----------|--------------------------|----------|
| SC-E001  | High-entropy string      | High     |

---

## Development

```bash
git clone https://github.com/joemunene/securecommit.git
cd securecommit
make dev       # install with dev dependencies
make test      # run test suite
make lint      # run linter
make scan      # self-scan the project
```

---

## License

MIT License. Copyright (c) 2026 Joe Munene.

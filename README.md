# Tork AI Governance Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Tork%20AI%20Governance-blue?logo=github)](https://github.com/marketplace/actions/tork-ai-governance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Add AI governance checks to your CI/CD pipeline. Scan for PII, validate policies, and enforce compliance automatically.

## Features

- **PII Detection** - Detect emails, SSNs, credit cards, API keys, and 15+ PII types
- **Policy Validation** - Enforce governance policies on AI outputs
- **Governance Score** - Get a 0-100 score for your codebase
- **SARIF Support** - Integrate with GitHub Code Scanning
- **Fast** - Scans thousands of files in seconds

## Quick Start

```yaml
name: AI Governance Check
on: [push, pull_request]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Tork Governance Scan
        uses: torknetwork/tork-action@v1
        with:
          api-key: ${{ secrets.TORK_API_KEY }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api-key` | Your Tork API key | Yes | - |
| `scan-path` | Path to scan | No | `.` |
| `fail-on-violation` | Fail build on violations | No | `true` |
| `severity-threshold` | Minimum severity to fail | No | `medium` |
| `scan-mode` | Scan mode: pii, policy, full | No | `full` |
| `output-format` | Output: json, sarif, markdown | No | `markdown` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Governance score (0-100) |
| `violations-count` | Number of violations found |
| `pii-detected` | Whether PII was detected |
| `sarif-file` | Path to SARIF file |

## Examples

### Basic Usage

```yaml
- name: Tork Scan
  uses: torknetwork/tork-action@v1
  with:
    api-key: ${{ secrets.TORK_API_KEY }}
```

### Custom Severity Threshold

```yaml
- name: Tork Scan (Critical Only)
  uses: torknetwork/tork-action@v1
  with:
    api-key: ${{ secrets.TORK_API_KEY }}
    severity-threshold: critical
    fail-on-violation: true
```

### With GitHub Code Scanning

```yaml
- name: Tork Scan
  uses: torknetwork/tork-action@v1
  with:
    api-key: ${{ secrets.TORK_API_KEY }}
    output-format: sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: tork-results.sarif
```

### Scan Specific Directory

```yaml
- name: Tork Scan
  uses: torknetwork/tork-action@v1
  with:
    api-key: ${{ secrets.TORK_API_KEY }}
    scan-path: ./src
```

## PII Types Detected

| Type | Severity | Example |
|------|----------|---------|
| SSN | Critical | 123-45-6789 |
| Credit Card | Critical | 4111-1111-1111-1111 |
| API Key | Critical | api_key=sk-xxxx |
| AWS Key | Critical | AKIA... |
| Private Key | Critical | -----BEGIN PRIVATE KEY----- |
| JWT | High | eyJhbG... |
| Passport | High | AB1234567 |
| Email | Medium | user@example.com |
| Phone | Medium | (555) 123-4567 |
| IP Address | Low | 192.168.1.1 |

## Getting an API Key

1. Sign up at [tork.network](https://tork.network)
2. Go to Dashboard → API Keys
3. Create a new key
4. Add to GitHub Secrets as `TORK_API_KEY`

## License

MIT © [Tork Network Pty Ltd](https://tork.network)

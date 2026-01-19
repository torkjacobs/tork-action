# Tork AI Governance Action v1.0.0

## Initial Release

The first release of Tork AI Governance Action - add AI governance checks to your CI/CD pipeline.

## Features

**PII Detection** - Scans 14+ types of sensitive data:
- Critical: SSN, Credit Cards, API Keys, AWS Keys, Private Keys
- High: JWTs, Passports, Medicare Numbers
- Medium: Emails, Phone Numbers, TFN, ABN, Date of Birth
- Low: IP Addresses

**Governance Scoring** - Get a 0-100 score for your codebase based on violations found

**Configurable Thresholds** - Set severity thresholds (low, medium, high, critical) to control when builds fail

**SARIF Output** - Generate SARIF reports for GitHub Code Scanning integration

**Fast Scanning** - Efficiently scans thousands of files, automatically skipping node_modules, .git, dist, and build directories

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
        uses: torkjacobs/tork-action@v1
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
| `output-format` | Output: json, sarif, markdown | No | `markdown` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Governance score (0-100) |
| `violations-count` | Number of violations found |
| `pii-detected` | Whether PII was detected |
| `sarif-file` | Path to SARIF file (if sarif output) |

## Links

- [Tork Website](https://tork.network)
- [Documentation](https://tork.network/docs)
- [Get API Key](https://tork.network/signup)
- [Report Issues](https://github.com/torkjacobs/tork-action/issues)

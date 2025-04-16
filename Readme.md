# RedRays ABAP Security Scanner

[![GitHub release](https://img.shields.io/github/release/redrays-io/redrays-cicd.svg)](https://github.com/redrays-io/redrays-cicd/releases/latest)
[![License](https://img.shields.io/github/license/redrays-io/redrays-cicd.svg)](LICENSE)

A GitHub Action and standalone script for scanning ABAP code for security vulnerabilities using the RedRays API.

## Overview

This repository provides tools to integrate RedRays ABAP security scanning into your CI/CD pipelines. You can use it as:

1. A GitHub Action in your workflows
2. A standalone Python script that can run anywhere

The scanner analyzes your ABAP code for security vulnerabilities such as SQL injection, OS command execution, directory traversal, and other OWASP Top 10 issues.

## GitHub Action Usage

Add the RedRays ABAP Security Scanner to your GitHub workflow:

```yaml
name: RedRays ABAP Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]
  # Optional: Add manual trigger
  workflow_dispatch:

jobs:
  scan-abap-code:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Scan ABAP code for security vulnerabilities
        uses: redrays-io/redrays-cicd@v1
        with:
          api-key: ${{ secrets.REDRAYS_API_KEY }}
          scan-dir: .
          output-format: html
          output-file: redrays_security_report.html
          fail-on-vulnerabilities: 'true'

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: redrays-security-report
          path: redrays_security_report.html
          retention-days: 7
```

### Inputs

| Input                   | Description                                       | Required | Default                          |
|-------------------------|---------------------------------------------------|----------|----------------------------------|
| `api-key`               | RedRays API key                                   | Yes      |                                  |
| `api-url`               | RedRays API URL                                   | No       | https://api2.redrays.io/api/scan |
| `scan-dir`              | Directory containing ABAP files to scan           | No       | .                                |
| `files`                 | Comma-separated list of specific files to scan    | No       |                                  |
| `output-format`         | Report output format (csv, html, json)            | No       | html                             |
| `output-file`           | Report output file path                           | No       | redrays_security_report.html     |
| `fail-on-vulnerabilities` | Fail the workflow if vulnerabilities are found  | No       | true                             |

### Outputs

| Output                 | Description                           |
|------------------------|---------------------------------------|
| `report-path`          | Path to the generated security report |
| `vulnerabilities-found`| Number of vulnerabilities found       |

## Standalone Script Usage

You can also use the scanner as a standalone Python script:

```bash
python redrays_scanner.py --api-key YOUR_API_KEY [options]
```

### Options

```
--api-key         RedRays API key (required)
--api-url         RedRays API URL (default: https://api2.redrays.io/api/scan)
--scan-dir        Directory containing ABAP files to scan
--files           Comma-separated list of specific files to scan
--output-format   Report output format (csv, html, json)
--output-file     Report output file path
--debug           Enable debug logging
```

### Examples

Scan all ABAP files in the current directory:
```bash
python redrays_scanner.py --api-key YOUR_API_KEY --scan-dir .
```

Scan specific files:
```bash
python redrays_scanner.py --api-key YOUR_API_KEY --files file1.abap,file2.abap
```

Change output format:
```bash
python redrays_scanner.py --api-key YOUR_API_KEY --scan-dir . --output-format csv
```

## Report Types

The scanner can generate reports in several formats:

- **HTML**: Interactive report with detailed information about each vulnerability
- **CSV**: Tabular data format for importing into spreadsheets or databases
- **JSON**: Machine-readable format for further processing

## Getting an API Key

To use the RedRays ABAP Security Scanner, you need an API key:

1. Register at [redrays.io](https://redrays.io)
2. Subscribe to a plan
3. Get your API key from your account dashboard
4. Add the API key as a secret in your GitHub repository

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/redrays-io/redrays-cicd/issues) on the GitHub repository.
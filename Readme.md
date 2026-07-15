# RedRays ABAP Security Scanner (GitHub Action)

Scan ABAP source for security vulnerabilities in CI using the RedRays **MC agent
API** (`/agent/v1`). Emits CSV, HTML, JSON, or **SARIF** (for GitHub code
scanning) and can fail the build on a configurable severity gate.

This is a **composite** action. The client (`redrays_scanner.py`) is **vendored
inside the action** and executed from the pinned action path -- it is never
downloaded from a branch at runtime, so pinning a tag pins the behavior.

---

## Quick start

```yaml
name: ABAP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: RedRays ABAP scan
        uses: redrays-io/redrays-cicd@v2      # moving major tag (see below)
        with:
          api-key: ${{ secrets.REDRAYS_TOKEN }}
          api-url: https://mc.example.com/agent/v1
          scan-dir: ./abap
          output-format: html
          output-file: redrays_report.html
          threshold: high
```

The `api-key` is forwarded to the client **only** through the `REDRAYS_TOKEN`
environment variable. It is never echoed and never placed on the command line.

---

## SARIF + GitHub code scanning

Set `output-format: sarif` and upload the result so findings appear in the
Security tab and as PR annotations:

```yaml
      - name: RedRays ABAP scan (SARIF)
        uses: redrays-io/redrays-cicd@v2
        with:
          api-key: ${{ secrets.REDRAYS_TOKEN }}
          api-url: https://mc.example.com/agent/v1
          scan-dir: ./abap
          output-format: sarif
          output-file: redrays.sarif
          fail-on-vulnerabilities: "false"   # let code scanning gate instead

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: redrays.sarif
```

Severity mapping to SARIF levels (SARIF only defines error/warning/note):
`CRITICAL`/`HIGH` -> `error`, `MEDIUM` -> `warning`, `LOW`/`INFO` -> `note`.
A `security-severity` property is set per rule so GitHub sorts findings.

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | yes | - | RedRays developer PAT. Sent as `X-RedRays-Api-Key`. Pass a secret. |
| `api-url` | no | `http://localhost:8080/agent/v1` | MC agent base URL ending in `/agent/v1`. |
| `scan-dir` | no | `.` | Directory searched recursively for `*.abap`. |
| `files` | no | `""` | Comma-separated file list. Overrides `scan-dir`. |
| `output-format` | no | `html` | `csv` \| `html` \| `json` \| `sarif`. |
| `output-file` | no | `redrays_security_report.html` | Report path. |
| `fail-on-vulnerabilities` | no | `true` | Fail if any finding exists. Only used when `threshold` is empty. |
| `threshold` | no | `""` | `critical` \| `high` \| `medium` \| `low` \| `informational`. |
| `scan-profile` | no | `CRITICAL_HIGH` | `QUICK` \| `FULL` \| `CRITICAL` \| `CRITICAL_HIGH`. |

## Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Actual path of the produced report. |
| `vulnerabilities-found` | Total number of findings. |
| `threshold-breached` | `true` if the gate was breached. |
| `scan-id` | MC session GUID for the scan. |

Outputs are written by the client to `$GITHUB_OUTPUT` -- **no log scraping**.

## Gating logic (single owner: the client)

- If `threshold` is set: the job fails when any finding severity is **at or
  above** the threshold (`CRITICAL>HIGH>MEDIUM>LOW>INFO`, inclusive `>=`).
  Findings below the threshold produce a warning but the job passes.
- If `threshold` is empty: the job fails when `fail-on-vulnerabilities: true`
  and at least one finding exists.

Exit code and gate are decided entirely inside `redrays_scanner.py`; the action
shell does not re-derive pass/fail.

---

## How it talks to MC (`/agent/v1`)

Auth header on every request: **`X-RedRays-Api-Key: <PAT>`**.
Optional `X-RedRays-Source: GITHUB_ACTION` label is sent on submit.

1. `GET /agent/v1/me` - verify the token / whoami.
2. `POST /agent/v1/scan-batch` - submit up to **200** objects in one session.
   Body: `{"programs":[{objectName,objectType,source}, ...], "scanProfile":"..."}`.
   ABAP `source` is sent as **raw text** (not base64, not a file upload).
   `objectType` is `FUNCTION` when the object name starts with `FUNC`, else
   `PROGRAM`. Returns `{"scan_id":"<guid>"}`.
3. `GET /agent/v1/scan-result/{scanId}` - poll until `COMPLETED` or `FAILED`.
4. `GET /agent/v1/findings?scan_id={scanId}` - collect findings.

---

## Versioning and the moving major tag

This action follows **SemVer** (`MAJOR.MINOR.PATCH`).

- **Immutable release tags** (e.g. `v2.0.0`, `v2.1.0`) each bundle a fixed
  copy of `redrays_scanner.py`. Pinning one gives fully reproducible behavior.
- A **moving major tag** (`v2`) is maintained and re-pointed to the latest
  `v2.x.y` release. This is the recommended reference for most users -- you get
  non-breaking fixes automatically while staying on a compatible major.
- For maximum supply-chain safety, pin to a **full commit SHA**.

Maintainers move the major tag on each release:

```bash
git tag -a v2.0.0 -m "v2.0.0"
git push origin v2.0.0
git tag -f v2 v2.0.0      # move the major tag
git push -f origin v2
```

Breaking changes bump the **major** and get a new moving tag (`v3`); `v2`
consumers are never surprised.

---

## Migration from v1 (`https://api.redrays.io/api/scan`)

v2 targets the MC agent API instead of the legacy single-endpoint scan service.

| Area | v1 | v2 |
|------|----|----|
| API | `https://api.redrays.io/api/scan` (one endpoint) | MC `/agent/v1` (me / scan-batch / scan-result / findings) |
| Auth header | `x-api-key` | `X-RedRays-Api-Key` |
| Token delivery | echoed in `Running: ...` log + CLI arg | env var `REDRAYS_TOKEN` only; never logged |
| Client source | `curl`ed from `master` at runtime | vendored in the action, run from `github.action_path` |
| Submit model | one POST per file | one batched async session (poll for result) |
| Outputs | scraped from the report with grep/awk/wc | written to `$GITHUB_OUTPUT` by the client |
| Formats | csv/html/json | csv/html/json + **sarif** |
| HTML report | unescaped interpolation (XSS risk) | all values HTML-escaped |

### What to change in your workflow

1. Point `api-url` at your MC agent base, e.g.
   `https://mc.example.com/agent/v1`.
2. Provide a **developer PAT** (validated as `X-RedRays-Api-Key`) instead of the
   old API key. Store it in `secrets.REDRAYS_TOKEN`.
3. Bump the `uses:` reference to `@v2`.
4. (Optional) switch `output-format` to `sarif` and add an
   `upload-sarif` step.

Input names, defaults, the `critical>...>informational` ordering with inclusive
`>=`, and "warn-but-pass below threshold" semantics are all preserved.

---

## Notes, assumptions, and contract gaps

- **Submit uses `/scan-batch`** for all runs (even a single file) because the
  contract caps a batch at 200 objects and returns one `scan_id` for the
  session; this keeps polling to a single GUID. Runs with more than 200 objects
  fail fast with a clear message (the contract does not define server-side
  chunking).
- **`objectType` detection** (`FUNCTION` vs `PROGRAM`) is a client heuristic
  (name prefix `FUNC`). The contract only says non-`FUNCTION` defaults to
  `PROGRAM`; it does not describe how a CI client should classify a file, so
  this is an explicit assumption.
- **`line_number` is a string** in the findings shape; the SARIF writer parses
  it defensively and falls back to line 1 when it is non-numeric or blank.
- **CVSS / `security-severity`** values used in SARIF are derived from the
  severity band because the agent findings mapper does **not** expose
  `cvss_score` (contract note on `AgentScanService.java:382-395`). This is a
  documented gap, not invented data.
- The contract's `/scan` (single), `/scans` (history), and `DELETE /scan/{id}`
  (cancel) endpoints are intentionally **not** used by this action.

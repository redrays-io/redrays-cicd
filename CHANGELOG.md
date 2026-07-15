# Changelog

All notable changes to this action are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). A moving major tag (`v2`) is
maintained alongside immutable release tags (see the README).

## [2.0.0] - 2026-07-15

### Changed (breaking)
- **Target the MC agent API `/agent/v1`** instead of the legacy
  `https://api.redrays.io/api/scan`. New endpoints: `GET /me`,
  `POST /scan-batch`, `GET /scan-result/{scanId}`, `GET /findings`.
- **Auth header is now `X-RedRays-Api-Key`** (was `x-api-key`), carrying a
  developer PAT.
- **Async batch flow**: files are submitted in one session via `/scan-batch`
  (raw ABAP text, max 200 objects), then the client polls `/scan-result` and
  collects `/findings`.

### Added
- **SARIF 2.1.0 output** (`output-format: sarif`) for GitHub code scanning,
  with per-rule `security-severity`.
- `scan-id` action output (MC session GUID).
- `scan-profile` input (`QUICK|FULL|CRITICAL|CRITICAL_HIGH`).
- Token connectivity check via `GET /me` before scanning.

### Fixed / hardened (anti-patterns from v1)
- **Client is vendored** in the action and run from `${{ github.action_path }}`;
  it is no longer `curl`ed from `master` at runtime. Pinning a tag now pins the
  client logic (removes the supply-chain risk).
- **Token is passed via the `REDRAYS_TOKEN` env var only** -- never echoed,
  never placed on the command line. The `Running: $CMD` log line is removed.
- **Action outputs are written to `$GITHUB_OUTPUT` by the client** instead of
  being scraped from the report with `grep`/`awk`/`wc` (fixes the JSON count
  bug and CSV/HTML fragility).
- **Single, consolidated gating logic** inside the client (no split shell vs
  Python fail paths).
- **HTML report values are HTML-escaped** (removes stored-XSS in the artifact).
- **Command is invoked as argv, not an eval'd concatenated string** (removes
  word-splitting / shell-injection via inputs).
- **Bounded HTTP behavior**: request timeouts, capped retries (no unbounded
  429 recursion), poll timeout.
- Uses `actions/setup-python@v5` with `python-version: 3.x` (no exact 3.9 pin)
  and relies only on the Python standard library (no runtime `pip install`).

### Migration
See "Migration from v1" in the README.

[2.0.0]: https://github.com/redrays-io/redrays-cicd/releases/tag/v2.0.0

#!/usr/bin/env python3
"""
RedRays ABAP Security Scanner - MC /agent/v1 client.

Vendored inside the GitHub Action and executed via
${{ github.action_path }}/redrays_scanner.py so that a pinned action tag
pins the client logic too (no runtime fetch from master).

Contract: MC AgentScanController @RequestMapping("/agent/v1").
Auth header: X-RedRays-Api-Key (developer PAT).

The API token is read ONLY from the REDRAYS_TOKEN environment variable.
It is never accepted as a CLI argument and never printed.
"""

import argparse
import csv
import html
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants derived strictly from the MC contract
# ---------------------------------------------------------------------------

DEFAULT_API_BASE = "http://localhost:8080/agent/v1"  # MC agent base; override via --api-url
AUTH_HEADER = "X-RedRays-Api-Key"
SOURCE_HEADER = "X-RedRays-Source"
SOURCE_LABEL = "GITHUB_ACTION"

# Contract severity ordering: CRITICAL>HIGH>MEDIUM>LOW>INFO
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "INFORMATIONAL": 0,  # accept the legacy CLI alias for INFO
}

# Contract batch cap
MAX_BATCH = 200

# Polling
POLL_INTERVAL_SECONDS = 5
POLL_TIMEOUT_SECONDS = 3600
HTTP_TIMEOUT_SECONDS = 60
MAX_RETRIES = 5


class ScanError(Exception):
    pass


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _request(method, url, token, body=None, headers=None):
    """Perform an HTTP request. Returns (status_code, parsed_json_or_text)."""
    data = None
    req_headers = {AUTH_HEADER: token}
    if headers:
        req_headers.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)

    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, _parse(raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            # 5xx are retryable; 4xx are not
            if 500 <= e.code < 600 and attempt < MAX_RETRIES - 1:
                last_exc = e
                time.sleep(POLL_INTERVAL_SECONDS * (attempt + 1))
                continue
            return e.code, _parse(raw)
        except urllib.error.URLError as e:
            last_exc = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(POLL_INTERVAL_SECONDS * (attempt + 1))
                continue
            raise ScanError("Network error contacting %s: %s" % (url, e))
    raise ScanError("Request failed after %d attempts: %s" % (MAX_RETRIES, last_exc))


def _parse(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _err_msg(payload, default):
    if isinstance(payload, dict) and "error" in payload:
        return str(payload["error"])
    return default


# ---------------------------------------------------------------------------
# Contract endpoint wrappers
# ---------------------------------------------------------------------------

def verify_token(base, token):
    """GET /me - whoami / token connectivity check."""
    status, payload = _request("GET", base + "/me", token)
    if status == 401:
        raise ScanError("Token verification failed (401): %s"
                        % _err_msg(payload, "Not authenticated"))
    if status != 200:
        raise ScanError("Token verification failed (%d): %s"
                        % (status, _err_msg(payload, "unexpected response")))
    dev = payload.get("developerName") or payload.get("developerEmail") or "developer"
    return dev


def submit_batch(base, token, programs, scan_profile):
    """POST /scan-batch - returns scan_id (session GUID)."""
    body = {"programs": programs, "scanProfile": scan_profile}
    status, payload = _request(
        "POST", base + "/scan-batch", token, body=body,
        headers={SOURCE_HEADER: SOURCE_LABEL},
    )
    if status == 200 and isinstance(payload, dict) and payload.get("scan_id"):
        return payload["scan_id"]
    if status == 403:
        raise ScanError("License limit (403): %s" % _err_msg(payload, "license error"))
    raise ScanError("Batch submit failed (%d): %s"
                    % (status, _err_msg(payload, "unexpected response")))


def poll_result(base, token, scan_id):
    """GET /scan-result/{scanId} - poll until COMPLETED or FAILED."""
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    last_progress = -1
    while True:
        status, payload = _request("GET", base + "/scan-result/" + scan_id, token)
        if status == 404:
            raise ScanError("Scan not found: %s" % scan_id)
        if status != 200 or not isinstance(payload, dict):
            raise ScanError("Poll failed (%d): %s"
                            % (status, _err_msg(payload, "unexpected response")))
        state = payload.get("status", "PENDING")
        progress = payload.get("progress", 0)
        if progress != last_progress:
            phase = payload.get("phase")
            print("  scan %s: %s %s%%%s" % (
                scan_id, state, progress,
                (" (" + str(phase) + ")") if phase else ""))
            last_progress = progress
        if state == "COMPLETED":
            return payload
        if state == "FAILED":
            raise ScanError("Scan FAILED (failed_objects=%s)"
                            % payload.get("failed_objects"))
        if time.time() > deadline:
            raise ScanError("Polling timed out after %ds (last status %s)"
                            % (POLL_TIMEOUT_SECONDS, state))
        time.sleep(POLL_INTERVAL_SECONDS)


def get_findings(base, token, scan_id):
    """GET /findings?scan_id= - returns list of finding dicts."""
    url = base + "/findings?scan_id=" + urllib.parse.quote(scan_id)
    status, payload = _request("GET", url, token)
    if status != 200 or not isinstance(payload, dict):
        raise ScanError("Findings fetch failed (%d): %s"
                        % (status, _err_msg(payload, "unexpected response")))
    return payload.get("findings", [])


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def classify_object_type(source):
    """FUNCTION vs PROGRAM from the SOURCE (a name-prefix guess mislabels real FMs).
    A function-module include is FUNCTION <name>. ... ENDFUNCTION; everything else
    (reports, executable programs, classes) is submitted as PROGRAM per the contract."""
    if re.search(r"(?im)^\s*FUNCTION\s+[\w/]+", source) and re.search(r"(?im)^\s*ENDFUNCTION\b", source):
        return "FUNCTION"
    return "PROGRAM"


def collect_programs(files_arg, scan_dir):
    """Build the contract 'programs' list from --files or --scan-dir."""
    paths = []
    if files_arg:
        for f in files_arg.split(","):
            f = f.strip()
            if f:
                paths.append(f)
    else:
        for root, _dirs, names in os.walk(scan_dir):
            for name in names:
                if name.lower().endswith(".abap"):
                    paths.append(os.path.join(root, name))
    paths.sort()

    programs = []
    for path in paths:
        if not os.path.isfile(path):
            print("WARNING: skipping missing file: %s" % path, file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        if not source.strip():
            print("WARNING: skipping empty file: %s" % path, file=sys.stderr)
            continue
        object_name = os.path.splitext(os.path.basename(path))[0]
        object_type = classify_object_type(source)
        programs.append({
            "objectName": object_name,
            "objectType": object_type,
            "source": source,        # RAW TEXT per contract (not base64)
            "_path": path,           # local-only; stripped before submit
        })
    return programs


# ---------------------------------------------------------------------------
# Threshold gating
# ---------------------------------------------------------------------------

def severity_rank(sev):
    return SEVERITY_ORDER.get((sev or "").strip().upper(), -1)


def threshold_breached(findings, threshold):
    if not threshold:
        return False
    gate = SEVERITY_ORDER.get(threshold.strip().upper())
    if gate is None:
        return False
    for f in findings:
        rank = severity_rank(f.get("severity"))
        if rank >= 0 and rank >= gate:
            return True
    return False


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def write_json_report(findings, out_file, scan_id, files_scanned):
    counts = _severity_counts(findings)
    report = {
        "report_date": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "files_scanned": files_scanned,
        "vulnerabilities_found": len(findings),
        "severity_counts": counts,
        "findings": findings,
    }
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_csv_report(findings, out_file):
    with open(out_file, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "Object Name", "Finding ID", "Severity", "Line",
            "Issue Title", "Issue Type", "Description", "Recommendation", "Status",
        ])
        for f in findings:
            writer.writerow([
                f.get("object_name", ""), f.get("finding_id", ""),
                f.get("severity", ""), f.get("line_number", ""),
                f.get("issue_title", ""), f.get("issue_type", ""),
                f.get("issue_description", ""), f.get("recommendation", ""),
                f.get("status", ""),
            ])


def write_html_report(findings, out_file, scan_id, files_scanned):
    counts = _severity_counts(findings)
    e = html.escape  # escape ALL interpolated values (no stored-XSS)
    rows = []
    for f in findings:
        rows.append(
            "<div class='card sev-%s'>"
            "<div class='badge'>%s</div>"
            "<h3>%s</h3>"
            "<p class='meta'>Object: <code>%s</code> &middot; Line: %s &middot; "
            "Finding: %s</p>"
            "<p>%s</p>"
            "<p class='rec'><strong>Recommendation:</strong> %s</p>"
            "</div>" % (
                e((f.get("severity") or "").lower()),
                e(f.get("severity", "")),
                e(f.get("issue_title", "")),
                e(f.get("object_name", "")),
                e(str(f.get("line_number", ""))),
                e(f.get("finding_id", "")),
                e(f.get("issue_description", "")),
                e(f.get("recommendation", "")),
            )
        )
    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>RedRays ABAP Security Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1a1a1a}}
h1{{color:#c0392b}}
.summary{{background:#f6f6f6;padding:1rem;border-radius:6px}}
.card{{border:1px solid #ddd;border-left:6px solid #999;padding:1rem;margin:1rem 0;border-radius:4px}}
.card.sev-critical{{border-left-color:#c0392b}}
.card.sev-high{{border-left-color:#e67e22}}
.card.sev-medium{{border-left-color:#f1c40f}}
.card.sev-low{{border-left-color:#3498db}}
.card.sev-info{{border-left-color:#95a5a6}}
.badge{{display:inline-block;font-weight:bold;font-size:.8rem}}
code{{background:#eee;padding:0 .3rem}}
</style></head><body>
<h1>RedRays ABAP Security Report</h1>
<div class="summary">
<p>Scan ID: <code>{scan_id}</code></p>
<p>Files Scanned: {files_scanned}</p>
<p>Vulnerabilities Found: {vuln_count}</p>
<p>CRITICAL: {c} &middot; HIGH: {h} &middot; MEDIUM: {m} &middot; LOW: {l} &middot; INFO: {i}</p>
</div>
{cards}
</body></html>""".format(
        scan_id=e(scan_id or ""),
        files_scanned=files_scanned,
        vuln_count=len(findings),
        c=counts["CRITICAL"], h=counts["HIGH"], m=counts["MEDIUM"],
        l=counts["LOW"], i=counts["INFO"],
        cards="\n".join(rows) if rows
        else "<p>No vulnerabilities found in the scanned files.</p>",
    )
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(doc)


def write_sarif_report(findings, out_file, scan_id, path_by_object=None):
    """SARIF 2.1.0 for GitHub code scanning upload."""
    path_by_object = path_by_object or {}
    sarif_level = {  # SARIF has only error/warning/note
        "CRITICAL": "error", "HIGH": "error",
        "MEDIUM": "warning", "LOW": "note", "INFO": "note",
    }
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("finding_id") or f.get("issue_type") or "redrays-finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": (f.get("issue_type") or "RedRaysFinding").replace(" ", ""),
                "shortDescription": {"text": f.get("issue_title") or rule_id},
                "fullDescription": {"text": f.get("issue_description") or ""},
                "helpUri": "https://redrays.io",
                "properties": {"security-severity": _cvss_for(f.get("severity"))},
            }
        try:
            line = int(str(f.get("line_number") or "1").strip() or "1")
        except ValueError:
            line = 1
        # Point the annotation at the REAL scanned file (repo-relative POSIX path) so GitHub
        # code-scanning attaches the alert to the actual source line, not a phantom "<name>.abap".
        real_path = path_by_object.get(f.get("object_name"))
        if real_path:
            uri = real_path.replace("\\", "/")
            if uri.startswith("./"):
                uri = uri[2:]
        else:
            uri = (f.get("object_name") or "unknown") + ".abap"
        results.append({
            "ruleId": rule_id,
            "level": sarif_level.get((f.get("severity") or "").upper(), "warning"),
            "message": {"text": "%s: %s" % (
                f.get("issue_title", ""), f.get("issue_description", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(line, 1)},
                }
            }],
            "properties": {"severity": f.get("severity", ""),
                           "scan_id": scan_id, "status": f.get("status", "")},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RedRays ABAP Security Scanner",
                "informationUri": "https://redrays.io",
                "version": "2.0.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def _cvss_for(sev):
    return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0",
            "LOW": "3.0", "INFO": "0.0"}.get((sev or "").upper(), "5.0")


def _severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


# ---------------------------------------------------------------------------
# GitHub output
# ---------------------------------------------------------------------------

def set_github_output(name, value):
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as fh:
        fh.write("%s=%s\n" % (name, value))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="RedRays ABAP Security Scanner (MC /agent/v1 client)")
    # NOTE: token is intentionally NOT a CLI arg. It is read from REDRAYS_TOKEN.
    parser.add_argument("--api-url", default=DEFAULT_API_BASE,
                        help="MC /agent/v1 base URL")
    parser.add_argument("--scan-dir", default=".")
    parser.add_argument("--files", default="")
    parser.add_argument("--output-format", default="html",
                        choices=["csv", "html", "json", "sarif"])
    parser.add_argument("--output-file", default="")
    parser.add_argument("--fail-on-vulnerabilities", default="true")
    parser.add_argument("--threshold", default="",
                        help="critical|high|medium|low|informational")
    parser.add_argument("--scan-profile", default="CRITICAL_HIGH",
                        help="QUICK|FULL|CRITICAL|CRITICAL_HIGH")
    args = parser.parse_args()

    token = os.environ.get("REDRAYS_TOKEN", "").strip()
    if not token:
        print("ERROR: REDRAYS_TOKEN environment variable is not set.", file=sys.stderr)
        sys.exit(2)

    base = args.api_url.rstrip("/")
    out_file = args.output_file.strip()
    if not out_file:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "html" if args.output_format == "html" else args.output_format
        out_file = "redrays_scan_report_%s.%s" % (stamp, ext)

    try:
        # 1. Verify token (GET /me)
        dev = verify_token(base, token)
        print("Authenticated as: %s" % dev)

        # 2. Collect ABAP source
        programs = collect_programs(args.files, args.scan_dir)
        if not programs:
            print("No .abap files found to scan.")
            _emit_empty(out_file, args, dev_scan_id="")
            sys.exit(0)
        if len(programs) > MAX_BATCH:
            print("ERROR: %d objects exceed contract batch max of %d. "
                  "Split the scan into multiple runs." % (len(programs), MAX_BATCH),
                  file=sys.stderr)
            sys.exit(2)

        submit_programs = [
            {k: v for k, v in p.items() if not k.startswith("_")} for p in programs
        ]
        print("Submitting %d ABAP object(s) (profile=%s)..."
              % (len(submit_programs), args.scan_profile))

        # 3. Submit batch (POST /scan-batch)
        scan_id = submit_batch(base, token, submit_programs, args.scan_profile)
        print("Scan submitted. scan_id=%s" % scan_id)

        # 4. Poll (GET /scan-result/{scanId})
        poll_result(base, token, scan_id)

        # 5. Collect findings (GET /findings?scan_id=)
        findings = get_findings(base, token, scan_id)
        print("Scan COMPLETED. %d finding(s)." % len(findings))

    except ScanError as ex:
        print("ERROR: %s" % ex, file=sys.stderr)
        sys.exit(2)

    # 6. Write report
    # object_name -> real local path, so SARIF annotations land on the actual repo file.
    path_by_object = {p["objectName"]: p["_path"] for p in programs}
    fmt = args.output_format
    if fmt == "json":
        write_json_report(findings, out_file, scan_id, len(programs))
    elif fmt == "csv":
        write_csv_report(findings, out_file)
    elif fmt == "sarif":
        write_sarif_report(findings, out_file, scan_id, path_by_object)
    else:
        write_html_report(findings, out_file, scan_id, len(programs))
    print("Report written to %s" % out_file)

    # 7. Gate
    vuln_count = len(findings)
    breached = threshold_breached(findings, args.threshold)
    fail_on_vulns = str(args.fail_on_vulnerabilities).lower() == "true"

    # Consolidated exit logic (single owner: this script)
    if args.threshold:
        should_fail = breached
    else:
        should_fail = fail_on_vulns and vuln_count > 0
        breached = should_fail  # report the effective gate result

    # 8. GitHub outputs
    set_github_output("report-path", out_file)
    set_github_output("vulnerabilities-found", str(vuln_count))
    set_github_output("threshold-breached", "true" if breached else "false")
    set_github_output("scan-id", scan_id)

    counts = _severity_counts(findings)
    print("Summary: total=%d CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d" % (
        vuln_count, counts["CRITICAL"], counts["HIGH"],
        counts["MEDIUM"], counts["LOW"], counts["INFO"]))

    if should_fail:
        reason = ("threshold '%s' breached" % args.threshold
                  if args.threshold else "vulnerabilities found")
        print("::error::RedRays scan gate failed: %s" % reason)
        sys.exit(1)

    if args.threshold and vuln_count > 0:
        print("::warning::%d vulnerability(ies) found but below threshold '%s'."
              % (vuln_count, args.threshold))
    sys.exit(0)


def _emit_empty(out_file, args, dev_scan_id):
    fmt = args.output_format
    if fmt == "json":
        write_json_report([], out_file, dev_scan_id, 0)
    elif fmt == "csv":
        write_csv_report([], out_file)
    elif fmt == "sarif":
        write_sarif_report([], out_file, dev_scan_id)
    else:
        write_html_report([], out_file, dev_scan_id, 0)
    set_github_output("report-path", out_file)
    set_github_output("vulnerabilities-found", "0")
    set_github_output("threshold-breached", "false")
    set_github_output("scan-id", dev_scan_id)


if __name__ == "__main__":
    main()

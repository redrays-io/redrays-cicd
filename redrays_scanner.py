#!/usr/bin/env python3
"""
RedRays ABAP Security Scanner

A self-contained script for scanning ABAP code for security vulnerabilities
using the RedRays API. This script checks for required dependencies, installs
them if needed, and performs security scanning of ABAP files.

Usage:
    python redrays_scanner.py --api-key YOUR_API_KEY [options]

Examples:
    # Scan all ABAP files in current directory:
    python redrays_scanner.py --api-key YOUR_API_KEY --scan-dir .

    # Scan specific files:
    python redrays_scanner.py --api-key YOUR_API_KEY --files file1.abap,file2.abap

    # Change output format:
    python redrays_scanner.py --api-key YOUR_API_KEY --scan-dir . --output-format csv

    # Set severity threshold:
    python redrays_scanner.py --api-key YOUR_API_KEY --scan-dir . --threshold high
"""

import argparse
import csv
import io
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("redrays-scanner")

# Required packages
REQUIRED_PACKAGES = ['requests']

# Define severity levels with numerical values for comparison
SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0
}


def check_dependencies():
    """Check if required packages are installed and install them if needed"""
    missing_packages = []
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        logger.info(f"Installing required packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            logger.info("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            sys.exit(1)


# Install dependencies before importing them
check_dependencies()

# Now import the required packages
import requests


class RedRaysScanner:
    """
    ABAP code security scanner using RedRays API
    """

    def __init__(self, api_key: str, api_url: str = "https://api.redrays.io/api/scan"):
        """
        Initialize the scanner with API credentials

        Args:
            api_key: RedRays API key
            api_url: RedRays API URL (default: https://api.redrays.io/api/scan)
        """
        self.api_key = api_key
        self.api_url = api_url
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key
        }

    def scan_code(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan ABAP code using RedRays API

        Args:
            code: ABAP code to scan
            file_path: Path of the file (optional)

        Returns:
            Dict containing scan results
        """
        payload = {"code": code}
        if file_path:
            payload["file_path"] = file_path

        try:
            logger.info(f"[ScanCode] Scanning file: {file_path or 'unnamed'}")
            response = requests.post(self.api_url, json=payload, headers=self.headers)

            # Check for API rate limits
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', '30'))
                logger.warning(f"API rate limit reached. Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                return self.scan_code(code, file_path)  # Retry the request

            # Handle 400 errors more gracefully - could be due to no credits left
            if response.status_code == 400:
                error_message = "Bad Request"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_message = error_data["message"]
                    elif "error" in error_data:
                        error_message = error_data["error"]
                except:
                    pass

                # Check for specific error messages about credits
                if "credit" in error_message.lower() or "subscription" in error_message.lower():
                    logger.error(f"API error: You do not have enough credits. Please check your RedRays subscription.")
                    exit(1)
                else:
                    logger.error(f"API error: {error_message}")

                return {
                    "success": False,
                    "error": error_message,
                    "data": None,
                    "scan_result": [{"title": "API Error", "severity": "Unknown", "description": error_message}]
                }

            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            error_message = str(e)
            if hasattr(e, 'response') and e.response:
                try:
                    error_data = e.response.json()
                    if "message" in error_data:
                        error_message = error_data["message"]
                    elif "error" in error_data:
                        error_message = error_data["error"]
                except:
                    error_message = f"{e.response.status_code} - {e.response.text}"

            logger.error(f"API error: {error_message}")
            return {
                "success": False,
                "error": error_message,
                "data": None,
                "scan_result": [{"title": "API Error", "severity": "Unknown", "description": error_message}]
            }


class ReportGenerator:
    """
    Generates vulnerability reports in various formats
    """

    @staticmethod
    def generate_report(scan_results: List[Dict[str, Any]], output_format: str,
                        output_file: Optional[str] = None) -> str:
        """
        Generate a report from scan results

        Args:
            scan_results: List of scan results
            output_format: Report format ('csv', 'html', or 'json')
            output_file: Output file path (optional)

        Returns:
            Path to the generated report, or report content if no output file specified
        """
        if output_format.lower() == 'csv':
            return ReportGenerator._generate_csv_report(scan_results, output_file)
        elif output_format.lower() == 'html':
            return ReportGenerator._generate_html_report(scan_results, output_file)
        elif output_format.lower() == 'json':
            return ReportGenerator._generate_json_report(scan_results, output_file)
        else:
            logger.error(f"Unsupported output format: {output_format}")
            return ""

    @staticmethod
    def _generate_csv_report(scan_results: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
        """
        Generate a CSV report from scan results

        Args:
            scan_results: List of scan results
            output_file: Output file path (optional)

        Returns:
            Path to the generated report, or report content if no output file specified
        """
        # Prepare data for CSV
        all_vulnerabilities = []

        for result in scan_results:
            file_path = result.get("file_path", "Unknown")
            scan_guid = result.get("scan_guid", "")

            # Get vulnerabilities from scan_result
            vulnerabilities = result.get("vulnerabilities", [])
            if not vulnerabilities and "scan_result" in result:
                # Try to extract vulnerabilities from scan_result if it's a string
                if isinstance(result["scan_result"], str):
                    try:
                        scan_result = json.loads(result["scan_result"])
                        vulnerabilities = scan_result if isinstance(scan_result, list) else []
                    except json.JSONDecodeError:
                        vulnerabilities = []
                # If scan_result is already a list
                elif isinstance(result["scan_result"], list):
                    vulnerabilities = result["scan_result"]

            # Add vulnerabilities to the master list
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    # Handle dictionary object
                    all_vulnerabilities.append({
                        "File Path": file_path,
                        "Scan GUID": scan_guid,
                        "Title": vuln.get("title", ""),
                        "Severity": vuln.get("severity", "Unknown"),
                        "Description": vuln.get("description", ""),
                        "Program": vuln.get("about_program", "")
                    })
                elif isinstance(vuln, str):
                    # Handle string (might be a raw message or error)
                    all_vulnerabilities.append({
                        "File Path": file_path,
                        "Scan GUID": scan_guid,
                        "Title": "Unknown",
                        "Severity": "Unknown",
                        "Description": vuln,
                        "Program": ""
                    })

        # If no vulnerabilities were found
        if not all_vulnerabilities:
            empty_report = "No vulnerabilities found in the scanned files."
            if output_file:
                with open(output_file, 'w', newline='') as f:
                    f.write(empty_report)
                return output_file
            return empty_report

        # Generate CSV
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=all_vulnerabilities[0].keys())
                writer.writeheader()
                writer.writerows(all_vulnerabilities)
            return output_file
        else:
            # Return as string if no output file specified
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=all_vulnerabilities[0].keys())
            writer.writeheader()
            writer.writerows(all_vulnerabilities)
            return output.getvalue()

    @staticmethod
    def _generate_html_report(scan_results: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report from scan results

        Args:
            scan_results: List of scan results
            output_file: Output file path (optional)

        Returns:
            Path to the generated report, or report content if no output file specified
        """
        # Prepare data for HTML
        all_vulnerabilities = []

        for result in scan_results:
            file_path = result.get("file_path", "Unknown")
            scan_guid = result.get("scan_guid", "")

            # Get vulnerabilities from scan_result
            vulnerabilities = result.get("vulnerabilities", [])
            if not vulnerabilities and "scan_result" in result:
                # Try to extract vulnerabilities from scan_result if it's a string
                if isinstance(result["scan_result"], str):
                    try:
                        scan_result = json.loads(result["scan_result"])
                        vulnerabilities = scan_result if isinstance(scan_result, list) else []
                    except json.JSONDecodeError:
                        vulnerabilities = [result["scan_result"]]  # Use the string as a single vulnerability
                # If scan_result is already a list
                elif isinstance(result["scan_result"], list):
                    vulnerabilities = result["scan_result"]

            # Add vulnerabilities to the master list
            for vuln in vulnerabilities:
                vuln_data = {}
                if vuln.get("severity", "Unknown") == "Unknown":
                    continue
                if isinstance(vuln, dict):
                    # Handle dictionary objects
                    vuln_data = {
                        "file_path": file_path,
                        "scan_guid": scan_guid,
                        "title": vuln.get("title", ""),
                        "severity": vuln.get("severity", "Unknown"),
                        "description": vuln.get("description", ""),
                        "about_program": vuln.get("about_program", ""),
                        "dataflow": vuln.get("dataflow_of_vulnerable_parameter", "")
                    }
                else:
                    # Handle string or other non-dictionary values
                    vuln_data = {
                        "file_path": file_path,
                        "scan_guid": scan_guid,
                        "title": "Unknown Issue",
                        "severity": "Unknown",
                        "description": str(vuln) if vuln else "",
                        "about_program": "",
                        "dataflow": ""
                    }

                all_vulnerabilities.append(vuln_data)

        # Generate HTML
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RedRays ABAP Security Scan Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                h1 {
                    color: #2c3e50;
                    text-align: center;
                    margin-bottom: 30px;
                }
                .summary {
                    background-color: #f8f9fa;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 30px;
                }
                .vulnerability-card {
                    background-color: white;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .vulnerability-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                .vulnerability-title {
                    font-size: 18px;
                    font-weight: bold;
                    margin: 0;
                }
                .vulnerability-severity {
                    padding: 5px 10px;
                    border-radius: 3px;
                    font-weight: bold;
                    color: white;
                }
                .severity-critical {
                    background-color: #d32f2f;
                }
                .severity-high {
                    background-color: #f44336;
                }
                .severity-medium {
                    background-color: #ff9800;
                }
                .severity-low {
                    background-color: #4caf50;
                }
                .severity-informational {
                    background-color: #2196f3;
                }
                .severity-unknown {
                    background-color: #9e9e9e;
                }
                .file-path {
                    font-family: monospace;
                    background-color: #f5f5f5;
                    padding: 3px 6px;
                    border-radius: 3px;
                    margin-top: 5px;
                    display: inline-block;
                }
                .details-block {
                    margin-top: 15px;
                }
                .details-title {
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                .dataflow {
                    font-family: monospace;
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 3px;
                    white-space: pre-wrap;
                    overflow-x: auto;
                    border: 1px solid #ddd;
                }
                .no-vulnerabilities {
                    text-align: center;
                    padding: 50px;
                    background-color: #f8f9fa;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                }
                th {
                    background-color: #f2f2f2;
                    text-align: left;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
            </style>
        </head>
        <body>
            <h1>RedRays ABAP Security Scan Report</h1>

            <div class="summary">
                <h2>Scan Summary</h2>
                <p>Date: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                <p>Files Scanned: """ + str(len(scan_results)) + """</p>
                <p>Vulnerabilities Found: """ + str(len(all_vulnerabilities)) + """</p>

                <h3>Severity Breakdown</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
        """

        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in all_vulnerabilities:
            severity = vuln["severity"].lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Add severity breakdown to HTML
        for severity, count in severity_counts.items():
            html_content += f"<tr><td>{severity.capitalize()}</td><td>{count}</td></tr>"

        html_content += """
                </table>
            </div>
        """

        # If no vulnerabilities were found
        if not all_vulnerabilities:
            html_content += """
            <div class="no-vulnerabilities">
                <h2>No vulnerabilities found in the scanned files.</h2>
                <p>Your ABAP code appears to be secure according to the RedRays security analysis.</p>
            </div>
            """
        else:
            # Add vulnerabilities to HTML
            html_content += "<h2>Vulnerability Details</h2>"

            for vuln in all_vulnerabilities:
                severity_class = f"severity-{vuln['severity'].lower()}" if vuln['severity'].lower() in ["critical",
                                                                                                        "high",
                                                                                                        "medium", "low",
                                                                                                        "informational"] else "severity-unknown"
                if severity_class == "severity-unknown":
                    continue
                html_content += f"""
                <div class="vulnerability-card">
                    <div class="vulnerability-header">
                        <h3 class="vulnerability-title">{vuln['title']}</h3>
                        <span class="vulnerability-severity {severity_class}">{vuln['severity']}</span>
                    </div>
                    <div class="file-path">{vuln['file_path']}</div>

                    <div class="details-block">
                        <div class="details-title">Description</div>
                        <p>{vuln['description']}</p>
                    </div>
                """

                if vuln['about_program']:
                    html_content += f"""
                    <div class="details-block">
                        <div class="details-title">About Program</div>
                        <p>{vuln['about_program']}</p>
                    </div>
                    """

                if vuln['dataflow']:
                    # Replace <br> tags with newlines for better display
                    dataflow = vuln['dataflow'].replace("<br>", "\n")
                    html_content += f"""
                    <div class="details-block">
                        <div class="details-title">Data Flow</div>
                        <div class="dataflow">{dataflow}</div>
                    </div>
                    """

                html_content += "</div>"

        html_content += """
        </body>
        </html>
        """

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_file
        else:
            return html_content

    @staticmethod
    def _generate_json_report(scan_results: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
        """
        Generate a JSON report from scan results

        Args:
            scan_results: List of scan results
            output_file: Output file path (optional)

        Returns:
            Path to the generated report, or report content if no output file specified
        """
        # Create the JSON structure
        report = {
            "report_date": datetime.now().isoformat(),
            "files_scanned": len(scan_results),
            "scan_results": scan_results
        }

        json_content = json.dumps(report, indent=2)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_content)
            return output_file
        else:
            return json_content


def find_abap_files(directory: str) -> List[str]:
    """
    Find all ABAP files in a directory and its subdirectories

    Args:
        directory: Directory to search in

    Returns:
        List of ABAP file paths
    """
    abap_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.abap'):
                abap_files.append(os.path.join(root, file))
    return abap_files


def check_threshold_breach(vulnerabilities: List[Dict[str, Any]], threshold: str) -> bool:
    """
    Check if any vulnerability exceeds the threshold severity

    Args:
        vulnerabilities: List of vulnerabilities
        threshold: Severity threshold (critical, high, medium, low, or informational)

    Returns:
        True if threshold is breached, False otherwise
    """
    if not threshold or threshold.lower() not in SEVERITY_LEVELS:
        return False

    threshold_value = SEVERITY_LEVELS[threshold.lower()]

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        if severity in SEVERITY_LEVELS and SEVERITY_LEVELS[severity] >= threshold_value:
            return True

    return False


def extract_all_vulnerabilities(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract all vulnerabilities from scan results

    Args:
        scan_results: List of scan results

    Returns:
        List of all vulnerabilities
    """
    all_vulnerabilities = []

    for result in scan_results:
        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities and "scan_result" in result:
            if isinstance(result["scan_result"], str):
                try:
                    scan_result = json.loads(result["scan_result"])
                    vulnerabilities = scan_result if isinstance(scan_result, list) else []
                except json.JSONDecodeError:
                    vulnerabilities = []
            elif isinstance(result["scan_result"], list):
                vulnerabilities = result["scan_result"]

        all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities


def main():
    """Main function to run the scanner"""
    parser = argparse.ArgumentParser(description='RedRays ABAP Security Scanner')
    parser.add_argument('--api-key', required=True, help='RedRays API key')
    parser.add_argument('--api-url', default='https://api.redrays.io/api/scan', help='RedRays API URL')
    parser.add_argument('--files', help='Comma-separated list of files to scan')
    parser.add_argument('--scan-dir', help='Directory containing ABAP files to scan')
    parser.add_argument('--output-format', default='html', choices=['csv', 'html', 'json'], help='Report output format')
    parser.add_argument('--output-file', help='Report output file path')
    parser.add_argument('--threshold',
                        choices=['critical', 'high', 'medium', 'low', 'informational'],
                        help='Severity threshold for failing the build (critical, high, medium, low, informational)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize scanner
    scanner = RedRaysScanner(args.api_key, args.api_url)

    # Determine output file if not specified
    if not args.output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_file = f"redrays_scan_report_{timestamp}.{args.output_format}"

    # Initialize scan results list
    scan_results = []

    # If specific files are provided via --files argument
    if args.files:
        logger.info(f"Manual file scanning mode detected")
        file_paths = [f.strip() for f in args.files.split(',')]

        for file_path in file_paths:
            if not file_path.lower().endswith('.abap'):
                logger.warning(f"Skipping non-ABAP file: {file_path}")
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()

                logger.info(f"[Files] Scanning file: {file_path}")
                result = scanner.scan_code(code, file_path)

                # Format the result for reporting
                formatted_result = {
                    "file_path": file_path,
                    "scan_guid": result.get("data", {}).get("scan_guid", "") if result.get("data") else "",
                    "vulnerabilities": []
                }

                # Extract vulnerabilities from the scan result
                if "data" in result and result.get("data"):
                    scan_result = result["data"].get("scan_result", [])

                    # If scan_result is a string (JSON), parse it
                    if isinstance(scan_result, str):
                        try:
                            scan_result = json.loads(scan_result)
                        except json.JSONDecodeError:
                            scan_result = []

                    formatted_result["vulnerabilities"] = scan_result
                    formatted_result["scan_result"] = scan_result
                elif "scan_result" in result:
                    # For error cases where we've embedded scan_result directly
                    formatted_result["vulnerabilities"] = result["scan_result"]
                    formatted_result["scan_result"] = result["scan_result"]

                scan_results.append(formatted_result)

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {str(e)}")

    # If a directory is provided via --scan-dir argument
    elif args.scan_dir:
        logger.info(f"Directory scanning mode detected: {args.scan_dir}")

        if not os.path.isdir(args.scan_dir):
            logger.error(f"Directory not found: {args.scan_dir}")
            sys.exit(1)

        # Find all ABAP files in the directory
        abap_files = find_abap_files(args.scan_dir)

        logger.info(f"Found {len(abap_files)} ABAP files to scan")

        for file_path in abap_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()

                logger.info(f"[ScanDir] Scanning file: {file_path}")
                result = scanner.scan_code(code, file_path)

                # Format the result for reporting
                formatted_result = {
                    "file_path": file_path,
                    "scan_guid": result.get("data", {}).get("scan_guid", "") if result.get("data") else "",
                    "vulnerabilities": []
                }

                # Extract vulnerabilities from the scan result
                if "data" in result and result.get("data"):
                    scan_result = result["data"].get("scan_result", [])

                    # If scan_result is a string (JSON), parse it
                    if isinstance(scan_result, str):
                        try:
                            scan_result = json.loads(scan_result)
                        except json.JSONDecodeError:
                            scan_result = []

                    formatted_result["vulnerabilities"] = scan_result
                    formatted_result["scan_result"] = scan_result
                elif "scan_result" in result:
                    # For error cases where we've embedded scan_result directly
                    formatted_result["vulnerabilities"] = result["scan_result"]
                    formatted_result["scan_result"] = result["scan_result"]

                scan_results.append(formatted_result)

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {str(e)}")

    else:
        logger.error("No scan mode specified. Please use --files or --scan-dir.")
        parser.print_help()
        sys.exit(1)

    # No files scanned - now displays a warning instead of an error
    if not scan_results:
        logger.warning("No files were scanned. No report will be generated.")
        sys.exit(0)  # Exit with success code instead of error

    # Generate report
    logger.info(f"Generating {args.output_format} report: {args.output_file}")
    report_path = ReportGenerator.generate_report(
        scan_results, args.output_format, args.output_file
    )

    # Extract all vulnerabilities for threshold checking
    all_vulnerabilities = extract_all_vulnerabilities(scan_results)
    vulnerability_count = len(all_vulnerabilities)

    # Check if threshold is breached
    threshold_breached = args.threshold and check_threshold_breach(all_vulnerabilities, args.threshold)

    if vulnerability_count > 0:
        if threshold_breached:
            logger.error(
                f"Found {vulnerability_count} vulnerabilities with {args.threshold} or higher severity. See report at: {report_path}")
            sys.exit(1)  # Exit with error if threshold is breached
        else:
            if args.threshold:
                pass
                #logger.warning(
                #    f"Found {vulnerability_count} vulnerabilities, but none exceed the {args.threshold} threshold. See report at: {report_path}")
            else:
                logger.warning(f"Found {vulnerability_count} vulnerabilities. See report at: {report_path}")
            sys.exit(0)  # Permit build to continue if no threshold breach
    else:
        logger.info("No vulnerabilities found in the scanned files.")
        sys.exit(0)


if __name__ == "__main__":
    main()

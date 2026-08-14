"""
scanner.py — Trivy wrapper for CVE scanning.

How it works:
  - Runs `trivy fs` on a cloned repo directory.
  - Parses the JSON output to extract vulnerability details.
  - Returns a summary: total CVEs, breakdown by severity, and top findings.
"""

import json
import subprocess
from dataclasses import dataclass, field


@dataclass
class VulnSummary:
    """Summary of vulnerabilities found in a repo."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings: list[dict] = field(default_factory=list)
    scan_error: str | None = None


def run_trivy_scan(repo_path: str) -> VulnSummary:
    """
    Run Trivy filesystem scan on a cloned repo and parse results.

    Args:
        repo_path: Path to the cloned repository directory.

    Returns:
        VulnSummary with counts and details of vulnerabilities found.
    """
    summary = VulnSummary()

    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--scanners", "vuln",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--quiet",
        repo_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout per repo
        )
    except subprocess.TimeoutExpired:
        summary.scan_error = "Trivy scan timed out (5 min limit)"
        return summary
    except FileNotFoundError:
        summary.scan_error = "Trivy not found — is it installed?"
        return summary

    if result.returncode != 0 and not result.stdout:
        summary.scan_error = f"Trivy error: {result.stderr.strip()[:200]}"
        return summary

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        summary.scan_error = "Failed to parse Trivy JSON output"
        return summary

    # Trivy JSON structure: {"Results": [{"Vulnerabilities": [...]}]}
    results = data.get("Results", [])

    for target in results:
        vulns = target.get("Vulnerabilities") or []
        target_name = target.get("Target", "unknown")

        for vuln in vulns:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            finding = {
                "id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": vuln.get("FixedVersion", "N/A"),
                "severity": severity,
                "target": target_name,
                "title": vuln.get("Title", ""),
            }

            summary.findings.append(finding)
            summary.total += 1

            if severity == "CRITICAL":
                summary.critical += 1
            elif severity == "HIGH":
                summary.high += 1
            elif severity == "MEDIUM":
                summary.medium += 1
            elif severity == "LOW":
                summary.low += 1

    return summary


def format_severity_line(summary: VulnSummary) -> str:
    """
    Return a short human-readable severity string like '3 CRIT, 5 HIGH, 2 MED'.

    Used for the console table output.
    """
    if summary.scan_error:
        return f"ERROR: {summary.scan_error[:40]}"

    if summary.total == 0:
        return "clean"

    parts = []
    if summary.critical:
        parts.append(f"{summary.critical} CRIT")
    if summary.high:
        parts.append(f"{summary.high} HIGH")
    if summary.medium:
        parts.append(f"{summary.medium} MED")
    if summary.low:
        parts.append(f"{summary.low} LOW")

    return ", ".join(parts)

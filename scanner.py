"""
scanner.py — Vulnerability scanning with Trivy and OSV-Scanner fallback.

How it works:
  - Primary: Runs `trivy fs` on a cloned repo (full transitive resolution).
  - Fallback: If Maven Central returns 429, uses `osv-scanner` instead
    (no network calls to Maven, scans declared deps only).
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
    scanner_used: str = "trivy"  # "trivy" or "osv-scanner"
    coverage: str = "full"  # "full" (trivy) or "direct-only" (osv without resolve)


def _is_maven_rate_limit(stderr: str) -> bool:
    """Check if the Trivy error is a Maven Central 429 rate limit."""
    return "429 Too Many Requests" in stderr and "maven" in stderr.lower()


def run_trivy_scan(repo_path: str) -> VulnSummary:
    """
    Run Trivy filesystem scan on a cloned repo and parse results.

    If Maven Central returns a 429 rate limit error, marks the scan_error
    as "maven_rate_limit" so the caller can fall back to osv-scanner.

    Args:
        repo_path: Path to the cloned repository directory.

    Returns:
        VulnSummary with counts and details of vulnerabilities found.
    """
    summary = VulnSummary(scanner_used="trivy")

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
        summary.scan_error = "Trivy not found -- is it installed?"
        return summary

    # Check for Maven 429 rate limit
    if result.returncode != 0 and _is_maven_rate_limit(result.stderr):
        summary.scan_error = "maven_rate_limit"
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
    _parse_trivy_results(summary, data)
    return summary


def run_osv_scan(repo_path: str) -> VulnSummary:
    """
    Run osv-scanner on a cloned repo as a fallback (no Maven Central calls).

    Uses --no-resolve to avoid hitting Maven Central for dependency resolution.
    Scans only declared dependencies in pom.xml/build.gradle files.

    Args:
        repo_path: Path to the cloned repository directory.

    Returns:
        VulnSummary with counts and details of vulnerabilities found.
    """
    summary = VulnSummary(scanner_used="osv-scanner", coverage="direct-only")

    cmd = [
        "osv-scanner", "scan", "source",
        "--format", "json",
        "--no-resolve",
        "-r",
        "--verbosity", "error",
        repo_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        summary.scan_error = "OSV scan timed out (2 min limit)"
        return summary
    except FileNotFoundError:
        summary.scan_error = "osv-scanner not found -- is it installed?"
        return summary

    # osv-scanner returns exit code 1 when vulns are found (not an error)
    if result.returncode not in (0, 1):
        summary.scan_error = f"OSV error: {result.stderr.strip()[:200]}"
        return summary

    if not result.stdout.strip():
        # No output = no vulnerabilities found
        return summary

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        summary.scan_error = "Failed to parse OSV-Scanner JSON output"
        return summary

    # OSV-Scanner JSON structure:
    # {"results": [{"source": {...}, "packages": [{"package": {...}, "groups": [...]}]}]}
    _parse_osv_results(summary, data)
    return summary


def _parse_trivy_results(summary: VulnSummary, data: dict) -> None:
    """Parse Trivy JSON output into VulnSummary."""
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
            _increment_severity(summary, severity)


def _parse_osv_results(summary: VulnSummary, data: dict) -> None:
    """Parse OSV-Scanner JSON output into VulnSummary."""
    results = data.get("results", [])

    for source in results:
        source_path = source.get("source", {}).get("path", "unknown")
        packages = source.get("packages", [])

        for pkg_entry in packages:
            pkg_info = pkg_entry.get("package", {})
            pkg_name = pkg_info.get("name", "unknown")
            pkg_version = pkg_info.get("version", "N/A")

            groups = pkg_entry.get("groups", [])
            for group in groups:
                # Each group is a set of related advisories for one vuln
                ids = group.get("ids", [])
                aliases = group.get("aliases", [])
                max_severity = group.get("max_severity", "")

                # Pick the best ID (prefer CVE over GHSA)
                vuln_id = _pick_best_id(ids, aliases)
                severity = _osv_severity_to_level(max_severity)

                finding = {
                    "id": vuln_id,
                    "package": pkg_name,
                    "installed_version": pkg_version,
                    "fixed_version": "N/A",
                    "severity": severity,
                    "target": source_path,
                    "title": "",
                }

                summary.findings.append(finding)
                summary.total += 1
                _increment_severity(summary, severity)


def _pick_best_id(ids: list[str], aliases: list[str]) -> str:
    """Pick the most useful vulnerability ID (prefer CVE over GHSA)."""
    all_ids = ids + aliases
    for vid in all_ids:
        if vid.startswith("CVE-"):
            return vid
    return all_ids[0] if all_ids else "N/A"


def _osv_severity_to_level(max_severity: str) -> str:
    """
    Convert OSV numeric CVSS score to severity level.

    OSV provides max_severity as a string like "9.8", "7.5", etc.
    """
    try:
        score = float(max_severity)
    except (ValueError, TypeError):
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _increment_severity(summary: VulnSummary, severity: str) -> None:
    """Increment the appropriate severity counter."""
    if severity == "CRITICAL":
        summary.critical += 1
    elif severity == "HIGH":
        summary.high += 1
    elif severity == "MEDIUM":
        summary.medium += 1
    elif severity == "LOW":
        summary.low += 1



def analyse_fixability(findings: list[dict]) -> dict:
    """
    Analyse vulnerability findings to produce a fixability summary.

    Groups CVEs by package, classifies upgrades as patch/minor/major,
    and identifies the best bang-for-buck upgrades (most CVEs per bump).

    Returns a dict with:
        fixable: count of CVEs with a known fixed version
        unfixable: count of CVEs with no fix available
        fixable_by_severity: breakdown of fixable CVEs by severity
        patch_bumps: count fixable by a patch version bump (x.y.Z)
        minor_bumps: count fixable by a minor version bump (x.Y.z)
        major_bumps: count fixable by a major version bump (X.y.z)
        unknown_bumps: count fixable but version comparison unclear
        best_upgrades: top upgrades ranked by CVEs fixed per bump (max 5)
    """
    if not findings:
        return {
            "fixable": 0,
            "unfixable": 0,
            "fixable_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "patch_bumps": 0,
            "minor_bumps": 0,
            "major_bumps": 0,
            "unknown_bumps": 0,
            "best_upgrades": [],
        }

    fixable = 0
    unfixable = 0
    fixable_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    patch_bumps = 0
    minor_bumps = 0
    major_bumps = 0
    unknown_bumps = 0

    # Group by (package, installed_version, fixed_version) to find multi-CVE upgrades
    upgrade_groups: dict[tuple[str, str, str], list[dict]] = {}

    for f in findings:
        fixed = f.get("fixed_version", "N/A")

        if not fixed or fixed == "N/A" or fixed == "":
            unfixable += 1
            continue

        fixable += 1
        severity = f.get("severity", "UNKNOWN").upper()
        if severity in fixable_by_severity:
            fixable_by_severity[severity] += 1

        installed = f.get("installed_version", "N/A")
        # Use first listed version when multiple are available
        fixed_first = fixed.split(",")[0].strip()
        bump_type = _classify_bump(installed, fixed_first)

        if bump_type == "patch":
            patch_bumps += 1
        elif bump_type == "minor":
            minor_bumps += 1
        elif bump_type == "major":
            major_bumps += 1
        else:
            unknown_bumps += 1

        # Group for best-upgrade calculation
        pkg = f.get("package", "unknown")
        key = (pkg, installed, fixed_first)
        if key not in upgrade_groups:
            upgrade_groups[key] = []
        upgrade_groups[key].append(f)

    # Find best upgrades: most CVEs fixed per single version bump
    best_upgrades = []
    for (pkg, installed, fixed), cves in sorted(
        upgrade_groups.items(), key=lambda x: len(x[1]), reverse=True
    )[:5]:
        severities = [c.get("severity", "UNKNOWN") for c in cves]
        best_upgrades.append({
            "package": pkg,
            "from": installed,
            "to": fixed,
            "cves_fixed": len(cves),
            "bump_type": _classify_bump(installed, fixed),
            "severities": severities,
        })

    return {
        "fixable": fixable,
        "unfixable": unfixable,
        "fixable_by_severity": fixable_by_severity,
        "patch_bumps": patch_bumps,
        "minor_bumps": minor_bumps,
        "major_bumps": major_bumps,
        "unknown_bumps": unknown_bumps,
        "best_upgrades": best_upgrades,
    }


def _classify_bump(installed: str, fixed: str) -> str:
    """
    Classify a version bump as patch, minor, or major.

    Compares semver-style versions. Returns 'unknown' if versions
    can't be parsed.
    """
    installed_parts = _parse_version(installed)
    fixed_parts = _parse_version(fixed)

    if not installed_parts or not fixed_parts:
        return "unknown"

    if fixed_parts[0] != installed_parts[0]:
        return "major"
    elif fixed_parts[1] != installed_parts[1]:
        return "minor"
    else:
        return "patch"


def _parse_version(version: str) -> list[int] | None:
    """
    Parse a version string into [major, minor, patch].

    Handles formats like: 1.2.3, v1.2.3, 1.2.3-rc1, 1.2
    When multiple versions are listed (comma-separated), takes the first.
    Returns None if unparseable.
    """
    import re
    # Handle comma-separated versions (e.g., "5.0.8, 3.0.3, 1.1.17")
    version = version.split(",")[0].strip()
    # Strip leading 'v' and anything after a hyphen/plus (pre-release tags)
    version = version.lstrip("v")
    version = re.split(r"[-+]", version)[0]

    parts = version.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
        # Pad to 3 parts
        while len(nums) < 3:
            nums.append(0)
        return nums
    except (ValueError, IndexError):
        return None

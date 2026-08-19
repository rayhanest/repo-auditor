#!/usr/bin/env python3
"""
auditor.py — GitHub Repo Auditor CLI.

Main entry point that orchestrates the full audit pipeline:
  1. Parse the input .txt file for repo identifiers.
  2. For each repo (sequentially):
     a. Check cache — skip if recently scanned.
     b. Shallow-clone the repo to a temp directory.
     c. Detect package managers and languages.
     d. Run Trivy CVE scan on the clone.
     e. Query GitHub API for bots, community health, contributor openness.
     f. Clean up the clone.
     g. Cache the result.
  3. Print a summary table + write JSON report.

Usage:
    python3 auditor.py repos.txt
    python3 auditor.py repos.txt --no-cache
    python3 auditor.py repos.txt --clear-cache
    python3 auditor.py repos.txt --output report.json
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import cache
import detector
import github_api
import reporter
import scanner


def parse_repos_file(filepath: str) -> list[tuple[str, str]]:
    """
    Parse a .txt file into (owner, repo) tuples.

    Skips blank lines and lines starting with #.
    Accepts formats:
      - owner/repo
      - https://github.com/owner/repo
      - github.com/owner/repo
    """
    repos = []
    path = Path(filepath)

    if not path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    for line_num, line in enumerate(path.read_text().splitlines(), start=1):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Normalize URLs to owner/repo format
        if "github.com/" in line:
            # Extract owner/repo from URL
            parts = line.split("github.com/")[-1].strip("/").split("/")
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
            else:
                print(f"  WARNING: Line {line_num}: Could not parse '{line}', skipping")
                continue
        elif "/" in line:
            parts = line.split("/")
            if len(parts) == 2:
                owner, repo = parts
            else:
                print(f"  WARNING: Line {line_num}: Could not parse '{line}', skipping")
                continue
        else:
            print(f"  WARNING: Line {line_num}: Could not parse '{line}', skipping")
            continue

        # Strip .git suffix if present
        repo = repo.removesuffix(".git")
        repos.append((owner, repo))

    return repos


def clone_repo(owner: str, repo: str, dest: str) -> bool:
    """
    Shallow-clone a repo into the destination directory.

    Returns True on success, False on failure.
    """
    url = f"https://github.com/{owner}/{repo}.git"
    cmd = ["git", "clone", "--depth", "1", "--quiet", url, dest]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  WARNING: Clone timed out for {owner}/{repo}")
        return False
    except FileNotFoundError:
        print("  ERROR: git not found -- is it installed?")
        return False


def _check_gh_auth() -> bool:
    """
    Verify the GitHub CLI is installed and authenticated.

    Returns True if `gh auth status` succeeds, False otherwise.
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _assess_triage(result: dict) -> dict:
    """
    Final triage assessment: is this repo worth contributing CVE fixes to?

    Returns a dict with:
        "verdict": "yes" | "maybe" | "no"
        "reason": human-readable explanation of why
        "factors": dict of all inputs that fed the decision
    """
    vuln = result.get("vulnerabilities", {})
    openness = result.get("contributor_openness", {})
    bots = result.get("bots", {})
    community = result.get("community", {})

    factors = {
        "has_cves": vuln.get("total", 0) > 0,
        "cve_count": vuln.get("total", 0),
        "is_archived": openness.get("is_archived", False),
        "activity_level": community.get("activity_level", "unknown"),
        "is_open_to_contributions": openness.get("is_open_to_contributions", False),
        "has_dependency_bot": bots.get("has_dependency_bot", False),
        "bot_pr_responsiveness": bots.get("bot_pr_responsiveness", "unknown"),
        "external_prs_merged": openness.get("external_prs_merged", 0),
        "dep_prs_merged": openness.get("dep_prs_merged", 0),
        "dep_prs_closed": openness.get("dep_prs_closed", 0),
    }

    # --- Hard no's ---

    if not factors["has_cves"]:
        return {"verdict": "no", "reason": "No CVEs found — nothing to fix", "factors": factors}

    # Only worth contributing if there's at least one HIGH or CRITICAL
    if vuln.get("critical", 0) == 0 and vuln.get("high", 0) == 0:
        return {"verdict": "no", "reason": "No HIGH or CRITICAL CVEs — low priority", "factors": factors}

    if factors["is_archived"]:
        return {"verdict": "no", "reason": "Repo is archived — cannot accept PRs", "factors": factors}

    if factors["activity_level"] == "dormant":
        return {"verdict": "no", "reason": "Repo is dormant — no one to review a PR", "factors": factors}

    # Actively closing dep/CVE PRs = they don't want this kind of help
    # Require 2+ closed to avoid false negatives from author-abandoned PRs
    if factors["dep_prs_closed"] >= 2 and factors["dep_prs_merged"] == 0:
        return {"verdict": "no", "reason": f"{factors['dep_prs_closed']} dep/CVE PR(s) closed without merging — project rejects this work", "factors": factors}

    # --- Yes signals ---

    # Dep/CVE PRs merged + open to contributions
    if factors["dep_prs_merged"] > 0 and factors["is_open_to_contributions"]:
        reason = f"{factors['dep_prs_merged']} dep/CVE PR(s) merged recently + open to contributions"
        if factors["bot_pr_responsiveness"] == "active":
            reason += " (note: bot is also active — check for duplicates)"
        if factors["dep_prs_closed"] > 0:
            reason += f" (note: {factors['dep_prs_closed']} also closed — review carefully)"
        if factors["activity_level"] == "low":
            reason += " (note: low activity — reviews may be slow)"
        return {"verdict": "yes", "reason": reason, "factors": factors}

    # Open + no bot or bot ignored/backlogged
    if factors["is_open_to_contributions"]:
        if not factors["has_dependency_bot"] or factors["bot_pr_responsiveness"] in ("ignored", "backlogged", "unknown"):
            reason = "Open to contributions"
            if not factors["has_dependency_bot"]:
                reason += ", no dependency bot — manual bumps needed"
            elif factors["bot_pr_responsiveness"] == "ignored":
                reason += ", dependency bot PRs are being ignored"
            elif factors["bot_pr_responsiveness"] == "backlogged":
                reason += ", dependency bot PRs are backlogged — check for duplicates before submitting"
            else:
                reason += ", no dependency bot activity detected"
            if factors["activity_level"] == "low":
                reason += " (note: low activity — reviews may be slow)"
            return {"verdict": "yes", "reason": reason, "factors": factors}

    # --- Maybe signals ---

    # Bot is actively merging and no other positive signal pushed us to YES
    if factors["has_dependency_bot"] and factors["bot_pr_responsiveness"] == "active":
        return {"verdict": "maybe", "reason": "Dependency bot is actively merging — they have an established workflow, check for duplicates", "factors": factors}

    # Not open but merges dep PRs internally — they care, but haven't invited outsiders
    if factors["dep_prs_merged"] > 0 and not factors["is_open_to_contributions"]:
        return {"verdict": "maybe", "reason": f"{factors['dep_prs_merged']} dep/CVE PR(s) merged internally — they maintain dep health but haven't shown openness to external help", "factors": factors}

    # Not open, no dep PR signal either way
    return {"verdict": "maybe", "reason": "Not clearly open to contributions, but has CVEs worth fixing", "factors": factors}


def audit_repo(owner: str, repo: str, use_cache: bool = True, skip_maven_scan: bool = False, trivy_only: bool = False) -> dict:
    """
    Run the full audit pipeline on a single repo.

    Parallelization strategy:
      - Clone + detect + Trivy scan run as one track (needs filesystem).
      - GitHub API calls run as a second track in parallel (no clone needed).
      - Within the API track, all calls run concurrently.

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        use_cache: Whether to use cached results.
        skip_maven_scan: If True, skip Trivy scan for Maven/Gradle repos
                         (used after a 429 has already been hit this run).
        trivy_only: If True, don't fall back to OSV-Scanner on Maven 429 —
                    report the scan error instead.

    Returns a dict with all collected data.
    """
    repo_id = f"{owner}/{repo}"

    # Check cache first
    if use_cache:
        cached = cache.get_cached_result(owner, repo)
        if cached:
            print(f"  [cached] Using cached result for {repo_id}")
            # Always recompute triage (cheap, and logic may have changed)
            triage = _assess_triage(cached)
            cached["worth_contributing"] = triage["verdict"]
            cached["triage_reason"] = triage["reason"]
            cached["triage_factors"] = triage["factors"]
            return cached

    result = {
        "repo": repo_id,
        "owner": owner,
        "name": repo,
        "package_managers": [],
        "languages": [],
        "vulnerabilities": {},
        "bots": {},
        "community": {},
        "contributor_openness": {},
    }

    def _run_api_track():
        """Run all GitHub API queries, sharing fetched data to minimise API calls."""
        repo_data = github_api.get_repo_data(owner, repo)
        commits = github_api.get_recent_commits(owner, repo)
        prs = github_api.get_recent_prs(owner, repo)

        bots = github_api.detect_bots(owner, repo, commits, prs)
        community = github_api.get_community_health(owner, repo, repo_data, commits)
        openness = github_api.get_contributor_openness(owner, repo, repo_data, prs)
        languages = github_api.get_languages(owner, repo)

        return {
            "bots": bots,
            "community": community,
            "openness": openness,
            "languages": languages,
        }

    def _run_scan_track():
        """Clone, detect, and scan (needs filesystem)."""
        tmp_dir = tempfile.mkdtemp(prefix=f"audit-{repo}-")
        scan_result = {
            "package_managers": [],
            "file_languages": [],
            "vulnerabilities": scanner.VulnSummary(),
            "error": None,
        }

        try:
            print(f"  Cloning {repo_id}...")
            if not clone_repo(owner, repo, tmp_dir):
                print(f"  FAILED: Could not clone {repo_id}")
                scan_result["error"] = "clone_failed"
                return scan_result

            # Detect package managers
            print(f"  Detecting package managers...")
            scan_result["package_managers"] = detector.detect_package_managers(tmp_dir)

            # Detect languages (file-based fallback)
            scan_result["file_languages"] = detector.detect_languages_from_files(tmp_dir)

            # Trivy scan
            MAVEN_ECOSYSTEMS = {"maven", "gradle"}
            is_maven = bool(MAVEN_ECOSYSTEMS & set(scan_result["package_managers"]))

            if skip_maven_scan and is_maven:
                if trivy_only:
                    print(f"  Skipping scan (Maven rate limit hit earlier, --trivy-only set)...")
                    scan_result["vulnerabilities"].scan_error = "maven_rate_limit (skipped, --trivy-only)"
                else:
                    print(f"  Running OSV-Scanner (Maven rate limit hit earlier)...")
                    scan_result["vulnerabilities"] = scanner.run_osv_scan(tmp_dir)
            else:
                print(f"  Running Trivy CVE scan...")
                scan_result["vulnerabilities"] = scanner.run_trivy_scan(tmp_dir)

                if scan_result["vulnerabilities"].scan_error == "maven_rate_limit":
                    if trivy_only:
                        print(f"  Maven rate limit (429) -- scan failed (--trivy-only set).")
                    else:
                        print(f"  Maven rate limit (429) -- falling back to OSV-Scanner...")
                        scan_result["vulnerabilities"] = scanner.run_osv_scan(tmp_dir)

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return scan_result

    # Run both tracks in parallel: scan (clone+trivy) and API queries
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_scan = pool.submit(_run_scan_track)
        future_api = pool.submit(_run_api_track)

    # Collect results — handle failures gracefully so one track doesn't kill the other
    try:
        scan_data = future_scan.result()
    except Exception as e:
        print(f"  ERROR: Scan track failed: {e}")
        scan_data = {"package_managers": [], "file_languages": [], "vulnerabilities": scanner.VulnSummary(), "error": "scan_exception"}

    try:
        api_data = future_api.result()
    except Exception as e:
        print(f"  ERROR: API track failed: {e}")
        api_data = {
            "bots": github_api.BotInfo(),
            "community": github_api.CommunityHealth(),
            "openness": github_api.ContributorOpenness(),
            "languages": [],
        }

    # Handle clone failure
    if scan_data["error"]:
        result["error"] = scan_data["error"]
        # Still include API data even if clone failed
        result["bots"] = asdict(api_data["bots"])
        result["community"] = asdict(api_data["community"])
        result["contributor_openness"] = asdict(api_data["openness"])
        result["languages"] = api_data["languages"]
        return result

    # Merge scan results
    result["package_managers"] = scan_data["package_managers"]
    result["vulnerabilities"] = asdict(scan_data["vulnerabilities"])

    # Merge API results
    result["bots"] = asdict(api_data["bots"])
    result["community"] = asdict(api_data["community"])
    result["contributor_openness"] = asdict(api_data["openness"])

    # Prefer API languages, fall back to file-based detection
    if api_data["languages"]:
        result["languages"] = api_data["languages"]
    else:
        print(f"  Note: GitHub API returned no languages — using file extension heuristics.")
        result["languages"] = scan_data["file_languages"]

    # --- Final triage assessment: is this repo worth contributing CVE fixes to? ---
    triage = _assess_triage(result)
    result["worth_contributing"] = triage["verdict"]
    result["triage_reason"] = triage["reason"]
    result["triage_factors"] = triage["factors"]

    # Cache the result (don't cache if there was a scan error)
    if use_cache and not result.get("vulnerabilities", {}).get("scan_error"):
        cache.save_result(owner, repo, result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Audit GitHub repos for CVEs, bots, and contribution readiness.",
        epilog="Example: python3 auditor.py repos.txt",
    )
    parser.add_argument(
        "repos_file",
        help="Path to a .txt file with GitHub repos (one per line, owner/repo format)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore cached results and re-scan everything",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the cache before running",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Custom output filename prefix (default: auto-generated with timestamp)",
    )
    parser.add_argument(
        "--trivy-only",
        action="store_true",
        help="Disable OSV-Scanner fallback — fail the scan instead of silently losing transitive coverage",
    )

    args = parser.parse_args()

    # Pre-flight: verify gh CLI is authenticated
    if not _check_gh_auth():
        print("Error: GitHub CLI is not authenticated.")
        print("Run 'gh auth login' to authenticate, then retry.")
        sys.exit(1)

    # Handle cache clearing
    if args.clear_cache:
        count = cache.clear_cache()
        print(f"Cleared {count} cached entries.")

    # Parse repos
    repos = parse_repos_file(args.repos_file)
    if not repos:
        print("No repos found in the input file.")
        sys.exit(1)

    # Deduplicate (preserves first occurrence order)
    seen = set()
    unique_repos = []
    for entry in repos:
        key = (entry[0].lower(), entry[1].lower())
        if key not in seen:
            seen.add(key)
            unique_repos.append(entry)
    if len(unique_repos) < len(repos):
        print(f"  Note: Removed {len(repos) - len(unique_repos)} duplicate repo(s).")
    repos = unique_repos

    print(f"\nAuditing {len(repos)} repos...\n")

    # Audit each repo sequentially (Ctrl+C stops after current repo, writes partial results)
    results = []
    maven_rate_limited = False

    try:
        for i, (owner, repo) in enumerate(repos, start=1):
            print(f"[{i}/{len(repos)}] {owner}/{repo}")
            result = audit_repo(
                owner, repo,
                use_cache=not args.no_cache,
                skip_maven_scan=maven_rate_limited,
                trivy_only=args.trivy_only,
            )
            results.append(result)

            # Detect if Maven rate limit was hit (triggers fast-fail for remaining Maven repos)
            vuln = result.get("vulnerabilities", {})
            if (vuln.get("scanner_used") == "osv-scanner"
                    and vuln.get("coverage") == "direct-only"
                    and not maven_rate_limited):
                # Only set the flag if this was actually a Maven/Gradle repo that fell back
                pkg_mgrs = set(result.get("package_managers", []))
                if pkg_mgrs & {"maven", "gradle"}:
                    maven_rate_limited = True
                    print(f"  Maven rate limit hit -- using OSV-Scanner for remaining Maven repos")

            print()
    except KeyboardInterrupt:
        skipped = len(repos) - len(results)
        print(f"\n\n  ⚠ Cancelled. {len(results)}/{len(repos)} repos completed, {skipped} skipped.")
        print()

    if not results:
        print("No results to report.")
        sys.exit(1)

    # Output results
    reporter.print_console_table(results)

    # Generate timestamped filenames in reports/ directory
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if args.output:
        base_name = args.output
    else:
        base_name = f"audit-{timestamp}"

    json_path = reports_dir / f"{base_name}.json"
    html_path = reports_dir / f"{base_name}.html"

    reporter.write_json_report(results, str(json_path))
    reporter.write_html_report(results, str(html_path))

    # Generate shortlist/ — repos worth contributing to
    shortlist_dir = Path(__file__).parent / "shortlist"
    shortlist_dir.mkdir(exist_ok=True)

    worth_repos = [r["repo"] for r in results if r.get("worth_contributing") == "yes"]
    repos_path = shortlist_dir / f"{base_name}-repos.txt"
    links_path = shortlist_dir / f"{base_name}-links.txt"

    repos_path.write_text("\n".join(worth_repos) + "\n" if worth_repos else "")
    links_path.write_text(
        "\n".join(f"https://github.com/{repo}" for repo in worth_repos) + "\n"
        if worth_repos else ""
    )

    print(f"Reports written to:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")
    print(f"  Worth repos: {repos_path} ({len(worth_repos)} repos)")
    print(f"  Worth links: {links_path}")

    # Note if any repos used the OSV fallback (partial coverage)
    osv_repos = [
        r["repo"] for r in results
        if r.get("vulnerabilities", {}).get("scanner_used") == "osv-scanner"
    ]
    if osv_repos:
        print(f"\n  ⚠ {len(osv_repos)} repo(s) scanned with OSV-Scanner (Maven rate limit).")
        print(f"  These report DIRECT dependencies only — transitive CVEs are missing.")
        print(f"  Re-run later with Trivy for full coverage, or use --trivy-only to fail instead.")


if __name__ == "__main__":
    main()

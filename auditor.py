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


def audit_repo(owner: str, repo: str, use_cache: bool = True) -> dict:
    """
    Run the full audit pipeline on a single repo.

    Returns a dict with all collected data.
    """
    repo_id = f"{owner}/{repo}"

    # Check cache first
    if use_cache:
        cached = cache.get_cached_result(owner, repo)
        if cached:
            print(f"  [cached] Using cached result for {repo_id}")
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

    # Step 1: Clone
    tmp_dir = tempfile.mkdtemp(prefix=f"audit-{repo}-")

    try:
        print(f"  Cloning {repo_id}...")
        if not clone_repo(owner, repo, tmp_dir):
            print(f"  FAILED: Could not clone {repo_id}")
            result["error"] = "clone_failed"
            return result

        # Step 2: Detect package managers
        print(f"  Detecting package managers...")
        result["package_managers"] = detector.detect_package_managers(tmp_dir)

        # Step 3: Detect languages (file-based fallback)
        file_languages = detector.detect_languages_from_files(tmp_dir)

        # Step 4: Trivy scan
        print(f"  Running Trivy CVE scan...")
        vuln_summary = scanner.run_trivy_scan(tmp_dir)
        result["vulnerabilities"] = asdict(vuln_summary)

    finally:
        # Always clean up the clone
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Step 5: GitHub API queries (don't need the clone)
    print(f"  Checking for bots...")
    bot_info = github_api.detect_bots(owner, repo)
    result["bots"] = asdict(bot_info)

    print(f"  Gathering community health...")
    community = github_api.get_community_health(owner, repo)
    result["community"] = asdict(community)

    print(f"  Assessing contributor openness...")
    openness = github_api.get_contributor_openness(owner, repo)
    result["contributor_openness"] = asdict(openness)

    # Get languages from GitHub API (preferred over file-based)
    api_languages = github_api.get_languages(owner, repo)
    result["languages"] = api_languages if api_languages else file_languages

    # Cache the result
    if use_cache:
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

    args = parser.parse_args()

    # Handle cache clearing
    if args.clear_cache:
        count = cache.clear_cache()
        print(f"Cleared {count} cached entries.")

    # Parse repos
    repos = parse_repos_file(args.repos_file)
    if not repos:
        print("No repos found in the input file.")
        sys.exit(1)

    print(f"\nAuditing {len(repos)} repos...\n")

    # Audit each repo sequentially
    results = []
    for i, (owner, repo) in enumerate(repos, start=1):
        print(f"[{i}/{len(repos)}] {owner}/{repo}")
        result = audit_repo(owner, repo, use_cache=not args.no_cache)
        results.append(result)
        print()

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

    print(f"Reports written to:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")


if __name__ == "__main__":
    main()

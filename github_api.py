"""
github_api.py — GitHub CLI (gh) wrapper for repo metadata.

Queries the GitHub API via `gh api` to gather:
  - Bot presence (dependency management bots in recent commits/PRs)
  - Bot PR responsiveness (do maintainers merge, ignore, or backlog bot PRs?)
  - Community health signals (activity, issue response, health files)
  - External contributor openness (CONTRIBUTING.md, merged external PRs)
  - Languages (from GitHub's language detection)

API call strategy:
  Shared data is fetched once and passed between functions to minimise
  redundant calls. No search API usage (30 req/min limit) — all data
  comes from REST endpoints (5,000 req/hr limit).
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


# Known dependency management bot logins — single source of truth used by
# both detection and responsiveness assessment.
DEP_BOT_LOGINS = frozenset({
    "dependabot[bot]", "renovate[bot]", "snyk-bot", "greenkeeper[bot]",
    "mend-bolt-for-github[bot]", "depfu[bot]", "pyup-bot",
})


@dataclass
class BotInfo:
    """Bots detected in the repo and how maintainers respond to their PRs."""
    bots_found: list[str] = field(default_factory=list)
    has_dependency_bot: bool = False
    # How maintainers handle dependency bot PRs (last 90 days):
    #   "active"     — mostly merged (>50% of bot PRs)
    #   "ignored"    — mostly closed without merging (>50% closed)
    #   "backlogged" — mostly left open (>50% still open)
    #   "unknown"    — no dependency bot or no bot PRs found
    bot_pr_responsiveness: str = "unknown"
    bot_prs_merged: int = 0
    bot_prs_closed: int = 0
    bot_prs_open: int = 0


@dataclass
class CommunityHealth:
    """Community activity signals."""
    open_issues: int = 0
    open_prs: int = 0
    commits_last_90_days: int = 0
    contributors_last_90_days: int = 0
    has_security_md: bool = False
    has_code_of_conduct: bool = False
    is_active: bool = False  # True if commits in last 90 days > 0
    activity_level: str = "unknown"  # "dormant", "low", "moderate", "high"
    counts_approximate: bool = False  # True when any count hit a pagination cap


@dataclass
class ContributorOpenness:
    """Signals of whether the project accepts external contributions."""
    has_contributing_md: bool = False
    has_good_first_issue_label: bool = False
    external_prs_merged: int = 0
    total_recent_prs_checked: int = 0
    is_archived: bool = False  # Archived repos are dead — can't accept PRs
    is_open_to_contributions: bool = False  # Our assessment


# ---------------------------------------------------------------------------
# Shared data fetchers — called once, results passed to multiple functions
# ---------------------------------------------------------------------------

def get_repo_data(owner: str, repo: str) -> dict | None:
    """
    Fetch the base /repos/{owner}/{repo} endpoint once.

    Contains: open_issues_count (issues+PRs), archived, security_and_analysis,
    language, etc. Shared across community health, openness, and bot detection.
    """
    data = _run_gh([f"/repos/{owner}/{repo}"])
    if isinstance(data, dict):
        return data
    return None


def get_recent_commits(owner: str, repo: str) -> list[dict]:
    """
    Fetch last 100 commits (default branch). Shared between bot detection
    and community health.
    """
    data = _run_gh([f"/repos/{owner}/{repo}/commits?per_page=100"])
    if isinstance(data, list):
        return data
    return []


def get_recent_prs(owner: str, repo: str) -> list[dict]:
    """
    Fetch last 100 PRs (all states, sorted by updated desc). Shared between
    bot detection, responsiveness assessment, and contributor openness.

    We fetch 100 to have enough data for both bot activity detection and
    external PR analysis.
    """
    data = _run_gh([
        f"/repos/{owner}/{repo}/pulls?state=all&sort=updated&direction=desc&per_page=100",
    ])
    if isinstance(data, list):
        return data
    return []


def get_languages(owner: str, repo: str) -> list[str]:
    """
    Get repo languages from GitHub API, sorted by bytes (most used first).
    """
    data = _run_gh([f"/repos/{owner}/{repo}/languages"])
    if not data or not isinstance(data, dict):
        return []

    sorted_langs = sorted(data.items(), key=lambda x: x[1], reverse=True)
    return [lang for lang, _ in sorted_langs]


# ---------------------------------------------------------------------------
# Bot detection
# ---------------------------------------------------------------------------

def detect_bots(owner: str, repo: str, commits: list[dict] | None = None,
                prs: list[dict] | None = None) -> BotInfo:
    """
    Detect dependency management bots and assess maintainer responsiveness.

    Detection (two layers):
      1. Config-based: check for known bot config files (most reliable).
         Short-circuits once a dep bot is confirmed.
      2. Activity-based: scan provided commits/PRs for bot logins
         (catches org-level bots with no per-repo config).

    Responsiveness:
      Derives from the shared PR list — no additional API calls needed.

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        commits: Pre-fetched commits list (avoids redundant call).
        prs: Pre-fetched PRs list (avoids redundant call).
    """
    info = BotInfo()
    bot_names: set[str] = set()

    # --- Config-based detection ---
    # Ordered by prevalence; short-circuits once a dep bot is found.
    BOT_CONFIG_FILES = [
        ("dependabot[bot]", [".github/dependabot.yml", ".github/dependabot.yaml"]),
        ("renovate[bot]", ["renovate.json", ".github/renovate.json", ".renovaterc",
                           "renovate.json5", ".github/renovate.json5", ".renovaterc.json"]),
        ("snyk-bot", [".snyk"]),
        ("mend-bolt-for-github[bot]", [".whitesource"]),
    ]

    dep_bot_found = False
    for bot_name, config_paths in BOT_CONFIG_FILES:
        if dep_bot_found:
            break
        for config_path in config_paths:
            result = _run_gh([f"/repos/{owner}/{repo}/contents/{config_path}"])
            if isinstance(result, dict) and "name" in result:
                bot_names.add(bot_name)
                dep_bot_found = True
                break

    # --- Activity-based detection ---
    if commits is None:
        commits = get_recent_commits(owner, repo)
    if prs is None:
        prs = get_recent_prs(owner, repo)

    for commit in commits:
        author = commit.get("author") or {}
        login = author.get("login", "")
        if _is_bot(login):
            bot_names.add(login)

    for pr in prs:
        user = pr.get("user") or {}
        login = user.get("login", "")
        if _is_bot(login):
            bot_names.add(login)

    info.bots_found = sorted(bot_names)
    info.has_dependency_bot = bool(bot_names & DEP_BOT_LOGINS)

    # --- Responsiveness: derived from the PR list (no extra API calls) ---
    if info.has_dependency_bot:
        _assess_bot_pr_responsiveness(info, prs)

    return info


def _assess_bot_pr_responsiveness(info: BotInfo, prs: list[dict]) -> None:
    """
    Assess how maintainers respond to dependency bot PRs.

    Uses the already-fetched PR list — filters for dependency-bot-authored PRs
    created in the last 90 days and categorises by outcome.
    Zero additional API calls.
    """
    cutoff = _days_ago_iso(90)

    total_merged = 0
    total_closed = 0
    total_open = 0

    for pr in prs:
        user = pr.get("user") or {}
        login = user.get("login", "")
        if login.lower() not in DEP_BOT_LOGINS:
            continue

        # Only count PRs created within last 90 days
        created_at = pr.get("created_at", "")
        if created_at < cutoff:
            continue

        # Categorise outcome
        merged_at = pr.get("merged_at")
        state = pr.get("state", "")

        if merged_at:
            total_merged += 1
        elif state == "closed":
            total_closed += 1
        elif state == "open":
            total_open += 1

    info.bot_prs_merged = total_merged
    info.bot_prs_closed = total_closed
    info.bot_prs_open = total_open

    total = total_merged + total_closed + total_open
    if total == 0:
        info.bot_pr_responsiveness = "unknown"
    elif total_merged > total // 2:
        info.bot_pr_responsiveness = "active"
    elif total_closed > total // 2:
        info.bot_pr_responsiveness = "ignored"
    elif total_open > total // 2:
        info.bot_pr_responsiveness = "backlogged"
    else:
        info.bot_pr_responsiveness = "active" if total_merged >= total_closed else "ignored"


# ---------------------------------------------------------------------------
# Community health
# ---------------------------------------------------------------------------

def get_community_health(owner: str, repo: str, repo_data: dict | None = None,
                         commits: list[dict] | None = None) -> CommunityHealth:
    """
    Gather community health signals: activity level, health files, etc.

    Uses repo_data for issue/PR counts (avoids search API) and pre-fetched
    commits for activity measurement.

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        repo_data: Pre-fetched /repos/{owner}/{repo} response.
        commits: Pre-fetched commits list.
    """
    health = CommunityHealth()

    # --- Issue and PR counts from REST (no search API) ---
    if repo_data is None:
        repo_data = _run_gh([f"/repos/{owner}/{repo}"])
    if isinstance(repo_data, dict):
        health.has_security_md = repo_data.get("security_and_analysis") is not None

    # GitHub's open_issues_count includes PRs. Fetch open PRs separately,
    # then subtract to get the real issue count.
    # Note: capped at 100 per page — if a repo has more, counts are approximate.
    open_prs_data = _run_gh([
        f"/repos/{owner}/{repo}/pulls?state=open&per_page=100",
    ])
    if isinstance(open_prs_data, list):
        health.open_prs = len(open_prs_data)
        if len(open_prs_data) >= 100:
            health.counts_approximate = True

    if isinstance(repo_data, dict):
        total_open = repo_data.get("open_issues_count", 0)
        health.open_issues = max(0, total_open - health.open_prs)

    # --- Commits in last 90 days ---
    since = _days_ago_iso(90)

    if commits is None:
        commits = _run_gh([
            f"/repos/{owner}/{repo}/commits?since={since}&per_page=100",
        ])
        if not isinstance(commits, list):
            commits = []

    # Filter to 90-day window (pre-fetched commits may include older ones)
    human_commits = 0
    contributors = set()
    for c in commits:
        # Check date if available
        commit_data = c.get("commit", {})
        commit_date = commit_data.get("committer", {}).get("date", "")
        if commit_date and commit_date < since:
            continue

        author = c.get("author") or {}
        login = author.get("login", "")
        if login and _is_bot(login):
            continue
        human_commits += 1
        if login:
            contributors.add(login)

    health.commits_last_90_days = human_commits
    health.contributors_last_90_days = len(contributors)

    # If we got 100 commits, we likely hit the pagination cap
    if len(commits) >= 100:
        health.counts_approximate = True

    # --- Health files ---
    community = _run_gh([f"/repos/{owner}/{repo}/community/profile"])
    if isinstance(community, dict):
        files = community.get("files", {})
        health.has_code_of_conduct = files.get("code_of_conduct") is not None
        health.has_security_md = (
            health.has_security_md or files.get("security") is not None
        )

    # --- Activity level ---
    health.is_active = health.commits_last_90_days > 0
    if health.commits_last_90_days == 0:
        health.activity_level = "dormant"
    elif health.commits_last_90_days < 10:
        health.activity_level = "low"
    elif health.commits_last_90_days < 50:
        health.activity_level = "moderate"
    else:
        health.activity_level = "high"

    return health


# ---------------------------------------------------------------------------
# Contributor openness
# ---------------------------------------------------------------------------

def get_contributor_openness(owner: str, repo: str, repo_data: dict | None = None,
                             prs: list[dict] | None = None) -> ContributorOpenness:
    """
    Assess whether the repo is open to external contributions.

    Uses pre-fetched PR list for external merge analysis (no extra API call).

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        repo_data: Pre-fetched /repos/{owner}/{repo} response.
        prs: Pre-fetched PRs list.
    """
    openness = ContributorOpenness()

    # Check if repo is archived
    if repo_data is None:
        repo_data = _run_gh([f"/repos/{owner}/{repo}"])
    if isinstance(repo_data, dict) and repo_data.get("archived", False):
        openness.is_archived = True
        openness.is_open_to_contributions = False
        return openness

    # Check for CONTRIBUTING.md
    contrib = _run_gh([f"/repos/{owner}/{repo}/contents/CONTRIBUTING.md"])
    openness.has_contributing_md = isinstance(contrib, dict) and "name" in contrib

    # Check for "good first issue" label
    labels = _run_gh([f"/repos/{owner}/{repo}/labels?per_page=100"])
    if isinstance(labels, list):
        label_names = [l.get("name", "").lower() for l in labels]
        openness.has_good_first_issue_label = "good first issue" in label_names

    # --- External PR analysis from shared PR list (no extra API call) ---
    if prs is None:
        prs = _run_gh([
            f"/repos/{owner}/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=50",
        ])
        if not isinstance(prs, list):
            prs = []

    cutoff = _days_ago_iso(90)
    external_merged = 0
    total_checked = 0

    for pr in prs:
        merged_at = pr.get("merged_at")
        if not merged_at:
            continue

        # Only count PRs merged within the last 90 days
        if merged_at < cutoff:
            continue

        # Skip bot-authored PRs — we want human external contributors
        user = pr.get("user") or {}
        login = user.get("login", "")
        if _is_bot(login):
            continue

        total_checked += 1

        # author_association tells us if the author is a member
        association = pr.get("author_association", "").upper()
        if association not in ("MEMBER", "OWNER", "COLLABORATOR"):
            external_merged += 1

    openness.external_prs_merged = external_merged
    openness.total_recent_prs_checked = total_checked

    # Score-based assessment:
    #   CONTRIBUTING.md exists           → 1 point
    #   "good first issue" label exists  → 1 point
    #   1-2 external PRs merged (90d)    → 1 point
    #   3+ external PRs merged (90d)     → 2 points
    #
    # Open = score >= 2.
    score = 0
    if openness.has_contributing_md:
        score += 1
    if openness.has_good_first_issue_label:
        score += 1
    if openness.external_prs_merged >= 3:
        score += 2
    elif openness.external_prs_merged > 0:
        score += 1

    openness.is_open_to_contributions = score >= 2

    return openness


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_gh(args: list[str]) -> dict | list | None:
    """Run a `gh api` command and return parsed JSON, or None on error."""
    cmd = ["gh", "api"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if result.returncode != 0:
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _is_bot(login: str) -> bool:
    """Check if a GitHub login looks like a bot."""
    if not login:
        return False
    login_lower = login.lower()
    return (
        login_lower.endswith("[bot]")
        or login_lower.endswith("-bot")
        or login_lower in {"dependabot", "renovate", "snyk-bot", "greenkeeper"}
    )


def _days_ago_iso(days: int) -> str:
    """Return an ISO 8601 timestamp for N days ago."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(days=days)
    return past.strftime("%Y-%m-%dT%H:%M:%SZ")

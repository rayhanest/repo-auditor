"""
github_api.py — GitHub CLI (gh) wrapper for repo metadata.

Queries the GitHub API via `gh api` to gather:
  - Bot presence (dependency management bots in recent commits/PRs)
  - Community health signals (activity, issue response, health files)
  - External contributor openness (CONTRIBUTING.md, merged external PRs)
  - Languages (from GitHub's language detection)
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


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


@dataclass
class ContributorOpenness:
    """Signals of whether the project accepts external contributions."""
    has_contributing_md: bool = False
    has_good_first_issue_label: bool = False
    external_prs_merged: int = 0
    total_recent_prs_checked: int = 0
    is_archived: bool = False  # Archived repos are dead — can't accept PRs
    is_open_to_contributions: bool = False  # Our assessment


def _run_gh(args: list[str]) -> dict | list | None:
    """
    Run a `gh api` command and return parsed JSON, or None on error.
    """
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


def get_languages(owner: str, repo: str) -> list[str]:
    """
    Get repo languages from GitHub API, sorted by bytes (most used first).

    Endpoint: GET /repos/{owner}/{repo}/languages
    Returns: {"Python": 50000, "JavaScript": 30000, ...}
    """
    data = _run_gh([f"/repos/{owner}/{repo}/languages"])
    if not data or not isinstance(data, dict):
        return []

    # Sort by byte count descending
    sorted_langs = sorted(data.items(), key=lambda x: x[1], reverse=True)
    return [lang for lang, _ in sorted_langs]


def get_repo_data(owner: str, repo: str) -> dict | None:
    """
    Fetch the base /repos/{owner}/{repo} endpoint once.

    This data is used by both get_community_health and get_contributor_openness,
    so fetching it once and passing it in saves a redundant API call.
    """
    data = _run_gh([f"/repos/{owner}/{repo}"])
    if isinstance(data, dict):
        return data
    return None


def detect_bots(owner: str, repo: str) -> BotInfo:
    """
    Detect dependency management bots and assess how maintainers respond to them.

    Detection (two layers):
      1. Config-based: check for known bot config files (most reliable).
      2. Activity-based: scan recent commits/PRs for bot logins
         (catches org-level bots with no per-repo config).

    Responsiveness (for repos with a dependency bot):
      Searches bot-authored PRs from the last 90 days and classifies
      maintainer behaviour as active, ignored, or backlogged.
    """
    info = BotInfo()
    bot_names: set[str] = set()

    # --- Config-based detection (reliable, doesn't depend on recency) ---
    BOT_CONFIG_FILES = {
        "dependabot[bot]": [
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
        ],
        "renovate[bot]": [
            "renovate.json",
            "renovate.json5",
            ".github/renovate.json",
            ".github/renovate.json5",
            ".renovaterc",
            ".renovaterc.json",
        ],
        "snyk-bot": [
            ".snyk",
        ],
        "mend-bolt-for-github[bot]": [
            ".whitesource",
        ],
    }

    for bot_name, config_paths in BOT_CONFIG_FILES.items():
        for config_path in config_paths:
            result = _run_gh([f"/repos/{owner}/{repo}/contents/{config_path}"])
            if isinstance(result, dict) and "name" in result:
                bot_names.add(bot_name)
                break

    # --- Activity-based detection (catches org-level setups without config files) ---
    commits = _run_gh([
        f"/repos/{owner}/{repo}/commits?per_page=100",
    ])

    if isinstance(commits, list):
        for commit in commits:
            author = commit.get("author") or {}
            login = author.get("login", "")
            if _is_bot(login):
                bot_names.add(login)

    prs = _run_gh([
        f"/repos/{owner}/{repo}/pulls?state=all&per_page=50&sort=updated&direction=desc",
    ])

    if isinstance(prs, list):
        for pr in prs:
            user = pr.get("user") or {}
            login = user.get("login", "")
            if _is_bot(login):
                bot_names.add(login)

    info.bots_found = sorted(bot_names)

    # Known dependency management bots
    dep_bots = {"dependabot[bot]", "renovate[bot]", "snyk-bot", "greenkeeper[bot]",
                "mend-bolt-for-github[bot]", "depfu[bot]", "pyup-bot"}
    info.has_dependency_bot = bool(bot_names & dep_bots)

    # --- Responsiveness: how do maintainers handle dependency bot PRs? ---
    if info.has_dependency_bot:
        _assess_bot_pr_responsiveness(owner, repo, info)

    return info


def _assess_bot_pr_responsiveness(owner: str, repo: str, info: BotInfo) -> None:
    """
    Check how maintainers respond to dependency bot PRs in the last 90 days.

    Uses the search API to find bot-authored PRs and categorises them
    by outcome: merged, closed (rejected), or still open.
    """
    since = _days_ago_iso(90)

    # Search for dependency bot PRs created in last 90 days
    # Try known bot authors in order of prevalence
    bot_authors = ["app/dependabot", "app/renovate", "app/snyk-bot"]
    total_merged = 0
    total_closed = 0
    total_open = 0

    for author in bot_authors:
        search = _run_gh([
            f"/search/issues?q=repo:{owner}/{repo}+author:{author}+type:pr+created:>{since[:10]}",
        ])
        if not isinstance(search, dict) or search.get("total_count", 0) == 0:
            continue

        # Fetch the actual PR items to check state
        items = search.get("items", [])
        for item in items:
            state = item.get("state", "")
            pull_request = item.get("pull_request", {})
            merged_at = pull_request.get("merged_at") if pull_request else None

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
        # Mixed — no clear majority
        info.bot_pr_responsiveness = "active" if total_merged >= total_closed else "ignored"


def get_community_health(owner: str, repo: str, repo_data: dict | None = None) -> CommunityHealth:
    """
    Gather community health signals: activity level, health files, etc.

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        repo_data: Optional pre-fetched /repos/{owner}/{repo} response to avoid
                   a duplicate API call.
    """
    health = CommunityHealth()

    # Basic repo info
    if repo_data is None:
        repo_data = _run_gh([f"/repos/{owner}/{repo}"])
    if isinstance(repo_data, dict):
        health.has_security_md = repo_data.get("security_and_analysis") is not None

    # Separate issue count (excludes PRs) via search API
    issue_search = _run_gh([
        f"/search/issues?q=repo:{owner}/{repo}+type:issue+state:open",
    ])
    if isinstance(issue_search, dict):
        health.open_issues = issue_search.get("total_count", 0)

    # Open PRs count
    pr_search = _run_gh([
        f"/search/issues?q=repo:{owner}/{repo}+type:pr+state:open",
    ])
    if isinstance(pr_search, dict):
        health.open_prs = pr_search.get("total_count", 0)

    # Commits in last 90 days
    since = _days_ago_iso(90)
    commits_data = _run_gh([
        f"/repos/{owner}/{repo}/commits?since={since}&per_page=100",
    ])
    if isinstance(commits_data, list):
        # Filter out bot commits for accurate human activity measurement
        human_commits = 0
        contributors = set()
        for c in commits_data:
            author = c.get("author") or {}
            login = author.get("login", "")
            if login and _is_bot(login):
                continue
            human_commits += 1
            if login:
                contributors.add(login)
        health.commits_last_90_days = human_commits
        health.contributors_last_90_days = len(contributors)

    # Check for health files
    community = _run_gh([f"/repos/{owner}/{repo}/community/profile"])
    if isinstance(community, dict):
        files = community.get("files", {})
        health.has_code_of_conduct = files.get("code_of_conduct") is not None
        health.has_security_md = (
            health.has_security_md or files.get("security") is not None
        )

    # Determine activity level based on human commits
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


def get_contributor_openness(owner: str, repo: str, repo_data: dict | None = None) -> ContributorOpenness:
    """
    Assess whether the repo is open to external contributions.

    Checks:
      - Presence of CONTRIBUTING.md
      - "good first issue" label exists
      - Merged PRs from non-org members (author_association != MEMBER/OWNER)

    Args:
        owner: GitHub org/user.
        repo: Repository name.
        repo_data: Optional pre-fetched /repos/{owner}/{repo} response to avoid
                   a duplicate API call.
    """
    openness = ContributorOpenness()

    # Check if repo is archived — archived repos cannot accept contributions
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

    # Check recent merged PRs for external contributors (within last 90 days)
    merged_prs = _run_gh([
        f"/repos/{owner}/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=50",
    ])

    cutoff = _days_ago_iso(90)

    if isinstance(merged_prs, list):
        external_merged = 0
        total_checked = 0

        for pr in merged_prs:
            # Only count actually merged PRs
            merged_at = pr.get("merged_at")
            if not merged_at:
                continue

            # Only count PRs merged within the last 90 days
            if merged_at < cutoff:
                continue

            total_checked += 1

            # author_association tells us if the author is a member
            association = pr.get("author_association", "").upper()
            if association not in ("MEMBER", "OWNER", "COLLABORATOR"):
                external_merged += 1

        openness.external_prs_merged = external_merged
        openness.total_recent_prs_checked = total_checked

    # Our assessment — score-based, so evidence compounds rather than
    # hiding behind arbitrary thresholds:
    #
    #   Signal                          Points
    #   ──────────────────────────────  ──────
    #   CONTRIBUTING.md exists           1
    #   "good first issue" label exists  1
    #   1-2 external PRs merged (90d)    1
    #   3+ external PRs merged (90d)     2  (strong demonstrated openness)
    #
    # Open = score >= 2.  This means:
    #   - CONTRIBUTING.md + label alone = open (docs say "come contribute")
    #   - 1 external PR + either doc/label = open (evidence + invitation)
    #   - 3+ external PRs alone = open (demonstrated, docs don't matter)
    #   - Only CONTRIBUTING.md, nothing else = NOT open (docs without action)
    #   - Only 1 external PR, no docs/label = NOT open (could be a one-off)
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

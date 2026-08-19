"""
reporter.py — Output formatting for audit results.

Supports three output modes:
  - Console table: A compact, human-readable summary printed to stdout.
  - JSON: Full structured output written to a file for further processing.
  - HTML: A styled, readable report for viewing in a browser.

Why all three:
  - Console table gives you a quick "which repos are worth looking at" view.
  - JSON preserves all the detail (individual CVEs, bot names, etc.) for
    later filtering or feeding into other tools.
  - HTML makes the data easy to share and read with formatting and color.
"""

import json
from datetime import datetime
from pathlib import Path


def print_console_table(results: list[dict]) -> None:
    """
    Print a compact summary table to the console.

    Columns: Repo | CVEs | Bots | Package Mgrs | Languages | Active | Open to Contribs
    """
    if not results:
        print("No results to display.")
        return

    # Column headers
    headers = ["Repo", "CVEs", "Bots", "Pkg Mgrs", "Languages", "Active", "Worth"]

    # Build rows
    rows = []
    for r in results:
        repo = r.get("repo", "unknown")
        cve_summary = _format_cves(r.get("vulnerabilities", {}))
        bots = _format_bots(r.get("bots", {}))
        pkg_mgrs = ", ".join(r.get("package_managers", [])) or "none"
        languages = ", ".join(r.get("languages", [])[:3]) or "unknown"  # Top 3
        active = _format_activity(r.get("community", {}))
        worth = r.get("worth_contributing", "?").upper()

        rows.append([repo, cve_summary, bots, pkg_mgrs, languages, active, worth])

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    # Cap widths for readability
    max_widths = [25, 18, 16, 18, 20, 12, 7]
    col_widths = [min(w, m) for w, m in zip(col_widths, max_widths)]

    # Print table
    separator = "─"
    top_border = "┌" + "┬".join(separator * (w + 2) for w in col_widths) + "┐"
    mid_border = "├" + "┼".join(separator * (w + 2) for w in col_widths) + "┤"
    bot_border = "└" + "┴".join(separator * (w + 2) for w in col_widths) + "┘"

    def format_row(cells):
        parts = []
        for cell, width in zip(cells, col_widths):
            truncated = cell[:width] + "…" if len(cell) > width else cell
            parts.append(f" {truncated:<{width}} ")
        return "│" + "│".join(parts) + "│"

    print()
    print(top_border)
    print(format_row(headers))
    print(mid_border)
    for row in rows:
        print(format_row(row))
    print(bot_border)
    print()

    # Print summary line
    repos_worth = sum(1 for r in results if r.get("worth_contributing") == "yes")
    print(f"  Summary: {len(results)} repos scanned, {repos_worth} worth contributing to")
    print()


def write_json_report(results: list[dict], output_path: str = "audit-report.json") -> str:
    """
    Write the full audit results to a JSON file.

    Args:
        results: List of result dicts from the audit pipeline.
        output_path: Where to write the JSON file.

    Returns:
        The path the file was written to.
    """
    path = Path(output_path)

    # Clean up internal fields
    clean_results = []
    for r in results:
        clean = {k: v for k, v in r.items() if not k.startswith("_")}
        clean_results.append(clean)

    output = {
        "audit_results": clean_results,
        "total_repos": len(clean_results),
        "summary": {
            "total_cves": sum(r.get("vulnerabilities", {}).get("total", 0) for r in clean_results),
            "repos_with_cves": sum(1 for r in clean_results if r.get("vulnerabilities", {}).get("total", 0) > 0),
            "repos_open_to_contributions": sum(
                1 for r in clean_results
                if r.get("contributor_openness", {}).get("is_open_to_contributions")
            ),
        },
    }

    path.write_text(json.dumps(output, indent=2, default=str))
    return str(path)


def _format_cves(vuln: dict) -> str:
    """Format CVE summary for table display."""
    total = vuln.get("total", 0)
    if vuln.get("scan_error"):
        return "ERROR"
    if total == 0:
        if vuln.get("coverage") == "direct-only":
            return "0 (direct only) *"
        return "clean"
    else:
        parts = []
        if vuln.get("critical", 0):
            parts.append(f"{vuln['critical']} CRIT")
        if vuln.get("high", 0):
            parts.append(f"{vuln['high']} HIGH")
        if vuln.get("medium", 0):
            parts.append(f"{vuln['medium']} MED")
        if vuln.get("low", 0):
            parts.append(f"{vuln['low']} LOW")
        label = ", ".join(parts) if parts else f"{total} total"

    # Annotate partial coverage (OSV without transitive resolution)
    if vuln.get("coverage") == "direct-only":
        label += " *"

    return label


def _format_bots(bots: dict) -> str:
    """Format bot info for table display."""
    found = bots.get("bots_found", [])
    if not found:
        return "none"

    # Shorten bot names for display
    short_names = []
    for bot in found:
        name = bot.replace("[bot]", "").replace("-bot", "")
        short_names.append(name)

    label = ", ".join(short_names[:3])  # Max 3 for table width

    # Append responsiveness indicator
    responsiveness = bots.get("bot_pr_responsiveness", "unknown")
    if responsiveness == "active":
        label += " ✓"
    elif responsiveness == "ignored":
        label += " ✗"
    elif responsiveness == "backlogged":
        label += " …"

    return label


def _format_activity(community: dict) -> str:
    """Format activity level for table display."""
    level = community.get("activity_level", "unknown")
    approximate = community.get("counts_approximate", False)
    suffix = "+" if approximate else ""

    if level == "high":
        return f"YES (high{suffix})"
    elif level == "moderate":
        return f"YES (moderate{suffix})"
    elif level == "low":
        return "low"
    elif level == "dormant":
        return "NO (dormant)"
    return "?"


def write_html_report(results: list[dict], output_path: str = "audit-report.html") -> str:
    """
    Write a styled HTML report from the audit results.

    Args:
        results: List of result dicts from the audit pipeline.
        output_path: Where to write the HTML file.

    Returns:
        The path the file was written to.
    """
    path = Path(output_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build summary stats
    repos_worth = sum(1 for r in results if r.get("worth_contributing") == "yes")

    # Build the HTML
    html_parts = [_html_header(timestamp, len(results), repos_worth)]

    # Summary table
    html_parts.append(_html_summary_table(results))

    # Detailed sections per repo
    for r in results:
        html_parts.append(_html_repo_detail(r))

    html_parts.append(_html_footer())

    path.write_text("\n".join(html_parts))
    return str(path)


def _html_header(timestamp: str, total_repos: int, repos_worth: int) -> str:
    """Generate the HTML header with embedded CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Repo Audit Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
            color: #1a1a1a;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }}
        .stats {{
            display: flex;
            gap: 1.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 1rem 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            min-width: 150px;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: bold;
            color: #1a1a1a;
        }}
        .stat-card .label {{
            font-size: 0.85rem;
            color: #666;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }}
        th {{
            background: #2d3748;
            color: white;
            padding: 0.75rem 1rem;
            text-align: left;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.9rem;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #f7fafc; }}
        .severity-crit {{ color: #e53e3e; font-weight: bold; }}
        .severity-high {{ color: #dd6b20; font-weight: bold; }}
        .severity-med {{ color: #d69e2e; }}
        .severity-low {{ color: #718096; }}
        .badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .badge-yes {{ background: #c6f6d5; color: #276749; }}
        .badge-no {{ background: #fed7d7; color: #9b2c2c; }}
        .badge-maybe {{ background: #fefcbf; color: #975a16; }}
        .badge-bot {{ background: #e9d8fd; color: #553c9a; }}
        .repo-detail {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .repo-detail h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }}
        .repo-detail h2 a {{
            color: #2b6cb0;
            text-decoration: none;
        }}
        .repo-detail h2 a:hover {{ text-decoration: underline; }}
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .detail-item {{
            padding: 0.5rem 0;
        }}
        .detail-item .label {{
            font-size: 0.8rem;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .detail-item .value {{
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>GitHub Repo Audit Report</h1>
    <p class="timestamp">Generated: {timestamp}</p>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{total_repos}</div>
            <div class="label">Repos Scanned</div>
        </div>
        <div class="stat-card">
            <div class="number">{repos_worth}</div>
            <div class="label">Worth Contributing</div>
        </div>
    </div>
"""


def _html_summary_table(results: list[dict]) -> str:
    """Generate the overview summary table."""
    rows = ""
    for r in results:
        repo = r.get("repo", "unknown")
        vuln = r.get("vulnerabilities", {})
        bots = r.get("bots", {})
        community = r.get("community", {})
        openness = r.get("contributor_openness", {})

        # CVE cell
        cve_parts = []
        if vuln.get("critical", 0):
            cve_parts.append(f'<span class="severity-crit">{vuln["critical"]} CRIT</span>')
        if vuln.get("high", 0):
            cve_parts.append(f'<span class="severity-high">{vuln["high"]} HIGH</span>')
        if vuln.get("medium", 0):
            cve_parts.append(f'<span class="severity-med">{vuln["medium"]} MED</span>')
        if vuln.get("low", 0):
            cve_parts.append(f'<span class="severity-low">{vuln["low"]} LOW</span>')
        cve_cell = ", ".join(cve_parts) if cve_parts else "clean"
        if not cve_parts and vuln.get("coverage") == "direct-only":
            cve_cell = '<span style="color:#666;">0 (direct only)</span>'

        # Bots cell — neutral color, with responsiveness as plain text
        bot_list = bots.get("bots_found", [])
        responsiveness = bots.get("bot_pr_responsiveness", "unknown")
        if bot_list:
            bot_names = " ".join(
                f'<span class="badge badge-bot">{b.replace("[bot]", "")}</span>'
                for b in bot_list[:3]
            )
            if responsiveness != "unknown":
                bot_cell = f'{bot_names} <small>({responsiveness})</small>'
            else:
                bot_cell = bot_names
        else:
            bot_cell = "none"

        # Package managers
        pkg_mgrs = ", ".join(r.get("package_managers", [])) or "none"

        # Languages (top 3)
        languages = ", ".join(r.get("languages", [])[:3]) or "unknown"

        # Activity — no color, just text
        activity = community.get("activity_level", "unknown")
        approximate = community.get("counts_approximate", False)
        if approximate and activity in ("high", "moderate"):
            activity_cell = f"{activity}+"
        else:
            activity_cell = activity

        # Worth contributing
        worth = r.get("worth_contributing", "?")
        if worth == "yes":
            worth_cell = '<span class="badge badge-yes">YES</span>'
        elif worth == "no":
            worth_cell = '<span class="badge badge-no">NO</span>'
        else:
            worth_cell = '<span class="badge badge-maybe">MAYBE</span>'

        rows += f"""        <tr>
            <td><a href="https://github.com/{repo}">{repo}</a></td>
            <td>{cve_cell}</td>
            <td>{bot_cell}</td>
            <td>{pkg_mgrs}</td>
            <td>{languages}</td>
            <td>{activity_cell}</td>
            <td>{worth_cell}</td>
        </tr>
"""

    return f"""    <h2 style="font-size:1.2rem; margin-bottom:0.75rem;">Overview</h2>
    <table>
        <thead>
            <tr>
                <th>Repo</th>
                <th>CVEs</th>
                <th>Bots</th>
                <th>Package Managers</th>
                <th>Languages</th>
                <th>Activity</th>
                <th>Worth Contributing</th>
            </tr>
        </thead>
        <tbody>
{rows}        </tbody>
    </table>
"""


def _html_repo_detail(r: dict) -> str:
    """Generate a detailed section for a single repo."""
    repo = r.get("repo", "unknown")
    vuln = r.get("vulnerabilities", {})
    bots = r.get("bots", {})
    community = r.get("community", {})
    openness = r.get("contributor_openness", {})

    # Detail grid items
    pkg_mgrs = ", ".join(r.get("package_managers", [])) or "none"
    languages = ", ".join(r.get("languages", [])) or "unknown"
    bot_names = ", ".join(b.replace("[bot]", "") for b in bots.get("bots_found", [])) or "none"
    has_dep_bot = "Yes" if bots.get("has_dependency_bot") else "No"
    bot_responsiveness = bots.get("bot_pr_responsiveness", "unknown")
    bot_prs_detail = f"{bots.get('bot_prs_merged', 0)} merged, {bots.get('bot_prs_closed', 0)} closed, {bots.get('bot_prs_open', 0)} open"

    # CVE severity summary
    cve_parts = []
    if vuln.get("critical", 0):
        cve_parts.append(f'<span class="severity-crit">{vuln["critical"]} CRIT</span>')
    if vuln.get("high", 0):
        cve_parts.append(f'<span class="severity-high">{vuln["high"]} HIGH</span>')
    if vuln.get("medium", 0):
        cve_parts.append(f'<span class="severity-med">{vuln["medium"]} MED</span>')
    if vuln.get("low", 0):
        cve_parts.append(f'<span class="severity-low">{vuln["low"]} LOW</span>')
    cve_summary = ", ".join(cve_parts) if cve_parts else "clean"

    # Community details
    commits_90d = community.get("commits_last_90_days", "N/A")
    contributors_90d = community.get("contributors_last_90_days", "N/A")
    open_issues = community.get("open_issues", "N/A")
    open_prs = community.get("open_prs", "N/A")
    activity_level = community.get("activity_level", "unknown")
    has_security = "Yes" if community.get("has_security_md") else "No"
    has_coc = "Yes" if community.get("has_code_of_conduct") else "No"

    # Openness details
    has_contributing = "Yes" if openness.get("has_contributing_md") else "No"
    has_gfi = "Yes" if openness.get("has_good_first_issue_label") else "No"
    ext_prs = openness.get("external_prs_merged", 0)
    total_prs_checked = openness.get("total_recent_prs_checked", 0)
    dep_pr_titles = openness.get("dep_pr_titles", [])
    dep_pr_closed_titles = openness.get("dep_pr_closed_titles", [])
    worth = r.get("worth_contributing", "?")
    triage_reason = r.get("triage_reason", "")

    return f"""    <div class="repo-detail">
        <h2><a href="https://github.com/{repo}">{repo}</a></h2>
        <div class="detail-grid">
            <div class="detail-item">
                <div class="label">Package Managers</div>
                <div class="value">{pkg_mgrs}</div>
            </div>
            <div class="detail-item">
                <div class="label">CVEs</div>
                <div class="value">{cve_summary}</div>
            </div>
            <div class="detail-item">
                <div class="label">Languages</div>
                <div class="value">{languages}</div>
            </div>
            <div class="detail-item">
                <div class="label">Bots Detected</div>
                <div class="value">{bot_names} (dep bot: {has_dep_bot})</div>
            </div>
            <div class="detail-item">
                <div class="label">Bot PR Responsiveness</div>
                <div class="value">{bot_responsiveness} ({bot_prs_detail})</div>
            </div>
            <div class="detail-item">
                <div class="label">Commits (90 days)</div>
                <div class="value">{commits_90d}</div>
            </div>
            <div class="detail-item">
                <div class="label">Contributors (90 days)</div>
                <div class="value">{contributors_90d}</div>
            </div>
            <div class="detail-item">
                <div class="label">Open Issues / PRs</div>
                <div class="value">{open_issues} / {open_prs}</div>
            </div>
            <div class="detail-item">
                <div class="label">Activity Level</div>
                <div class="value">{activity_level}</div>
            </div>
            <div class="detail-item">
                <div class="label">SECURITY.md</div>
                <div class="value">{has_security}</div>
            </div>
            <div class="detail-item">
                <div class="label">Code of Conduct</div>
                <div class="value">{has_coc}</div>
            </div>
            <div class="detail-item">
                <div class="label">CONTRIBUTING.md</div>
                <div class="value">{has_contributing}</div>
            </div>
            <div class="detail-item">
                <div class="label">"Good First Issue" Label</div>
                <div class="value">{has_gfi}</div>
            </div>
            <div class="detail-item">
                <div class="label">External PRs Merged</div>
                <div class="value">{ext_prs} of {total_prs_checked} human merged PRs recently are external</div>
            </div>
            <div class="detail-item">
                <div class="label">Worth Contributing</div>
                <div class="value"><strong>{worth}</strong> — {_html_escape(triage_reason)}</div>
            </div>
        </div>{_html_dep_pr_list(dep_pr_titles, dep_pr_closed_titles)}
    </div>
"""


def _html_dep_pr_list(merged_titles: list[str], closed_titles: list[str]) -> str:
    """Render matched dependency/CVE PR titles (merged and closed) as a list."""
    if not merged_titles and not closed_titles:
        return ""

    sections = []

    if merged_titles:
        items = "\n".join(f"            <li>{_html_escape(t)}</li>" for t in merged_titles)
        sections.append(f"""            <div style="margin-bottom:0.5rem;">
                <span style="font-size:0.8rem; color:#276749; font-weight:500;">Merged ({len(merged_titles)})</span>
                <ul style="margin-top:0.25rem; padding-left:1.5rem; font-size:0.85rem;">
{items}
                </ul>
            </div>""")

    if closed_titles:
        items = "\n".join(f"            <li>{_html_escape(t)}</li>" for t in closed_titles)
        sections.append(f"""            <div>
                <span style="font-size:0.8rem; color:#9b2c2c; font-weight:500;">Closed without merging ({len(closed_titles)})</span>
                <ul style="margin-top:0.25rem; padding-left:1.5rem; font-size:0.85rem;">
{items}
                </ul>
            </div>""")

    content = "\n".join(sections)
    return f"""
        <div style="margin-top:0.75rem;">
            <span style="font-size:0.8rem; color:#666; text-transform:uppercase; letter-spacing:0.05em;">Dep/CVE PRs (last 90 days)</span>
{content}
        </div>"""


def _html_footer() -> str:
    """Generate the HTML footer."""
    return """</div>
</body>
</html>"""


def _html_escape(text: str) -> str:
    """Basic HTML escaping for user-provided content."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

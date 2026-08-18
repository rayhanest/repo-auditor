# repo-auditor

A CLI tool that audits GitHub repositories for CVE remediation opportunities. Given a list of repos, it scans for dependency vulnerabilities, detects dependency management bots, assesses maintainer responsiveness, and determines whether a repo is worth contributing CVE fixes to.

Built to answer: **"Which repos are worth contributing CVE fixes to?"**

## What it checks

| Signal | Method |
|--------|--------|
| Dependency CVEs (direct + transitive) | Trivy filesystem scan (OSV-Scanner fallback for Maven rate limits — direct deps only) |
| Dependency management bots | Config file detection + commit/PR author analysis; responsiveness assessment (active/ignored/backlogged) |
| Dep/CVE PRs merged | Keyword matching on merged PR titles — proves the project actively maintains dependency health |
| Package managers | Lockfile and manifest detection |
| Languages | GitHub API language breakdown |
| Community activity | Human commits, contributors, and open issues in last 90 days (bot activity filtered out) |
| Open to external PRs | Score-based: docs/labels + recently merged external PRs (last 90 days) |
| **Worth contributing** | Final triage verdict (yes/maybe/no) combining all signals above |

## How "worth contributing" is determined

The tool produces a final `yes` / `maybe` / `no` verdict for each repo:

| Condition | Verdict |
|-----------|---------|
| No CVEs found | **no** — nothing to fix |
| Repo is archived | **no** — can't accept PRs |
| Repo is dormant (0 commits in 90 days) | **no** — no one to review |
| Dep/CVE PRs closed without merging (none merged) | **no** — project rejects this work |
| Dep/CVE PRs merged recently + open to contributions | **yes** — proven they maintain dependency health |
| Open to contributions + no dep bot or bot ignored/backlogged | **yes** — opportunity for manual bumps |
| Open to contributions + dep bot actively merging | **maybe** — bot may already handle it |
| Not open + merges dep PRs internally | **maybe** — they care about deps but haven't invited outsiders |
| Not clearly open but has CVEs | **maybe** — worth a shot for critical ones |

Notes are attached when:
- Community has low activity (reviews may be slow)
- Bot is backlogged (check for duplicate PRs before submitting)

## Prerequisites

- **Python 3.10+**
- **git**
- **[Trivy](https://github.com/aquasecurity/trivy)** — for vulnerability scanning
- **[GitHub CLI (gh)](https://cli.github.com/)** — authenticated (`gh auth login`)
- **[OSV-Scanner](https://github.com/google/osv-scanner)** *(optional)* — fallback for Maven/Gradle repos when Trivy hits rate limits

## Installation

```bash
git clone https://github.com/your-username/repo-auditor.git
cd repo-auditor
```

No external Python dependencies required — the tool uses only the standard library plus system tools.

## Usage

### 1. Create a repos file

Create a `.txt` file with one repo per line in `owner/repo` format:

```
docker/compose
expressjs/express
kubernetes/kubernetes
```

Lines starting with `#` are treated as comments. Blank lines are ignored. Full GitHub URLs also work.

### 2. Run the audit

```bash
python3 auditor.py repos.txt
```

### 3. View the results

The tool outputs:
- A **console table** for quick triage
- A **JSON report** with full details (individual CVEs, triage reasoning, matched PR titles)
- An **HTML report** for readable, shareable viewing

All reports are saved to `reports/` with timestamped filenames.

### Example output

```
Auditing 2 repos...

[1/2] gogf/gf
  Cloning gogf/gf...
  Detecting package managers...
  Running Trivy CVE scan...

[2/2] locustio/locust
  Cloning locustio/locust...
  Detecting package managers...
  Running Trivy CVE scan...

┌─────────────────┬──────────────────┬──────────────┬────────────┬────────────┬──────────────┬───────┐
│ Repo            │ CVEs             │ Bots         │ Pkg Mgrs   │ Languages  │ Active       │ Worth │
├─────────────────┼──────────────────┼──────────────┼────────────┼────────────┼──────────────┼───────┤
│ gogf/gf         │ 8 CRIT, 338 HIGH │ none         │ go modules │ Go, Shell  │ YES (moderate)│ YES   │
│ locustio/locust │ 16 HIGH, 5 MED   │ dependabot ✓ │ pip, yarn  │ Python, TS │ YES (high+)  │ YES   │
└─────────────────┴──────────────────┴──────────────┴────────────┴────────────┴──────────────┴───────┘

  Summary: 2 repos scanned, 2 worth contributing to

Reports written to:
  JSON: reports/audit-2026-08-18_12-01-20.json
  HTML: reports/audit-2026-08-18_12-01-20.html
```

### Console indicators

- **Bots column:** `dependabot ✓` = bot active (merging), `dependabot ✗` = bot ignored, `dependabot …` = bot backlogged
- **Active column:** `+` suffix means the count hit a pagination cap (actual activity is higher)
- **Worth column:** `YES` / `MAYBE` / `NO` — the final triage verdict

## CLI Options

| Flag | Description |
|------|-------------|
| `--no-cache` | Ignore cached results and re-scan everything |
| `--clear-cache` | Clear all cached results before running |
| `-o`, `--output` | Custom filename prefix for reports (default: `audit-TIMESTAMP`) |
| `--trivy-only` | Disable OSV-Scanner fallback — fail the scan instead of silently losing transitive coverage |

## How caching works

Results are cached in `.audit-cache/` with a 24-hour TTL. Re-running the same list within 24 hours skips already-scanned repos. Use `--no-cache` to force a fresh scan.

The triage verdict (`worth_contributing`) is always recomputed on cached data, so changes to the assessment logic take effect immediately without needing to re-scan.

## Project structure

```
repo-auditor/
├── auditor.py        # CLI entry point — orchestrates the pipeline + triage logic
├── scanner.py        # Trivy/OSV-Scanner wrapper — CVE scanning
├── github_api.py     # gh CLI wrapper — bots, community, openness, dep PR detection
├── detector.py       # Package manager and language detection
├── cache.py          # File-based scan cache (24hr TTL)
├── reporter.py       # Output formatting (console table, JSON, HTML)
├── reports/          # Generated reports (timestamped)
└── repos.txt         # Your input file
```

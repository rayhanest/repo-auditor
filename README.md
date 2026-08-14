# repo-auditor

A CLI tool that audits GitHub repositories for CVE remediation opportunities. Given a list of repos, it scans for dependency vulnerabilities, detects dependency management bots, identifies package managers and languages, and assesses whether the community is active and open to external contributions.

Built to answer: **"Which repos are worth contributing CVE fixes to?"**

## What it checks

| Signal | Method |
|--------|--------|
| Dependency CVEs (direct + transitive) | Trivy filesystem scan against lockfiles |
| Dependency management bots | Commit/PR author analysis for known bot patterns |
| Package managers | Lockfile and manifest detection |
| Languages | GitHub API language breakdown |
| Community activity | Commits, contributors, and issues in last 90 days |
| External contributor openness | CONTRIBUTING.md, "good first issue" labels, merged external PRs |

## Prerequisites

- **Python 3.10+**
- **git**
- **[Trivy](https://github.com/aquasecurity/trivy)** — for vulnerability scanning
- **[GitHub CLI (gh)](https://cli.github.com/)** — authenticated (`gh auth login`)

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
- A **JSON report** with full details (individual CVEs, versions, etc.)
- An **HTML report** for readable, shareable viewing

All reports are saved to `reports/` with timestamped filenames.

### Example output

```
Auditing 2 repos...

[1/2] docker/compose
  Cloning docker/compose...
  Detecting package managers...
  Running Trivy CVE scan...
  Checking for bots...
  Gathering community health...
  Assessing contributor openness...

[2/2] expressjs/express
  ...

┌──────────────────┬──────────────┬────────────┬────────────┬────────────┬──────────────┬──────────────┐
│ Repo             │ CVEs         │ Bots       │ Pkg Mgrs   │ Languages  │ Active       │ Ext Contribs │
├──────────────────┼──────────────┼────────────┼────────────┼────────────┼──────────────┼──────────────┤
│ docker/compose   │ 3 HIGH, 2 MED│ dependabot │ go modules │ Go, Shell  │ YES (high)   │ YES          │
│ expressjs/express│ 1 MED        │ none       │ npm        │ JavaScript │ YES (moderate)│ YES          │
└──────────────────┴──────────────┴────────────┴────────────┴────────────┴──────────────┴──────────────┘

  Summary: 2 repos scanned, 6 total CVEs, 2 open to contributions

Reports written to:
  JSON: reports/audit-2026-08-14_14-30-00.json
  HTML: reports/audit-2026-08-14_14-30-00.html
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--no-cache` | Ignore cached results and re-scan everything |
| `--clear-cache` | Clear all cached results before running |
| `-o`, `--output` | Custom filename prefix for reports (default: `audit-TIMESTAMP`) |

## How caching works

Results are cached in `.audit-cache/` with a 24-hour TTL. Re-running the same list within 24 hours skips already-scanned repos. Use `--no-cache` to force a fresh scan.

## Project structure

```
repo-auditor/
├── auditor.py        # CLI entry point — orchestrates the pipeline
├── scanner.py        # Trivy wrapper — CVE scanning
├── github_api.py     # gh CLI wrapper — bots, community, contributor openness
├── detector.py       # Package manager and language detection
├── cache.py          # File-based scan cache (24hr TTL)
├── reporter.py       # Output formatting (console table, JSON, HTML)
├── reports/          # Generated reports (timestamped)
└── repos.txt         # Your input file
```


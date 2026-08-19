```
                         ┌─────────────────┐
                         │  Start: Assess  │
                         │     Triage      │
                         └────────┬────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       Has CVEs?            │
                    └─────────────┬──────────────┘
                          no │          │ yes
                    ┌────────▼───┐      │
                    │  NO: noth- │      │
                    │  ing to fix│      │
                    └────────────┘      │
                                        │
                    ┌───────────────────▼────────────────┐
                    │           Archived?                │
                    └───────────────────┬────────────────┘
                              yes │          │ no
                    ┌─────────────▼──┐       │
                    │  NO: can't     │       │
                    │  accept PRs    │       │
                    └────────────────┘       │
                                             │
                    ┌────────────────────────▼───────────────────┐
                    │           Dormant? (0 commits 90d)         │
                    └────────────────────────┬───────────────────┘
                                   yes │          │ no
                    ┌──────────────────▼──┐       │
                    │  NO: no one to      │       │
                    │  review a PR        │       │
                    └─────────────────────┘       │
                                                  │
                    ┌─────────────────────────────▼──────────────────────────┐
                    │  2+ dep/CVE PRs closed AND 0 merged?                  │
                    └─────────────────────────────┬──────────────────────────┘
                                        yes │          │ no
                    ┌───────────────────────▼──┐       │
                    │  NO: project rejects     │       │
                    │  this work               │       │
                    └──────────────────────────┘       │
                                                       │
                    ┌──────────────────────────────────▼─────────────────────────┐
                    │  Dep/CVE PRs merged > 0 AND open to contributions?         │
                    └──────────────────────────────────┬─────────────────────────┘
                                             yes │          │ no
                    ┌────────────────────────────▼──┐       │
                    │  YES                          │       │
                    │  + note if bot active         │       │
                    │  + note if some closed        │       │
                    │  + note if low activity       │       │
                    └───────────────────────────────┘       │
                                                            │
                    ┌───────────────────────────────────────▼────────────────────────────┐
                    │  Open to contributions AND (no bot OR bot ignored/backlogged)?      │
                    └───────────────────────────────────────┬────────────────────────────┘
                                                  yes │          │ no
                    ┌─────────────────────────────────▼──┐       │
                    │  YES                               │       │
                    │  + reason (no bot / ignored /      │       │
                    │    backlogged)                      │       │
                    │  + note if low activity            │       │
                    └────────────────────────────────────┘       │
                                                                 │
                    ┌────────────────────────────────────────────▼───────────────────┐
                    │  Has dep bot AND bot actively merging?                         │
                    └────────────────────────────────────────────┬───────────────────┘
                                                      yes │          │ no
                    ┌─────────────────────────────────────▼──┐       │
                    │  MAYBE: established workflow,           │       │
                    │  check for duplicates                   │       │
                    └────────────────────────────────────────┘       │
                                                                     │
                    ┌────────────────────────────────────────────────▼────────────────┐
                    │  Dep/CVE PRs merged > 0 AND NOT open to contributions?          │
                    └────────────────────────────────────────────────┬────────────────┘
                                                          yes │          │ no
                    ┌─────────────────────────────────────────▼──┐       │
                    │  MAYBE: maintain dep health but             │       │
                    │  haven't shown openness                     │       │
                    └────────────────────────────────────────────┘       │
                                                                         │
                                                            ┌────────────▼────────────┐
                                                            │  MAYBE: not clearly     │
                                                            │  open, but has CVEs     │
                                                            │  worth fixing           │
                                                            └─────────────────────────┘
```

## Edge cases and notes

**Notes attached conditionally (don't change verdict, just add context):**
- `bot_pr_responsiveness == "active"` on a YES → "check for duplicates"
- `dep_prs_closed > 0` on a YES → "review carefully"
- `activity_level == "low"` on a YES → "reviews may be slow"
- `bot_pr_responsiveness == "backlogged"` → "check for duplicates before submitting"

**Known edge cases:**
1. Very active repos (100-PR window covers only days) → may undercount external PRs → could miss openness signal → falls to MAYBE instead of YES
2. Squash-merge repos → contributor count understated (commits attributed to merger) → activity level accurate but contributor count misleading
3. Author-abandoned PRs showing as "closed" → 1 closed is tolerated, 2+ triggers NO
4. Bot configured but no PRs created yet → detected via config file, responsiveness = "unknown" → treated same as no bot for triage purposes
5. Repo with CONTRIBUTING.md + labels but 0 external PRs merged → NOT open (docs alone insufficient)

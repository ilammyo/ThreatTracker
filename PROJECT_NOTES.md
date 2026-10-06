# ThreatTracker Project Notes

## What We Are Trying To Do

Turn a firehose of public vulnerability feeds into a daily brief that is
actually worth opening, hosted safely as a static GitHub Pages site.

The model:

- GitHub Actions fetches public security feeds on a 6-hour schedule
- `scripts/build_data.py` normalizes, cross-references and scores them into static JSON
- GitHub Pages serves a read-only frontend from `docs/`
- Browsers only load static HTML, CSS, JavaScript, and JSON

## History

- **v1 (March 2026).** Replaced a local Flask + SQLite dashboard with the
  static model. Sources: CISA KEV, NVD, MSRC, Apple. One flat table of
  roughly 20,000 rows sorted by date.
- **Stall (June to October 2026).** GitHub paused the cron schedule after 60
  days without commits. Nobody noticed for four months, which showed the
  real problem: the page was not useful enough to visit.
- **v2 (October 2026).** Product rework. Stack watchlist, EPSS, parsed
  exploitation signals, five vendor sources, "This week" brief, dismissals,
  first-seen tracking, per-source fallback, schedule keep-alive.

## Scope Decisions

- **Default to the stack.** The dashboard opens filtered to `watchlist.json`.
  "Everything" is one click away for research.
- **NVD stays, but as a long tail.** Most NVD rows are irrelevant and lack
  CPE data at publication. They are kept for search and KEV enrichment, with
  descriptions trimmed when neither relevant nor exploited.
- **Chrome is in.** v1 excluded Google feeds. Chrome is on every endpoint
  and its "exploit exists in the wild" notes matter, so stable-channel
  desktop releases are included. Other Google feeds remain out.
- **Okta's feed is a blog.** sec.okta.com mixes research posts with
  advisories. Rows are tagged `[Advisory]` or `[Blog]` by keyword. The Okta
  Trust page has no machine-readable feed.
- **Shallow feeds accumulate.** Chrome, Fortinet, AWS, Zoom, Okta and Apple
  expose only recent items. Previous rows within 90 days are carried forward
  each build so history builds up.
- **Dismissals are per browser.** A static site has no shared state. The
  brief is a personal reading list, so localStorage is acceptable.

## Current Architecture

- `watchlist.json` - stack definitions, EPSS threshold
- `scripts/build_data.py` - fetchers, enrichment, watchlist, output
- `docs/data/alerts.json` - watchlist, exploited and vendor rows (compact JSON, not committed)
- `docs/data/alerts-tail.json` - the NVD long tail, loaded on demand
- `docs/data/summary.json` - counts, watchlist names, week stats
- `docs/data/status.json` - per-source status: ok / stale / error
- `docs/index.html`, `docs/app.js`, `docs/style.css` - dashboard
- `.github/workflows/deploy-pages.yml` - build, keep-alive, deploy
- `.github/dependabot.yml` - monthly bumps for pinned actions

## Alert Fields Worth Knowing

- `relevant`, `matched[]` - watchlist result
- `actively_exploited`, `exploit_source` - `kev` or `vendor`
- `publicly_disclosed`, `ransomware`, `due_date`, `required_action`
- `epss`, `epss_percentile`
- `first_seen` - build timestamp the row first appeared
- `shadowed` - NVD row whose CVE another source already covers; hidden by default
- `cve_ids[]` - all CVEs on a release-type row (Apple, Chrome, Fortinet)

## Ideas Not Yet Done

- Push notifications: an Atom feed of brief items, or a Teams/Slack webhook
  post for KEV additions matching the watchlist.
- Seed the watchlist from the Trelica app inventory.
- Fold the threat-brief skill's news feeds into the same build.
- SSVC decision points from NVD (`ssvcV203` metrics) as another signal.

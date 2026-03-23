# ThreatTracker

ThreatTracker is a static threat feed dashboard designed for GitHub Pages.

The deployed site is plain HTML, CSS, JavaScript, and generated JSON. Feed
collection happens during a build step, not in the browser and not in a live
Python web server.

## What It Does

- Fetches public security advisories from:
  - CISA KEV
  - NVD
  - Microsoft MSRC
  - Apple security updates
- Normalizes them into JSON files under `docs/data/`
- Serves a read-only dashboard from `docs/`
- Supports scheduled GitHub Actions refreshes

## Local Build

```bash
python3 scripts/build_data.py
python3 -m http.server 8000 --directory docs
```

Then open `http://127.0.0.1:8000`.

## GitHub Pages

This repository includes a GitHub Actions workflow that:

1. Builds fresh feed data
2. Uploads the `docs/` directory as a Pages artifact
3. Deploys it to GitHub Pages

Enable GitHub Pages in the repository settings and select GitHub Actions as the
source.

## Notes

- No Flask server is required for production hosting.
- No browser-side third-party CDN dependencies are used.
- The site is read-only once deployed.
- Google-focused feeds are intentionally excluded from this version.

## Project Direction

The goal of this repository is to replace a locally running Flask dashboard with
a safer hosted model:

- Feed collection happens in GitHub Actions on a schedule
- Normalized alert data is written to JSON under `docs/data/`
- GitHub Pages serves a static, read-only dashboard
- Browsers only download static assets and generated JSON
- No live app server, local SQLite database, or browser-triggered feed refresh is required

This keeps the workstation footprint low while preserving a useful threat feed dashboard.

# ThreatTracker Project Notes

## What We Are Trying To Do

This project exists to turn a local threat feed dashboard into something that is
safe and simple to host on GitHub Pages.

The intended model is:

- GitHub Actions fetches public security feeds on a schedule
- A Python build script normalizes the feed data into static JSON files
- GitHub Pages serves a read-only frontend from `docs/`
- End users only load static HTML, CSS, JavaScript, and JSON

## Why This Direction

The previous approach depended on:

- A local Flask server
- A local SQLite database
- On-demand outbound network requests from the machine viewing the dashboard

That is workable, but it is a worse fit for a work machine and cannot be hosted
on GitHub Pages.

The static-site approach is better because:

- GitHub Pages can host it directly
- The browser does not need to fetch feeds from vendors
- There is no long-running app server to maintain
- The deployed site is read-only

## Scope Decisions

This version intentionally excludes Google-focused sources:

- Chrome releases
- Google Cloud / GCP bulletins

That keeps the dashboard aligned with the feeds the owner actually cares about.

## Current Architecture

- `scripts/build_data.py`
  - Fetches and normalizes supported feeds
- `docs/data/*.json`
  - Generated output consumed by the frontend
- `docs/index.html`
  - Static dashboard shell
- `docs/app.js`
  - Client-side filtering, sorting, and rendering
- `.github/workflows/deploy-pages.yml`
  - Scheduled build and Pages deployment

## Expected Deployment Flow

1. Push to `main`
2. Enable GitHub Pages with GitHub Actions as the source
3. Let the workflow build and deploy the site
4. Use manual dispatch or the 6-hour schedule to refresh feed data

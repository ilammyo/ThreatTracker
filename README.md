# ThreatTracker

ThreatTracker is a static vulnerability and advisory dashboard hosted on
GitHub Pages, filtered to the products we actually run.

The deployed site is plain HTML, CSS, JavaScript, and generated JSON. Feed
collection happens in a GitHub Actions build step every 6 hours, not in the
browser.

Live site: https://ilammyo.github.io/ThreatTracker/

## What It Does

Pulls public security feeds:

| Source | What we take from it |
| --- | --- |
| CISA KEV | Exploited CVEs, due dates, required action, ransomware flag |
| NVD | CVEs published in the last 90 days, CVSS (v3.1/v4/v3/v2), CPE vendor and product |
| Microsoft MSRC | Three months of CVRF: CVSS, product family, "Exploited: Yes", "Publicly Disclosed: Yes" |
| Apple | Security releases with CVE lists and the "may have been exploited" note |
| Fortinet PSIRT | Advisories with CVSS and in-the-wild exploitation notes |
| Chrome Releases | Stable channel desktop updates with CVE counts and in-the-wild notes |
| Zoom | Security bulletins with severity and CVE |
| AWS | Security bulletins |
| Okta | Security blog and advisories |
| FIRST EPSS | Exploitation probability for every CVE |

Then enriches and prioritizes:

- **Watchlist.** `watchlist.json` lists the stack. Matching alerts are flagged
  `relevant` and the dashboard defaults to showing only those. Toggle to
  "Everything" for the full feed.
- **Cross-referencing.** KEV rows inherit CVSS, vendor and product from NVD.
  Any row whose CVE is in KEV is marked exploited with its due date.
- **First seen.** Each row remembers the build in which it first appeared, so
  "NEW" means new to the dashboard, not merely recently published.
- **Resilience.** If a source fails, the previous build's rows for that source
  are reused and the feed is marked `stale` rather than silently disappearing.
- **Duplicates.** An NVD row whose CVE is already described by a vendor
  advisory or KEV row is marked `shadowed` and hidden by default.
- **Payload split.** `alerts.json` holds watchlist, exploited and vendor rows.
  The NVD long tail lives in `alerts-tail.json` and loads only when the
  dashboard is switched to "Everything".

The dashboard opens with a "This week" brief: exploited-in-the-wild items,
watchlist products rated Critical or with high EPSS, KEV remediation due
dates, and vendor patch releases. Items can be dismissed per browser.

## Local Build

```bash
python3 scripts/build_data.py
python3 -m http.server 8000 --directory docs
```

Then open `http://127.0.0.1:8000`.

Environment variables:

| Variable | Purpose |
| --- | --- |
| `NVD_API_KEY` | Optional. Raises the NVD rate limit from 5 to 50 requests per 30 seconds. Store in a repo secret, never in the file. |
| `PREVIOUS_DATA_URL` | Where to load the previous build's `alerts.json` for first-seen tracking and fallback. Defaults to the live site. Set empty to use the local file only. |
| `THREATTRACKER_FETCH` | `urllib` (default) or `curl`. The curl backend exists for proxies that truncate Python downloads. |
| `THREATTRACKER_CACHE_DIR` | Local development only. Caches raw feed responses so rebuilds skip the five-minute NVD paging. |

## Editing the Watchlist

Each entry in `watchlist.json` has:

- `terms`: matched whole-word, case-insensitive, against vendor, product,
  title and description. Use for distinctive names (okta, fortigate).
- `strict_terms`: matched against vendor, product and title only. Use for
  words that appear in unrelated descriptions (windows, apple, chrome).
- `cpe_vendors`: matched against the primary vendor of NVD CPE strings.
  NVD rows are matched only this way plus `terms`, because their CPE product
  lists include platforms such as "windows".
- `cpe_products`: when set, a CPE vendor hit also needs one of these in the
  product (Google Chrome: vendor google, product chrome).
- `exclude_products`: skip the match when the product contains one of these
  (Microsoft: Azure Linux republications).
- `msrc_families`: for the Microsoft entry, which MSRC product families
  count. Leaves out Azure Linux and other open-source republications.

## GitHub Pages

The workflow in `.github/workflows/deploy-pages.yml`:

1. Builds fresh feed data
2. Stamps a cache-busting version into `index.html`
3. Re-enables itself so GitHub's 60-day inactivity rule does not pause the schedule
4. Uploads `docs/` as a Pages artifact and deploys it

## Notes

- No browser-side third-party dependencies. A strict Content Security Policy is set.
- The site is read-only once deployed. Dismissals live in the viewer's browser only.
- Generated JSON under `docs/data/` is not committed.

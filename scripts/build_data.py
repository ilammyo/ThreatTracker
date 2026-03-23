#!/usr/bin/env python3
"""Build ThreatTracker static data files for GitHub Pages."""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
DATA_DIR = DOCS_DIR / "data"

USER_AGENT = "ThreatTracker/1.0"
DEFAULT_DAYS = 30
NVD_FETCH_DAYS = 7
NVD_REQUEST_DELAY = 6

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MSRC_API_URL = "https://api.msrc.microsoft.com"
APPLE_SECURITY_URL = "https://support.apple.com/en-us/100100"


def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def fetch(url: str, extra_headers: dict[str, str] | None = None) -> bytes:
    ctx = ssl.create_default_context()
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        return resp.read()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_date(date_text: str) -> str:
    if not date_text:
        return ""
    date_text = date_text.strip()
    try:
        if len(date_text) >= 10 and date_text[4] == "-":
            return date_text[:10]
    except IndexError:
        pass

    for fmt in ("%d %b %Y", "%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_text, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return date_text[:10]


def entry_child(entry: ET.Element, ns: dict[str, str], tag: str) -> ET.Element | None:
    node = entry.find(f"atom:{tag}", ns)
    if node is None:
        node = entry.find(tag)
    return node


def element_text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return "".join(node.itertext()).strip()


class AppleTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.entries: list[dict[str, str]] = []
        self.in_table = False
        self.in_row = False
        self.in_cell = False
        self.current_row: list[str] = []
        self.current_cell = ""
        self.current_link: str | None = None
        self.cell_index = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "table":
            self.in_table = True
        elif tag == "tr" and self.in_table:
            self.in_row = True
            self.current_row = []
            self.current_link = None
            self.cell_index = 0
        elif tag == "td" and self.in_row:
            self.in_cell = True
            self.current_cell = ""
            self.cell_index += 1
        elif tag == "a" and self.in_cell and self.cell_index == 1:
            href = attrs_dict.get("href")
            if href:
                self.current_link = href

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self.in_cell:
            self.in_cell = False
            self.current_row.append(self.current_cell.strip())
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if len(self.current_row) >= 2:
                self.entries.append(
                    {
                        "name": self.current_row[0],
                        "link": self.current_link or "",
                        "date": self.current_row[-1],
                    }
                )
        elif tag == "table":
            self.in_table = False

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            self.current_cell += data


@dataclass
class FetchResult:
    source: str
    alerts: list[dict[str, Any]]
    status: str
    error: str = ""


def make_alert(source: str, alert_id: str, title: str, published_date: str, **kwargs: Any) -> dict[str, Any]:
    return {
        "id": alert_id,
        "source": source,
        "cve_id": kwargs.get("cve_id"),
        "title": title,
        "description": kwargs.get("description"),
        "severity": kwargs.get("severity", "UNKNOWN"),
        "cvss_score": kwargs.get("cvss_score"),
        "vendor": kwargs.get("vendor"),
        "product": kwargs.get("product"),
        "published_date": published_date,
        "url": kwargs.get("url"),
        "actively_exploited": kwargs.get("actively_exploited", 0),
    }


def fetch_kev() -> FetchResult:
    data = json.loads(fetch(CISA_KEV_URL))
    alerts = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        alerts.append(
            make_alert(
                "kev",
                f"kev:{cve_id}",
                f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} - {vuln.get('vulnerabilityName', '')}".strip(),
                normalize_date(vuln.get("dateAdded", "")),
                cve_id=cve_id,
                description=vuln.get("shortDescription"),
                vendor=vuln.get("vendorProject"),
                product=vuln.get("product"),
                severity="UNKNOWN",
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
                actively_exploited=1,
            )
        )
    return FetchResult("kev", alerts, "ok")


def fetch_nvd() -> FetchResult:
    all_alerts: list[dict[str, Any]] = []
    start_index = 0
    results_per_page = 200
    end = datetime.utcnow()
    start = end - timedelta(days=NVD_FETCH_DAYS)
    pub_start = start.strftime("%Y-%m-%dT00:00:00.000")
    pub_end = end.strftime("%Y-%m-%dT23:59:59.999")

    while True:
        url = (
            f"{NVD_API_URL}"
            f"?pubStartDate={pub_start}"
            f"&pubEndDate={pub_end}"
            f"&startIndex={start_index}"
            f"&resultsPerPage={results_per_page}"
        )
        raw = fetch(url)
        data = json.loads(raw)
        total = data.get("totalResults", 0)

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    break

            desc = ""
            for entry in cve.get("descriptions", []):
                if entry.get("lang") == "en":
                    desc = entry.get("value", "")
                    break

            all_alerts.append(
                make_alert(
                    "nvd",
                    f"nvd:{cve_id}",
                    cve_id,
                    normalize_date(cve.get("published", "")),
                    cve_id=cve_id,
                    description=desc[:1000] if desc else None,
                    severity=cvss_to_severity(cvss_score),
                    cvss_score=cvss_score,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )

        start_index += results_per_page
        if start_index >= total:
            break
        time.sleep(NVD_REQUEST_DELAY)

    return FetchResult("nvd", all_alerts, "ok")


def fetch_msrc() -> FetchResult:
    all_alerts: list[dict[str, Any]] = []
    now = datetime.utcnow()
    months = [now, now.replace(day=1) - timedelta(days=1)]

    for dt in months:
        month_id = dt.strftime("%Y-%b")
        url = f"{MSRC_API_URL}/cvrf/v3.0/document/{month_id}"
        try:
            raw = fetch(url, {"Accept": "application/json"})
        except urllib.error.HTTPError:
            continue
        data = json.loads(raw)
        doc_date = normalize_date(data.get("DocumentTracking", {}).get("CurrentReleaseDate", ""))

        for vuln in data.get("Vulnerability", []):
            cve_id = vuln.get("CVE", "")
            title = vuln.get("Title", {}).get("Value", cve_id)
            cvss_score = None
            for score_set in vuln.get("CVSSScoreSets", []):
                base = score_set.get("BaseScore")
                if base is not None:
                    score = float(base)
                    if cvss_score is None or score > cvss_score:
                        cvss_score = score

            severity = cvss_to_severity(cvss_score)
            if severity == "UNKNOWN":
                for threat in vuln.get("Threats", []):
                    if threat.get("Type") == 3:
                        sev_text = threat.get("Description", {}).get("Value", "").upper()
                        mapping = {"IMPORTANT": "HIGH", "MODERATE": "MEDIUM"}
                        if sev_text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "IMPORTANT", "MODERATE"}:
                            severity = mapping.get(sev_text, sev_text)
                            break

            desc = ""
            for note in vuln.get("Notes", []):
                if note.get("Type") in (1, 2):
                    candidate = re.sub(r"<[^>]+>", "", note.get("Value", "")).strip()
                    if candidate:
                        desc = candidate
                        break

            published = doc_date
            revisions = vuln.get("RevisionHistory", [])
            if revisions:
                published = normalize_date(revisions[0].get("Date", doc_date))

            all_alerts.append(
                make_alert(
                    "msrc",
                    f"msrc:{cve_id}",
                    title,
                    published,
                    cve_id=cve_id if cve_id.startswith("CVE-") else None,
                    description=desc[:1000] if desc else None,
                    severity=severity,
                    cvss_score=cvss_score,
                    vendor="Microsoft",
                    url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                )
            )

    return FetchResult("msrc", all_alerts, "ok")


def fetch_apple() -> FetchResult:
    parser = AppleTableParser()
    parser.feed(fetch(APPLE_SECURITY_URL).decode("utf-8", errors="replace"))
    alerts = []

    for entry in parser.entries:
        name = entry["name"]
        date_str = entry["date"]
        link = entry["link"]
        if not name or not date_str or "Name and information link" in name:
            continue
        published = normalize_date(date_str)
        if link and not link.startswith("http"):
            link = f"https://support.apple.com{link}"
        path_match = re.search(r"/(\d+)$", link or "")
        alert_id = f"apple:{path_match.group(1)}" if path_match else f"apple:{abs(hash(name)) % 1000000}"
        alerts.append(
            make_alert(
                "apple",
                alert_id,
                name,
                published,
                severity="UNKNOWN",
                vendor="Apple",
                url=link or None,
            )
        )

    return FetchResult("apple", alerts, "ok")


FETCHERS = [
    fetch_kev,
    fetch_nvd,
    fetch_msrc,
    fetch_apple,
]


def build() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    run_started = utc_now()
    status_rows = []
    alerts: list[dict[str, Any]] = []

    for fetcher in FETCHERS:
        source = fetcher.__name__.removeprefix("fetch_")
        try:
            result = fetcher()
            alerts.extend(result.alerts)
            status_rows.append(
                {
                    "source": result.source,
                    "last_fetched": run_started,
                    "status": result.status,
                    "error_message": result.error,
                    "count": len(result.alerts),
                }
            )
        except Exception as exc:
            status_rows.append(
                {
                    "source": source,
                    "last_fetched": run_started,
                    "status": "error",
                    "error_message": str(exc)[:300],
                    "count": 0,
                }
            )

    kev_cves = {alert["cve_id"] for alert in alerts if alert["source"] == "kev" and alert.get("cve_id")}
    for alert in alerts:
        if alert.get("cve_id") in kev_cves and alert["source"] != "kev":
            alert["actively_exploited"] = 1

    alerts = [alert for alert in alerts if alert.get("published_date")]
    alerts.sort(
        key=lambda item: (
            item.get("published_date", ""),
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(item.get("severity", "UNKNOWN"), 5),
            item.get("source", ""),
        ),
        reverse=True,
    )

    cutoff = (datetime.utcnow() - timedelta(days=DEFAULT_DAYS)).strftime("%Y-%m-%d")
    recent_alerts = [alert for alert in alerts if alert["published_date"] >= cutoff]

    summary = {
        "generated_at": run_started,
        "total_alerts": len(alerts),
        "recent_alerts": len(recent_alerts),
        "default_days": DEFAULT_DAYS,
        "sources": sorted({alert["source"] for alert in alerts}),
        "counts": {
            "CRITICAL": sum(1 for item in recent_alerts if item.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for item in recent_alerts if item.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for item in recent_alerts if item.get("severity") == "MEDIUM"),
            "LOW": sum(1 for item in recent_alerts if item.get("severity") == "LOW"),
            "UNKNOWN": sum(1 for item in recent_alerts if item.get("severity") == "UNKNOWN"),
        },
    }

    (DATA_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    (DATA_DIR / "status.json").write_text(json.dumps(status_rows, indent=2), encoding="utf-8")
    (DATA_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {len(alerts)} alerts to {DATA_DIR}")


if __name__ == "__main__":
    build()

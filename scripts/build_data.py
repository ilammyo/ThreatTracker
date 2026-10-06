#!/usr/bin/env python3
"""Build ThreatTracker static data files for GitHub Pages.

Pipeline:
  1. Load the stack watchlist (watchlist.json) and the previous build's
     alerts (from the live site, or docs/data/alerts.json locally).
  2. Fetch every source. A source that fails falls back to its previous
     rows (status "stale") so one flaky API does not blank the dashboard.
  3. Enrich: NVD CVSS/CPE lookups for KEV CVEs, EPSS scores, cross-source
     severity and vendor inheritance, watchlist relevance, first_seen.
  4. Write docs/data/alerts.json, status.json, summary.json.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
DATA_DIR = DOCS_DIR / "data"
WATCHLIST_PATH = ROOT / "watchlist.json"

USER_AGENT = "ThreatTracker/2.0 (+https://github.com/ilammyo/ThreatTracker)"
DEFAULT_DAYS = 90          # fetch / retention window
DEFAULT_VIEW_DAYS = 30     # default dashboard window
NVD_PAGE_SIZE = 2000       # API maximum
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_REQUEST_DELAY = 1.0 if NVD_API_KEY else 6.5   # 50 req/30s with key, 5 req/30s without
APPLE_DETAIL_LIMIT = 80
# Time budgets (seconds). A source that exceeds its budget stops where it is
# and reports status "partial" instead of risking the job timeout.
NVD_TIME_BUDGET = int(os.environ.get("NVD_TIME_BUDGET", "900"))
APPLE_TIME_BUDGET = int(os.environ.get("APPLE_TIME_BUDGET", "120"))
PREVIOUS_DATA_URL = os.environ.get(
    "PREVIOUS_DATA_URL", "https://ilammyo.github.io/ThreatTracker/data/alerts.json"
)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MSRC_API_URL = "https://api.msrc.microsoft.com"
APPLE_SECURITY_URL = "https://support.apple.com/en-us/100100"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
FORTINET_RSS_URL = "https://www.fortiguard.com/rss/ir.xml"
OKTA_RSS_URL = "https://sec.okta.com/rss.xml"
AWS_RSS_URL = "https://aws.amazon.com/security/security-bulletins/rss/feed/"
CHROME_ATOM_URL = "https://chromereleases.googleblog.com/feeds/posts/default"
ZOOM_BULLETIN_URL = "https://www.zoom.com/en/trust/security-bulletin/"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
TAG_RE = re.compile(r"<[^>]+>")
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# Sources whose feeds only expose a shallow window; previous rows are kept
# so history accumulates across builds.
ACCUMULATING_SOURCES = {"apple", "fortinet", "okta", "zoom", "aws", "chrome"}
# Sources whose every row is inherently about a stack vendor.
VENDOR_SOURCES = {"apple", "fortinet", "okta", "zoom", "aws", "chrome"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


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


FETCH_BACKEND = os.environ.get("THREATTRACKER_FETCH", "urllib").lower()  # "urllib" (default) or "curl"
FETCH_CACHE_DIR = os.environ.get("THREATTRACKER_CACHE_DIR", "").strip()  # local dev only: caches raw responses


def _http_get(url: str, headers: dict[str, str], timeout: int) -> bytes:
    if FETCH_BACKEND == "curl":
        # Debug fallback for environments whose proxy truncates urllib reads.
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            out_path = tmp.name
        cmd = ["curl", "-sSL", "--compressed", "--max-time", str(timeout), "-o", out_path, "-w", "%{http_code}", url]
        for key, value in headers.items():
            if key.lower() != "accept-encoding":
                cmd += ["-H", f"{key}: {value}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        try:
            body = Path(out_path).read_bytes()
        finally:
            Path(out_path).unlink(missing_ok=True)
        if proc.returncode != 0:
            raise urllib.error.URLError(proc.stderr.strip() or f"curl exit {proc.returncode}")
        code = int(proc.stdout.strip() or 0)
        if code >= 400:
            raise urllib.error.HTTPError(url, code, f"HTTP {code}", {}, None)  # type: ignore[arg-type]
        return body
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        body = resp.read()
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip" and not url.endswith(".gz"):
            body = gzip.decompress(body)
        return body


def fetch(url: str, extra_headers: dict[str, str] | None = None, retries: int = 3, timeout: int = 90) -> bytes:
    """GET with retry/backoff on transient failures."""
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity" if url.endswith(".gz") else "gzip"}
    if extra_headers:
        headers.update(extra_headers)
    cache_path: Path | None = None
    if FETCH_CACHE_DIR:
        cache_path = Path(FETCH_CACHE_DIR) / (hashlib.sha1(url.encode()).hexdigest() + ".bin")
        if cache_path.exists():
            return cache_path.read_bytes()
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            body = _http_get(url, headers, timeout)
            if cache_path is not None:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_bytes(body)
            return body
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code in (403, 429, 500, 502, 503, 504) and attempt < retries - 1:
                wait = 6 * (attempt + 1)
                log(f"  HTTP {exc.code} from {url[:80]} - retrying in {wait}s")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                wait = 6 * (attempt + 1)
                log(f"  {type(exc).__name__} from {url[:80]} - retrying in {wait}s")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"fetch failed: {last_exc}")


def strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", unescape(TAG_RE.sub(" ", text or ""))).strip()


def normalize_date(date_text: str) -> str:
    """Return YYYY-MM-DD from the various date shapes the feeds use."""
    if not date_text:
        return ""
    date_text = date_text.strip()
    if len(date_text) >= 10 and date_text[4] == "-" and date_text[7] == "-":
        return date_text[:10]
    for fmt in ("%d %b %Y", "%B %d, %Y", "%b %d, %Y", "%Y-%m-%d", "%m/%d/%Y", "%d %B %Y"):
        try:
            return datetime.strptime(date_text, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    try:
        return parsedate_to_datetime(date_text).astimezone(timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, IndexError):
        pass
    return ""


def stable_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]


def days_ago_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def rss_items(raw: bytes) -> list[dict[str, str]]:
    """Parse RSS 2.0 or Atom into a list of {title, link, date, description}."""
    root = ET.fromstring(raw)
    ns = {"a": "http://www.w3.org/2005/Atom", "content": "http://purl.org/rss/1.0/modules/content/"}
    items: list[dict[str, str]] = []
    for item in root.iter("item"):
        items.append(
            {
                "title": (item.findtext("title") or "").strip(),
                "link": (item.findtext("link") or item.findtext("guid") or "").strip(),
                "date": item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date") or "",
                "description": item.findtext("description") or item.findtext("content:encoded", namespaces=ns) or "",
            }
        )
    if items:
        return items
    for entry in root.findall("a:entry", ns):
        link = ""
        for node in entry.findall("a:link", ns):
            if node.get("rel") in (None, "alternate") and node.get("href"):
                link = node.get("href", "")
                break
        items.append(
            {
                "title": (entry.findtext("a:title", namespaces=ns) or "").strip(),
                "link": link,
                "date": entry.findtext("a:published", namespaces=ns) or entry.findtext("a:updated", namespaces=ns) or "",
                "description": entry.findtext("a:content", namespaces=ns) or entry.findtext("a:summary", namespaces=ns) or "",
            }
        )
    return items


class TableParser(HTMLParser):
    """Collects every <tr> inside <table> as a list of (cell_text, first_href) tuples."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[tuple[str, str]]] = []
        self.depth = 0
        self.in_row = False
        self.in_cell = False
        self.current_row: list[tuple[str, str]] = []
        self.cell_text = ""
        self.cell_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self.depth += 1
        elif tag == "tr" and self.depth:
            self.in_row = True
            self.current_row = []
        elif tag in ("td", "th") and self.in_row:
            self.in_cell = True
            self.cell_text = ""
            self.cell_href = ""
        elif tag == "a" and self.in_cell and not self.cell_href:
            href = dict(attrs).get("href")
            if href:
                self.cell_href = href
        elif tag in ("br", "p") and self.in_cell:
            self.cell_text += " "

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self.in_cell:
            self.in_cell = False
            self.current_row.append((re.sub(r"\s+", " ", self.cell_text).strip(), self.cell_href))
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if self.current_row:
                self.rows.append(self.current_row)
        elif tag == "table" and self.depth:
            self.depth -= 1

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            self.cell_text += data


# --------------------------------------------------------------------------
# Alert model
# --------------------------------------------------------------------------

@dataclass
class FetchResult:
    source: str
    alerts: list[dict[str, Any]]
    status: str = "ok"
    error: str = ""
    note: str = ""


def make_alert(source: str, alert_id: str, title: str, published_date: str, **kwargs: Any) -> dict[str, Any]:
    cve_ids = kwargs.get("cve_ids") or ([kwargs["cve_id"]] if kwargs.get("cve_id") else [])
    return {
        "id": alert_id,
        "source": source,
        "cve_id": kwargs.get("cve_id"),
        "cve_ids": sorted(set(cve_ids)),
        "title": title,
        "description": kwargs.get("description"),
        "severity": kwargs.get("severity", "UNKNOWN"),
        "cvss_score": kwargs.get("cvss_score"),
        "vendor": kwargs.get("vendor"),
        "product": kwargs.get("product"),
        "published_date": published_date,
        "url": kwargs.get("url"),
        "actively_exploited": 1 if kwargs.get("actively_exploited") else 0,
        "exploit_source": kwargs.get("exploit_source"),      # "kev" | "vendor" | None
        "publicly_disclosed": 1 if kwargs.get("publicly_disclosed") else 0,
        "ransomware": 1 if kwargs.get("ransomware") else 0,
        "due_date": kwargs.get("due_date"),
        "required_action": kwargs.get("required_action"),
        "epss": None,
        "epss_percentile": None,
        "relevant": False,
        "matched": [],
        "first_seen": None,
        "shadowed": 0,
    }


# --------------------------------------------------------------------------
# Fetchers
# --------------------------------------------------------------------------

def fetch_kev() -> FetchResult:
    data = json.loads(fetch(CISA_KEV_URL))
    alerts = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "") or ""
        product = vuln.get("product", "") or ""
        name = vuln.get("vulnerabilityName", "") or ""
        # KEV names usually already start with "<vendor> <product>"; avoid "Apple Multiple Products - Apple Multiple Products ..."
        title = name if name.lower().startswith(f"{vendor} {product}".strip().lower()) or product.lower() in name.lower() else f"{vendor} {product} - {name}".strip(" -")
        alerts.append(
            make_alert(
                "kev",
                f"kev:{cve_id}",
                title,
                normalize_date(vuln.get("dateAdded", "")),
                cve_id=cve_id,
                description=vuln.get("shortDescription"),
                vendor=vuln.get("vendorProject"),
                product=vuln.get("product"),
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}" if cve_id else None,
                actively_exploited=True,
                exploit_source="kev",
                ransomware=str(vuln.get("knownRansomwareCampaignUse", "")).lower() == "known",
                due_date=normalize_date(vuln.get("dueDate", "")) or None,
                required_action=vuln.get("requiredAction"),
            )
        )
    return FetchResult("kev", alerts)


def nvd_extract(cve: dict[str, Any]) -> dict[str, Any]:
    """Pull CVSS, description, and CPE vendor/product out of an NVD CVE record."""
    cvss_score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            # Prefer the NVD-issued metric over CNA-issued when both exist.
            metric_list = sorted(metric_list, key=lambda m: 0 if m.get("type") == "Primary" else 1)
            cvss_score = metric_list[0].get("cvssData", {}).get("baseScore")
            break

    desc = ""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            desc = entry.get("value", "")
            break

    vendors: list[str] = []
    products: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and parts[0] == "cpe":
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    if vendor and vendor not in vendors:
                        vendors.append(vendor)
                    if product and product not in products:
                        products.append(product)

    return {
        "cvss_score": cvss_score,
        "severity": cvss_to_severity(cvss_score),
        "description": desc,
        "vendor": ", ".join(vendors[:3]) or None,
        "product": ", ".join(products[:3]) or None,
        "status": cve.get("vulnStatus"),
    }


def nvd_query(params: str, budget: float | None = None) -> tuple[list[dict[str, Any]], bool]:
    """Page through an NVD query. Returns (raw CVE records, complete)."""
    records: list[dict[str, Any]] = []
    start_index = 0
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else None
    started = time.monotonic()
    while True:
        url = f"{NVD_API_URL}?{params}&startIndex={start_index}&resultsPerPage={NVD_PAGE_SIZE}"
        page_started = time.monotonic()
        data = json.loads(fetch(url, headers, retries=3, timeout=120))
        page = data.get("vulnerabilities", [])
        records.extend(item.get("cve", {}) for item in page)
        total = data.get("totalResults", 0)
        start_index += NVD_PAGE_SIZE
        log(f"  nvd page {start_index // NVD_PAGE_SIZE}: {len(records)}/{total} in {time.monotonic() - page_started:.1f}s")
        if start_index >= total or not page:
            return records, True
        if budget is not None and time.monotonic() - started > budget:
            log(f"  nvd: time budget of {budget:.0f}s exceeded with {len(records)}/{total}; stopping early")
            return records, False
        time.sleep(NVD_REQUEST_DELAY)


def fetch_nvd() -> FetchResult:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DEFAULT_DAYS)
    params = f"pubStartDate={start.strftime('%Y-%m-%dT00:00:00.000')}&pubEndDate={end.strftime('%Y-%m-%dT23:59:59.999')}"
    alerts = []
    records, complete = nvd_query(params, budget=NVD_TIME_BUDGET)
    for cve in records:
        cve_id = cve.get("id", "")
        info = nvd_extract(cve)
        if info["status"] == "Rejected":
            continue
        alerts.append(
            make_alert(
                "nvd",
                f"nvd:{cve_id}",
                cve_id,
                normalize_date(cve.get("published", "")),
                cve_id=cve_id,
                description=info["description"][:1000] or None,
                severity=info["severity"],
                cvss_score=info["cvss_score"],
                vendor=info["vendor"],
                product=info["product"],
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    if not complete:
        return FetchResult("nvd", alerts, status="partial", note="NVD time budget exceeded; newest CVEs may be missing until the next run")
    return FetchResult("nvd", alerts)


def fetch_nvd_kev_lookup() -> dict[str, dict[str, Any]]:
    """NVD records for every KEV CVE, keyed by CVE. Used to enrich KEV rows
    that fall outside the 90-day NVD publish window."""
    time.sleep(NVD_REQUEST_DELAY)
    lookup = {}
    records, _complete = nvd_query("hasKev", budget=180)
    for cve in records:
        lookup[cve.get("id", "")] = nvd_extract(cve)
    return lookup


def msrc_family_map(product_tree: dict[str, Any]) -> dict[str, str]:
    """ProductID -> top-level family name (Windows, Browser, Microsoft Office, ...)."""
    mapping: dict[str, str] = {}

    def walk(items: list[dict[str, Any]], family: str | None) -> None:
        for node in items:
            if "Items" in node:
                walk(node["Items"], family or node.get("Name"))
            elif node.get("ProductID"):
                mapping[node["ProductID"]] = family or node.get("Value", "")

    for branch in product_tree.get("Branch", []):
        walk(branch.get("Items", []), None)
    for item in product_tree.get("FullProductName", []):
        pid = item.get("ProductID")
        if pid and pid not in mapping:
            value = item.get("Value", "")
            mapping[pid] = "Azure Linux" if "Azure Linux" in value else (value[:60] or "Other")
    return mapping


def fetch_msrc() -> FetchResult:
    all_alerts: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    months = [now, now.replace(day=1) - timedelta(days=1)]
    first_of_prev = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
    months.append(first_of_prev - timedelta(days=1))  # three months so Patch Tuesday gaps are covered

    seen_ids: set[str] = set()
    for dt in months:
        month_id = dt.strftime("%Y-%b")
        url = f"{MSRC_API_URL}/cvrf/v3.0/document/{month_id}"
        try:
            raw = fetch(url, {"Accept": "application/json"}, retries=2)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        data = json.loads(raw)
        doc_date = normalize_date(data.get("DocumentTracking", {}).get("CurrentReleaseDate", ""))
        families = msrc_family_map(data.get("ProductTree", {}))

        for vuln in data.get("Vulnerability", []):
            cve_id = vuln.get("CVE", "")
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            title = (vuln.get("Title") or {}).get("Value") or cve_id

            cvss_score = None
            for score_set in vuln.get("CVSSScoreSets", []):
                base = score_set.get("BaseScore")
                if base is not None:
                    score = float(base)
                    if cvss_score is None or score > cvss_score:
                        cvss_score = score

            severity = cvss_to_severity(cvss_score)
            exploited = False
            disclosed = False
            likely = False
            for threat in vuln.get("Threats", []):
                value = (threat.get("Description") or {}).get("Value", "")
                if threat.get("Type") == 1:
                    if "Exploited:Yes" in value:
                        exploited = True
                    if "Publicly Disclosed:Yes" in value:
                        disclosed = True
                    if "Exploitation More Likely" in value:
                        likely = True
                elif threat.get("Type") == 3 and severity == "UNKNOWN":
                    sev_text = value.upper()
                    mapping = {"IMPORTANT": "HIGH", "MODERATE": "MEDIUM"}
                    if sev_text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "IMPORTANT", "MODERATE"}:
                        severity = mapping.get(sev_text, sev_text)

            product_ids: list[str] = []
            for status in vuln.get("ProductStatuses", []):
                product_ids.extend(status.get("ProductID", []))
            family_names = sorted({families.get(pid, "") for pid in product_ids} - {""})

            desc = ""
            for note in vuln.get("Notes", []):
                if note.get("Type") in (1, 2):
                    candidate = strip_html(note.get("Value", ""))
                    if candidate:
                        desc = candidate
                        break
            flags = []
            if exploited:
                flags.append("Exploited in the wild")
            if disclosed:
                flags.append("Publicly disclosed")
            if likely:
                flags.append("Exploitation more likely")
            if flags:
                desc = f"[{'; '.join(flags)}] {desc}".strip()

            published = doc_date
            revisions = vuln.get("RevisionHistory", [])
            if revisions:
                published = normalize_date(revisions[0].get("Date", doc_date)) or doc_date

            all_alerts.append(
                make_alert(
                    "msrc",
                    f"msrc:{cve_id}",
                    title,
                    published,
                    cve_id=cve_id if cve_id.startswith("CVE-") else None,
                    description=desc[:1000] or None,
                    severity=severity,
                    cvss_score=cvss_score,
                    vendor="Microsoft",
                    product=", ".join(family_names) or None,
                    url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                    actively_exploited=exploited,
                    exploit_source="vendor" if exploited else None,
                    publicly_disclosed=disclosed,
                )
            )

    return FetchResult("msrc", all_alerts)


APPLE_NO_CVE_NOTE = "This update has no published CVE entries."


def fetch_apple(previous: dict[str, dict[str, Any]]) -> FetchResult:
    parser = TableParser()
    parser.feed(fetch(APPLE_SECURITY_URL).decode("utf-8", errors="replace"))
    cutoff = days_ago_iso(DEFAULT_DAYS)
    alerts = []
    detail_fetches = 0
    skipped_for_time = 0
    started = time.monotonic()
    for row in parser.rows:
        if len(row) < 2:
            continue
        name, link = row[0]
        date_str = row[-1][0]
        if not name or "Name and information link" in name:
            continue
        no_cves = APPLE_NO_CVE_NOTE in name
        name = name.replace(APPLE_NO_CVE_NOTE, "").strip()
        published = normalize_date(date_str)
        if not published:
            continue
        if link and not link.startswith("http"):
            link = f"https://support.apple.com{link}"
        path_match = re.search(r"/(\d+)$", link or "")
        alert_id = f"apple:{path_match.group(1)}" if path_match else f"apple:{stable_id(name, published)}"

        cve_ids: list[str] = []
        exploited = False
        description = None
        prev = previous.get(alert_id)
        if prev and prev.get("cve_ids") is not None and prev.get("source") == "apple" and not prev.get("_carried"):
            cve_ids = prev.get("cve_ids", [])
            exploited = bool(prev.get("actively_exploited"))
            description = prev.get("description")
        elif link and published >= cutoff and not no_cves and detail_fetches < APPLE_DETAIL_LIMIT and (time.monotonic() - started) > APPLE_TIME_BUDGET:
            skipped_for_time += 1
        elif link and published >= cutoff and not no_cves and detail_fetches < APPLE_DETAIL_LIMIT:
            detail_fetches += 1
            try:
                html = fetch(link, retries=1, timeout=30).decode("utf-8", errors="replace")
                text = strip_html(html)
                cve_ids = sorted(set(CVE_RE.findall(text)))
                exploited = bool(re.search(r"may have been (actively )?exploited", text, re.I))
                parts = [f"{len(cve_ids)} CVE{'s' if len(cve_ids) != 1 else ''} addressed."]
                if exploited:
                    parts.append("Apple is aware of a report that at least one issue may have been exploited in the wild.")
                description = " ".join(parts)
                time.sleep(0.5)
            except Exception as exc:  # detail pages are best-effort
                log(f"  apple detail failed for {link}: {exc}")
        elif no_cves:
            description = "No published CVE entries."

        alerts.append(
            make_alert(
                "apple",
                alert_id,
                name,
                published,
                cve_ids=cve_ids,
                description=description,
                vendor="Apple",
                product=re.split(r"\s+\d", name, maxsplit=1)[0].strip() or None,
                url=link or None,
                actively_exploited=exploited,
                exploit_source="vendor" if exploited else None,
            )
        )
    note = f"{detail_fetches} detail pages fetched"
    if skipped_for_time:
        note += f"; {skipped_for_time} skipped for time, retried next run"
    return FetchResult("apple", alerts, status="partial" if skipped_for_time else "ok", note=note)


def fetch_fortinet() -> FetchResult:
    alerts = []
    for item in rss_items(fetch(FORTINET_RSS_URL)):
        desc_html = item["description"]
        desc = strip_html(desc_html)
        published = normalize_date(item["date"])
        if not published:
            continue
        score_match = re.search(r"CVSSv3 Score:\s*([\d.]+)", desc)
        cvss = float(score_match.group(1)) if score_match else None
        cves = sorted(set(CVE_RE.findall(desc)))
        exploited = bool(re.search(r"exploited in the wild|actively exploited|has been reported to be exploited", desc, re.I))
        products = sorted(set(re.findall(r"\bForti[A-Z][A-Za-z]+(?:\s?(?:EMS|Cloud|Manager))?", desc)))
        ir_match = re.search(r"(FG-IR-\d{2}-\d+)", item["link"])
        ir_id = ir_match.group(1) if ir_match else stable_id(item["link"])
        alerts.append(
            make_alert(
                "fortinet",
                f"fortinet:{ir_id}",
                f"{ir_id}: {item['title']}" if ir_match else item["title"],
                published,
                cve_id=cves[0] if len(cves) == 1 else None,
                cve_ids=cves,
                description=re.sub(r"^CVSSv3 Score:\s*[\d.]+\s*", "", desc)[:1000] or None,
                severity=cvss_to_severity(cvss),
                cvss_score=cvss,
                vendor="Fortinet",
                product=", ".join(products[:4]) or None,
                url=item["link"],
                actively_exploited=exploited,
                exploit_source="vendor" if exploited else None,
            )
        )
    return FetchResult("fortinet", alerts)


def fetch_okta() -> FetchResult:
    alerts = []
    cutoff = days_ago_iso(DEFAULT_DAYS)
    for item in rss_items(fetch(OKTA_RSS_URL)):
        published = normalize_date(item["date"])
        if not published or published < cutoff:
            continue
        desc = strip_html(item["description"])
        cves = sorted(set(CVE_RE.findall(desc + " " + item["title"])))
        advisory = bool(re.search(r"advisory|vulnerab|CVE-|security (update|notice|bulletin)|incident", item["title"] + " " + desc, re.I))
        alerts.append(
            make_alert(
                "okta",
                f"okta:{stable_id(item['link'])}",
                item["title"],
                published,
                cve_id=cves[0] if len(cves) == 1 else None,
                cve_ids=cves,
                description=(("[Advisory] " if advisory else "[Blog] ") + desc)[:1000] or None,
                vendor="Okta",
                url=item["link"],
            )
        )
    return FetchResult("okta", alerts)


def fetch_aws() -> FetchResult:
    alerts = []
    sev_map = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
    for item in rss_items(fetch(AWS_RSS_URL)):
        published = normalize_date(item["date"])
        if not published:
            continue
        desc = strip_html(item["description"])
        title = item["title"]
        cves = sorted(set(CVE_RE.findall(title + " " + desc)))
        sev_match = re.search(r"Content Type:\s*([A-Za-z]+)", desc)
        severity = sev_map.get(sev_match.group(1).lower(), "UNKNOWN") if sev_match else "UNKNOWN"
        product_match = re.search(r"\b(?:in|for|affecting)\s+((?:AWS|Amazon)\s[A-Za-z0-9 .-]+?)(?:\s*\(|\s*-|$)", title)
        bulletin = re.search(r"(\d{4}-\d{3}-aws)", item["link"], re.I)
        alert_id = f"aws:{bulletin.group(1).upper()}" if bulletin else f"aws:{stable_id(item['link'])}"
        alerts.append(
            make_alert(
                "aws",
                alert_id,
                title,
                published,
                cve_id=cves[0] if len(cves) == 1 else None,
                cve_ids=cves,
                description=re.sub(r"^.*?Description:\s*", "", desc, count=1)[:1000] or None,
                severity=severity,
                vendor="AWS",
                product=product_match.group(1).strip() if product_match else None,
                url=item["link"],
            )
        )
    return FetchResult("aws", alerts)


def fetch_chrome() -> FetchResult:
    alerts = []
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for item in rss_items(fetch(CHROME_ATOM_URL)):
        title = item["title"]
        if not re.search(r"^(Stable Channel Update for Desktop|Extended Stable (Channel )?Update for Desktop)", title.strip(), re.I):
            continue
        published = normalize_date(item["date"])
        if not published:
            continue
        text = strip_html(item["description"])
        cves = sorted(set(CVE_RE.findall(text)))
        if not cves and "security" not in text.lower():
            continue
        version_match = re.search(r"updated to (\d+\.\d+\.\d+\.\d+)", text)
        version = version_match.group(1) if version_match else ""
        severities = [s.lower() for s in re.findall(r"\b(Critical|High|Medium|Low)\b\s+CVE-", text)]
        top = min(severities, key=lambda s: sev_rank[s]) if severities else None
        exploited = bool(re.search(r"exploit for CVE-[\d-]+ exists in the wild|exploited in the wild", text, re.I))
        summary = f"Chrome {version} ".strip() + f"- {len(cves)} security fix{'es' if len(cves) != 1 else ''}."
        if exploited:
            summary += " Google is aware that an exploit exists in the wild."
        is_extended = title.lower().startswith("extended")
        alerts.append(
            make_alert(
                "chrome",
                f"chrome:{stable_id(item['link'])}",
                f"{'Chrome Extended Stable' if is_extended else 'Chrome Stable'} {version}".strip(),
                published,
                cve_ids=cves,
                description=summary,
                severity=top.upper() if top else "UNKNOWN",
                vendor="Google",
                product="Chrome",
                url=item["link"],
                actively_exploited=exploited,
                exploit_source="vendor" if exploited else None,
            )
        )
    return FetchResult("chrome", alerts)


def fetch_zoom() -> FetchResult:
    parser = TableParser()
    parser.feed(fetch(ZOOM_BULLETIN_URL).decode("utf-8", errors="replace"))
    alerts = []
    for row in parser.rows:
        cells = [c[0] for c in row]
        if not cells or not re.match(r"ZSB-\d{2}-?\d{3}", cells[0]):
            continue
        zsb = cells[0]
        title = cells[1] if len(cells) > 1 else zsb
        severity_text = cells[2].upper() if len(cells) > 2 else "UNKNOWN"
        severity = severity_text if severity_text in SEVERITY_RANK else "UNKNOWN"
        cves = sorted(set(CVE_RE.findall(" ".join(cells))))
        dates = [normalize_date(c) for c in cells if re.match(r"\d{2}/\d{2}/\d{4}", c)]
        published = dates[0] if dates else ""
        if not published:
            continue
        link = row[0][1] or f"/trust/security-bulletin/{zsb}"
        if link.startswith("/"):
            link = f"https://www.zoom.com{link}"
        product = title.split(" - ")[0].strip() if " - " in title else None
        alerts.append(
            make_alert(
                "zoom",
                f"zoom:{zsb}",
                f"{zsb}: {title}",
                published,
                cve_id=cves[0] if len(cves) == 1 else None,
                cve_ids=cves,
                severity=severity,
                vendor="Zoom",
                product=product,
                url=link,
            )
        )
    return FetchResult("zoom", alerts)


def fetch_epss() -> dict[str, tuple[float, float]]:
    raw = fetch(EPSS_URL, timeout=120)
    text = gzip.decompress(raw).decode("utf-8", errors="replace")
    scores: dict[str, tuple[float, float]] = {}
    reader = csv.reader(line for line in io.StringIO(text) if not line.startswith("#"))
    header = next(reader, None)
    if not header or header[0] != "cve":
        raise RuntimeError("unexpected EPSS CSV header")
    for row in reader:
        if len(row) >= 3:
            try:
                scores[row[0]] = (float(row[1]), float(row[2]))
            except ValueError:
                continue
    return scores


# --------------------------------------------------------------------------
# Watchlist
# --------------------------------------------------------------------------

@dataclass
class WatchEntry:
    name: str
    terms: list[re.Pattern[str]]          # searched in vendor, product, title, description
    strict_terms: list[re.Pattern[str]]   # searched in vendor, product, title only
    cpe_vendors: set[str]
    msrc_families: set[str] = field(default_factory=set)
    exclude_products: list[str] = field(default_factory=list)
    cpe_products: list[str] = field(default_factory=list)   # if set, a CPE vendor hit also needs one of these in product


def compile_terms(terms: list[str]) -> list[re.Pattern[str]]:
    patterns = []
    for term in terms:
        term = term.strip()
        if term:
            patterns.append(re.compile(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", re.I))
    return patterns


def load_watchlist() -> tuple[list[WatchEntry], dict[str, Any]]:
    if not WATCHLIST_PATH.exists():
        return [], {}
    data = json.loads(WATCHLIST_PATH.read_text(encoding="utf-8"))
    entries = []
    for raw in data.get("entries", []):
        entries.append(
            WatchEntry(
                name=raw["name"],
                terms=compile_terms(raw.get("terms", [])),
                strict_terms=compile_terms(raw.get("strict_terms", [])),
                cpe_vendors={v.lower() for v in raw.get("cpe_vendors", [])},
                msrc_families=set(raw.get("msrc_families", [])),
                exclude_products=[v.lower() for v in raw.get("exclude_products", [])],
                cpe_products=[v.lower() for v in raw.get("cpe_products", [])],
            )
        )
    return entries, data


def apply_watchlist(alerts: list[dict[str, Any]], watchlist: list[WatchEntry]) -> None:
    for alert in alerts:
        matched: list[str] = []
        source = alert["source"]
        if source == "nvd":
            # NVD titles are just CVE ids and the CPE product list includes
            # platforms ("windows", "linux kernel"), so strict terms would
            # misfire. NVD relevance comes from the primary CPE vendor and
            # distinctive description terms only.
            haystack_short = ""
        else:
            haystack_short = " ".join(str(alert.get(k) or "") for k in ("vendor", "product", "title"))
        haystack = haystack_short + " " + str(alert.get("title") or "") + " " + str(alert.get("description") or "")
        # Only the primary (first) CPE vendor counts; secondary entries are
        # usually the platform (e.g. "windows" on a Chrome CVE).
        primary_vendor = str(alert.get("vendor") or "").split(",")[0].strip().lower()
        product_text = str(alert.get("product") or "").lower()
        for entry in watchlist:
            hit = False
            if source == "msrc":
                if entry.name == "Microsoft":
                    families = {f.strip() for f in str(alert.get("product") or "").split(",")}
                    hit = bool(families & entry.msrc_families) if entry.msrc_families else True
                else:
                    hit = any(p.search(haystack_short) for p in entry.terms + entry.strict_terms)
            else:
                cpe_hit = primary_vendor in entry.cpe_vendors and (
                    not entry.cpe_products or any(x in product_text for x in entry.cpe_products)
                )
                hit = (
                    cpe_hit
                    or any(p.search(haystack_short) for p in entry.strict_terms)
                    or any(p.search(haystack) for p in entry.terms)
                )
                if hit and entry.exclude_products and any(x in product_text for x in entry.exclude_products):
                    hit = False
            if hit:
                matched.append(entry.name)

        if source in VENDOR_SOURCES and not matched:
            matched.append({"apple": "Apple", "fortinet": "Fortinet", "okta": "Okta", "zoom": "Zoom", "aws": "AWS", "chrome": "Google Chrome"}[source])
        alert["matched"] = matched
        alert["relevant"] = bool(matched)


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def load_previous() -> dict[str, dict[str, Any]]:
    """Previous build's alerts keyed by id. Live site first, local file second."""
    rows: list[dict[str, Any]] = []
    loaded = False
    if PREVIOUS_DATA_URL:
        for suffix in ("", "-tail"):
            # Cache-buster: GitHub Pages' CDN may otherwise serve the previous deploy for up to 10 minutes.
            url = PREVIOUS_DATA_URL.replace("alerts.json", f"alerts{suffix}.json") + f"?build={int(time.time())}"
            try:
                rows.extend(json.loads(fetch(url, retries=2, timeout=120)))
                loaded = True
                log(f"Loaded previous alerts from {url}")
            except Exception as exc:
                if suffix == "":
                    log(f"Previous data not available from URL: {exc}")
    if not loaded:
        for name in ("alerts.json", "alerts-tail.json"):
            local = DATA_DIR / name
            if local.exists():
                try:
                    rows.extend(json.loads(local.read_bytes()))
                    log(f"Loaded previous alerts from {local}")
                except json.JSONDecodeError:
                    pass
    return {row["id"]: row for row in rows if isinstance(row, dict) and row.get("id")}


def run_fetchers(previous: dict[str, dict[str, Any]], run_started: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fetchers: list[tuple[str, Callable[[], FetchResult]]] = [
        ("kev", fetch_kev),
        ("nvd", fetch_nvd),
        ("msrc", fetch_msrc),
        ("apple", lambda: fetch_apple(previous)),
        ("fortinet", fetch_fortinet),
        ("okta", fetch_okta),
        ("zoom", fetch_zoom),
        ("aws", fetch_aws),
        ("chrome", fetch_chrome),
    ]
    cutoff = days_ago_iso(DEFAULT_DAYS)
    alerts: list[dict[str, Any]] = []
    status_rows: list[dict[str, Any]] = []

    for source, fetcher in fetchers:
        log(f"Fetching {source}...")
        started = time.monotonic()
        try:
            result = fetcher()
            rows = result.alerts
            carried = 0
            if source in ACCUMULATING_SOURCES:
                fresh_ids = {a["id"] for a in rows}
                for prev in previous.values():
                    if prev.get("source") == source and prev["id"] not in fresh_ids and prev.get("published_date", "") >= cutoff:
                        keep = dict(prev)
                        keep["_carried"] = True
                        rows.append(keep)
                        carried += 1
            alerts.extend(rows)
            note = result.note
            if carried:
                note = f"{note}; {carried} carried from previous build".strip("; ")
            status_rows.append(
                {
                    "source": source,
                    "last_fetched": run_started,
                    "status": result.status,
                    "error_message": result.error,
                    "note": note,
                    "count": len(rows),
                    "seconds": round(time.monotonic() - started, 1),
                }
            )
            log(f"  {source}: {len(rows)} rows in {time.monotonic() - started:.1f}s")
        except Exception as exc:
            fallback = [dict(prev, _carried=True) for prev in previous.values() if prev.get("source") == source]
            alerts.extend(fallback)
            last_ok = next((p.get("last_fetched") for p in fallback if p.get("last_fetched")), None)
            status_rows.append(
                {
                    "source": source,
                    "last_fetched": last_ok or run_started,
                    "status": "stale" if fallback else "error",
                    "error_message": f"{type(exc).__name__}: {str(exc)[:240]}",
                    "note": f"reusing {len(fallback)} rows from previous build" if fallback else "",
                    "count": len(fallback),
                    "seconds": round(time.monotonic() - started, 1),
                }
            )
            log(f"  {source} FAILED: {exc} (fallback rows: {len(fallback)})")
    return alerts, status_rows


def enrich(alerts: list[dict[str, Any]], previous: dict[str, dict[str, Any]], run_started: str,
           kev_lookup: dict[str, dict[str, Any]], epss: dict[str, tuple[float, float]]) -> None:
    # A previous build without first_seen tracking cannot tell us what is new.
    tracks_first_seen = any(p.get("first_seen") for p in previous.values())
    # If one build stamped a large share of rows with the same first_seen, that
    # build had stale previous data; don't trust those stamps.
    stamp_counts: dict[str, int] = {}
    for p in previous.values():
        if p.get("first_seen"):
            stamp_counts[p["first_seen"]] = stamp_counts.get(p["first_seen"], 0) + 1
    suspect_stamps = {stamp for stamp, n in stamp_counts.items() if n > 0.3 * max(len(previous), 1)}
    if suspect_stamps:
        log(f"  WARNING: ignoring first_seen stamps from a stale previous build: {sorted(suspect_stamps)}")
    # Per-CVE best severity/CVSS and vendor/product from non-KEV sources.
    cve_metadata: dict[str, dict[str, str]] = {}
    cve_severity: dict[str, tuple[str, float | None]] = {}

    def offer_severity(cve: str, sev: str, score: float | None) -> None:
        existing = cve_severity.get(cve)
        if existing is None or (sev != "UNKNOWN" and existing[0] == "UNKNOWN"):
            cve_severity[cve] = (sev, score)
        elif score is not None and (existing[1] is None or score > existing[1]):
            cve_severity[cve] = (sev, score)

    for cve, info in kev_lookup.items():
        if info.get("severity", "UNKNOWN") != "UNKNOWN":
            offer_severity(cve, info["severity"], info.get("cvss_score"))
        meta = cve_metadata.setdefault(cve, {})
        for key in ("vendor", "product"):
            if info.get(key) and not meta.get(key):
                meta[key] = info[key]

    for alert in alerts:
        cve = alert.get("cve_id")
        if not cve:
            continue
        meta = cve_metadata.setdefault(cve, {})
        for key in ("vendor", "product"):
            value = alert.get(key)
            if value and not meta.get(key):
                meta[key] = value
        if alert["source"] != "kev":
            offer_severity(cve, alert.get("severity", "UNKNOWN"), alert.get("cvss_score"))

    kev_rows = {a["cve_id"]: a for a in alerts if a["source"] == "kev" and a.get("cve_id")}
    # CVEs that a non-NVD row already describes; the NVD copy is "shadowed"
    # and hidden by default in the dashboard.
    covered_elsewhere: set[str] = set()
    for a in alerts:
        if a["source"] != "nvd":
            covered_elsewhere.update(a.get("cve_ids") or ([a["cve_id"]] if a.get("cve_id") else []))

    for alert in alerts:
        alert.pop("_carried", None)
        cve = alert.get("cve_id")
        cve_ids = alert.get("cve_ids") or ([cve] if cve else [])
        alert["cve_ids"] = cve_ids

        # Only the sparse sources borrow vendor/product; vendor feeds keep their own.
        if cve and cve in cve_metadata and alert["source"] in ("kev", "nvd"):
            for key, value in cve_metadata[cve].items():
                if not alert.get(key):
                    alert[key] = value

        # Inherit severity for KEV rows and anything else still UNKNOWN,
        # taking the worst severity across every CVE on the row.
        if alert.get("severity", "UNKNOWN") == "UNKNOWN":
            best: tuple[str, float | None] | None = None
            for c in cve_ids:
                cand = cve_severity.get(c)
                if cand and cand[0] != "UNKNOWN" and (best is None or SEVERITY_RANK[cand[0]] < SEVERITY_RANK[best[0]]):
                    best = cand
            if best:
                alert["severity"] = best[0]
                if best[1] is not None and alert.get("cvss_score") is None:
                    alert["cvss_score"] = best[1]

        alert["shadowed"] = 1 if (alert["source"] == "nvd" and cve and cve in covered_elsewhere) else 0

        # KEV cross-reference: any row whose CVEs intersect KEV is exploited.
        kev_hits = [c for c in cve_ids if c in kev_rows]
        if kev_hits and alert["source"] != "kev":
            alert["actively_exploited"] = 1
            alert["exploit_source"] = alert.get("exploit_source") or "kev"
            first = kev_rows[kev_hits[0]]
            alert["due_date"] = alert.get("due_date") or first.get("due_date")
            if first.get("ransomware"):
                alert["ransomware"] = 1

        # EPSS: highest score across the row's CVEs.
        best: tuple[float, float] | None = None
        for c in cve_ids:
            score = epss.get(c)
            if score and (best is None or score[0] > best[0]):
                best = score
        if best:
            alert["epss"] = round(best[0], 4)
            alert["epss_percentile"] = round(best[1], 4)

        # first_seen: preserve from previous build, else stamp now.
        prev = previous.get(alert["id"])
        if prev and prev.get("first_seen") and prev["first_seen"] not in suspect_stamps:
            alert["first_seen"] = prev["first_seen"]
        elif prev and prev.get("first_seen"):
            alert["first_seen"] = alert.get("published_date") or run_started
        elif prev:
            # Row existed in a build that predates first_seen tracking.
            alert["first_seen"] = prev.get("published_date") or alert.get("published_date") or run_started
        elif previous and tracks_first_seen:
            alert["first_seen"] = run_started
        else:
            alert["first_seen"] = alert.get("published_date") or run_started


EMPTY_VALUES = (None, "", 0, False, [])


def compact(alert: dict[str, Any], tail: bool = False) -> dict[str, Any]:
    """Drop empty fields; the frontend restores defaults. Tail rows also lose
    the long description."""
    out = {k: v for k, v in alert.items() if v not in EMPTY_VALUES or k in ("title", "published_date", "id", "source")}
    if tail and out.get("description"):
        out["description"] = out["description"][:200]
    return out


def build() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    run_started = utc_now()
    watchlist, watchlist_raw = load_watchlist()
    log(f"Watchlist: {len(watchlist)} entries")
    previous = load_previous()
    log(f"Previous alerts: {len(previous)}")

    alerts, status_rows = run_fetchers(previous, run_started)

    kev_lookup: dict[str, dict[str, Any]] = {}
    try:
        log("Fetching NVD records for KEV CVEs...")
        kev_lookup = fetch_nvd_kev_lookup()
        log(f"  {len(kev_lookup)} KEV CVEs enriched from NVD")
    except Exception as exc:
        log(f"  NVD KEV lookup failed: {exc}")
        status_rows.append({"source": "nvd-kev", "last_fetched": run_started, "status": "error",
                            "error_message": str(exc)[:240], "note": "", "count": 0, "seconds": 0})

    epss: dict[str, tuple[float, float]] = {}
    try:
        log("Fetching EPSS...")
        epss = fetch_epss()
        status_rows.append({"source": "epss", "last_fetched": run_started, "status": "ok",
                            "error_message": "", "note": "", "count": len(epss), "seconds": 0})
        log(f"  {len(epss)} EPSS scores")
    except Exception as exc:
        log(f"  EPSS failed: {exc}")
        # Carry previous EPSS values forward through the previous rows.
        for prev in previous.values():
            if prev.get("epss") is not None:
                for c in prev.get("cve_ids") or []:
                    epss.setdefault(c, (prev["epss"], prev.get("epss_percentile") or 0.0))
        status_rows.append({"source": "epss", "last_fetched": run_started, "status": "stale" if epss else "error",
                            "error_message": str(exc)[:240], "note": f"{len(epss)} scores carried", "count": len(epss), "seconds": 0})

    enrich(alerts, previous, run_started, kev_lookup, epss)
    newly_seen = [a for a in alerts if a.get("first_seen") == run_started]
    if previous and len(newly_seen) > 0.3 * len(alerts):
        log(f"  WARNING: {len(newly_seen)} of {len(alerts)} rows look new; previous data was probably stale. Falling back to published dates.")
        for a in newly_seen:
            a["first_seen"] = a.get("published_date") or run_started
    apply_watchlist(alerts, watchlist)

    alerts = [alert for alert in alerts if alert.get("published_date")]
    alerts.sort(
        key=lambda item: (
            item.get("published_date", ""),
            -SEVERITY_RANK.get(item.get("severity", "UNKNOWN"), 5),
            item.get("source", ""),
        ),
        reverse=True,
    )

    cutoff = days_ago_iso(DEFAULT_DAYS)
    recent = [a for a in alerts if a["published_date"] >= cutoff]
    relevant = [a for a in recent if a["relevant"]]
    week = days_ago_iso(7)
    epss_threshold = float(watchlist_raw.get("epss_threshold", 0.5))

    summary = {
        "generated_at": run_started,
        "total_alerts": len(alerts),
        "recent_alerts": len(recent),
        "relevant_alerts": len(relevant),
        "default_days": DEFAULT_DAYS,
        "default_view_days": DEFAULT_VIEW_DAYS,
        "epss_threshold": epss_threshold,
        "sources": sorted({a["source"] for a in alerts}),
        "watchlist": [w.name for w in watchlist],
        "counts": {sev: sum(1 for a in recent if a.get("severity") == sev) for sev in SEVERITY_RANK},
        "relevant_counts": {sev: sum(1 for a in relevant if a.get("severity") == sev) for sev in SEVERITY_RANK},
        "week": {
            "kev_added": sum(1 for a in alerts if a["source"] == "kev" and a["published_date"] >= week),
            "kev_added_relevant": sum(1 for a in alerts if a["source"] == "kev" and a["published_date"] >= week and a["relevant"]),
            "vendor_exploited": sum(1 for a in recent if a.get("exploit_source") == "vendor" and a["published_date"] >= week),
            "new_since_last_build": sum(1 for a in alerts if a.get("first_seen") == run_started) if previous else 0,
        },
    }

    # Main payload: everything except the NVD long tail (rows that are neither
    # on the watchlist nor exploited). The tail goes to a second file the
    # dashboard loads only in "Everything" scope.
    def is_tail(alert: dict[str, Any]) -> bool:
        return alert["source"] == "nvd" and not alert["relevant"] and not alert["actively_exploited"]

    main_rows = [compact(a) for a in alerts if not is_tail(a)]
    tail_rows = [compact(a, tail=True) for a in alerts if is_tail(a)]
    summary["main_alerts"] = len(main_rows)
    summary["tail_alerts"] = len(tail_rows)

    (DATA_DIR / "alerts.json").write_text(json.dumps(main_rows, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    (DATA_DIR / "alerts-tail.json").write_text(json.dumps(tail_rows, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    (DATA_DIR / "status.json").write_text(json.dumps(status_rows, indent=2), encoding="utf-8")
    (DATA_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"Wrote {len(alerts)} alerts ({len(relevant)} relevant in window) to {DATA_DIR}")
    failed = [r["source"] for r in status_rows if r["status"] == "error"]
    if failed:
        log(f"Sources with no data: {', '.join(failed)}")


if __name__ == "__main__":
    build()

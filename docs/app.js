const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const sourceLabels = {
    apple: "Apple Security Updates",
    kev: "CISA KEV",
    msrc: "Microsoft MSRC",
    nvd: "NVD",
    fortinet: "Fortinet PSIRT",
    okta: "Okta Security",
    zoom: "Zoom Security Bulletins",
    aws: "AWS Security Bulletins",
    chrome: "Chrome Releases",
};
const sourceShort = {
    apple: "Apple", kev: "KEV", msrc: "MSRC", nvd: "NVD", fortinet: "Fortinet",
    okta: "Okta", zoom: "Zoom", aws: "AWS", chrome: "Chrome",
};
const RELEASE_SOURCES = new Set(["apple", "chrome", "fortinet", "zoom", "aws", "okta"]);

const STALENESS_HOURS = 8;
const NEW_ALERT_HOURS = 48;
const SEARCH_INPUT_DELAY_MS = 150;
const MAX_RENDERED_ALERTS = 500;
const BRIEF_MAX_ITEMS = 12;
const STORAGE_KEYS = { scope: "tt.scope", dismissed: "tt.dismissed", hideDismissed: "tt.hideDismissed" };

let allAlerts = [];
let allStatus = [];
let summaryData = {};
let generatedAt = "";
let defaultWindowDays = 30;
let epssThreshold = 0.5;
let currentSort = { key: "published_date", desc: true };
let quickFilterActive = null; // "critical" | "exploited" | "new" | null
let searchInputTimer = null;
let scope = "stack"; // "stack" | "all"
let activeChip = null; // watchlist entry name
let dismissed = new Map(); // id -> ISO timestamp
let showDismissedInBrief = false;
let tailLoaded = false;   // the NVD long tail (alerts-tail.json) is fetched on demand
let tailLoading = null;

// --- Storage (per-browser conveniences; everything degrades gracefully) ---

function storageGet(key, fallback) {
    try {
        const raw = window.localStorage.getItem(key);
        return raw === null ? fallback : JSON.parse(raw);
    } catch (_error) {
        return fallback;
    }
}

function storageSet(key, value) {
    try {
        window.localStorage.setItem(key, JSON.stringify(value));
    } catch (_error) {
        // ignore: private mode or storage disabled
    }
}

function loadState() {
    scope = storageGet(STORAGE_KEYS.scope, "stack") === "all" ? "all" : "stack";
    const entries = storageGet(STORAGE_KEYS.dismissed, []);
    dismissed = new Map(Array.isArray(entries) ? entries.filter((e) => Array.isArray(e) && e.length === 2) : []);
    const hide = storageGet(STORAGE_KEYS.hideDismissed, true);
    document.getElementById("hide-dismissed-filter").checked = Boolean(hide);
}

function persistDismissed() {
    storageSet(STORAGE_KEYS.dismissed, [...dismissed.entries()]);
}

function pruneDismissed() {
    // Drop dismissals for alerts that no longer exist in the data set.
    const ids = new Set(allAlerts.map((a) => a.id));
    let changed = false;
    for (const id of [...dismissed.keys()]) {
        if (!ids.has(id)) {
            dismissed.delete(id);
            changed = true;
        }
    }
    if (changed) persistDismissed();
}

// --- Helpers ---

function buildSearchText(alert) {
    return [
        alert.cve_id,
        ...(alert.cve_ids || []),
        alert.title,
        alert.vendor,
        alert.product,
        alert.description,
        alert.source,
        sourceLabels[alert.source],
        ...(alert.matched || []),
    ].filter(Boolean).join(" ").toLowerCase();
}

function parseDateValue(value) {
    if (!value) return null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        const [year, month, day] = value.split("-").map(Number);
        return new Date(Date.UTC(year, month - 1, day));
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return null;
    return parsed;
}

function safeUrl(value) {
    if (!value) return "";
    try {
        const parsed = new URL(value, window.location.origin);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return parsed.href;
        }
    } catch (_error) {
        return "";
    }
    return "";
}

async function loadJson(path) {
    const response = await fetch(path);
    if (!response.ok) {
        throw new Error(`Failed to load ${path}: ${response.status}`);
    }
    return response.json();
}

function formatTimestamp(value) {
    if (!value) return "";
    const date = parseDateValue(value);
    if (!date) return value;
    return date.toLocaleString();
}

function relativeTime(value) {
    const date = parseDateValue(value);
    if (!date) return "";
    const diffMs = Date.now() - date.getTime();
    const diffH = Math.floor(diffMs / 3600000);
    if (diffH < 1) return "just now";
    if (diffH < 24) return `${diffH}h`;
    const diffD = Math.floor(diffH / 24);
    return `${diffD}d ago`;
}

function isoCutoff(days) {
    const now = new Date();
    now.setUTCHours(0, 0, 0, 0);
    now.setUTCDate(now.getUTCDate() - days);
    return now.toISOString().slice(0, 10);
}

function isoFuture(days) {
    return isoCutoff(-days);
}

function todayIso() {
    return isoCutoff(0);
}

function isNewAlert(alert) {
    const stamp = alert.first_seen || alert.published_date;
    const date = parseDateValue(stamp);
    if (!date) return false;
    return date.getTime() >= Date.now() - NEW_ALERT_HOURS * 3600000;
}

function formatEpss(alert) {
    if (alert.epss === null || alert.epss === undefined) return "";
    return `${(alert.epss * 100).toFixed(alert.epss >= 0.1 ? 0 : 1)}%`;
}

function cveLabel(alert) {
    const ids = alert.cve_ids || [];
    if (alert.cve_id) return alert.cve_id;
    if (ids.length === 1) return ids[0];
    if (ids.length > 1) return `${ids.length} CVEs`;
    return "";
}

function inScope(alert) {
    if (scope === "all") return true;
    return Boolean(alert.relevant);
}

function matchesChip(alert) {
    if (!activeChip) return true;
    return (alert.matched || []).includes(activeChip);
}

// --- Brief ---

function computeBrief() {
    const week = isoCutoff(7);
    const twoWeeks = isoCutoff(14);
    const dueStart = isoCutoff(7);
    const dueEnd = isoFuture(14);
    const seen = new Set();
    const lists = { exploited: [], stack: [], due: [], releases: [] };

    const keysFor = (alert) => (alert.cve_ids.length ? alert.cve_ids : [alert.id]);
    const take = (alert, list) => {
        if (alert.shadowed) return;
        const keys = keysFor(alert);
        if (keys.some((k) => seen.has(k))) return;
        for (const k of keys) seen.add(k);
        lists[list].push(alert);
    };

    const candidates = allAlerts.filter((a) => (showDismissedInBrief || !dismissed.has(a.id)) && matchesChip(a));

    // 1. Exploited in the wild: vendor-confirmed first, then KEV additions.
    for (const a of candidates) {
        if (a.exploit_source === "vendor" && a.published_date >= twoWeeks && inScope(a)) take(a, "exploited");
    }
    for (const a of candidates) {
        if (a.source === "kev" && a.published_date >= week && (inScope(a) || scope === "all")) take(a, "exploited");
    }
    // 2. Stack critical / high EPSS. CVEs already summarized by a vendor
    //    release row (Chrome, Apple, Fortinet) and MSRC's Chromium
    //    republications are left to the releases list.
    const coveredByRelease = new Set();
    for (const a of allAlerts) {
        if (RELEASE_SOURCES.has(a.source)) for (const c of a.cve_ids) coveredByRelease.add(c);
    }
    for (const a of candidates) {
        if (!a.relevant || a.published_date < twoWeeks) continue;
        if (a.source === "msrc" && /^Chromium\b/i.test(a.title || "")) continue;
        if ((a.source === "nvd" || a.source === "msrc") && a.cve_ids.some((c) => coveredByRelease.has(c))) continue;
        if (a.severity === "CRITICAL" || (a.epss !== null && a.epss >= epssThreshold)) take(a, "stack");
    }
    // 3. KEV remediation due.
    for (const a of candidates) {
        if (a.source !== "kev" || !a.due_date) continue;
        if (a.due_date >= dueStart && a.due_date <= dueEnd && inScope(a)) {
            for (const k of keysFor(a)) seen.delete(k); // a due item is worth repeating even if listed above
            take(a, "due");
        }
    }
    // 4. Vendor patch releases.
    for (const a of candidates) {
        if (RELEASE_SOURCES.has(a.source) && a.published_date >= twoWeeks && inScope(a)) take(a, "releases");
    }

    const bySeverityThenDate = (x, y) => {
        const sx = severityOrder[x.severity] ?? 5;
        const sy = severityOrder[y.severity] ?? 5;
        if (sx !== sy) return sx - sy;
        return y.published_date.localeCompare(x.published_date);
    };
    lists.exploited.sort((x, y) => y.published_date.localeCompare(x.published_date));
    lists.stack.sort((x, y) => {
        const ex = x.epss ?? -1;
        const ey = y.epss ?? -1;
        if (x.severity !== y.severity) return bySeverityThenDate(x, y);
        if (ex !== ey) return ey - ex;
        return y.published_date.localeCompare(x.published_date);
    });
    lists.due.sort((x, y) => x.due_date.localeCompare(y.due_date));
    lists.releases.sort((x, y) => {
        if (Boolean(x.actively_exploited) !== Boolean(y.actively_exploited)) return x.actively_exploited ? -1 : 1;
        return y.published_date.localeCompare(x.published_date);
    });
    return lists;
}

function makePill(text, cls) {
    const pill = document.createElement("span");
    pill.className = `pill ${cls}`;
    pill.textContent = text;
    return pill;
}

function renderBriefList(listName, alerts) {
    const ul = document.getElementById(`brief-${listName}`);
    const count = document.getElementById(`brief-count-${listName}`);
    const template = document.getElementById("brief-item-template");
    ul.innerHTML = "";
    count.textContent = alerts.length ? String(alerts.length) : "";
    if (!alerts.length) {
        const li = document.createElement("li");
        li.className = "brief-empty";
        li.textContent = "Nothing right now.";
        ul.appendChild(li);
        return;
    }
    const today = todayIso();
    for (const alert of alerts.slice(0, BRIEF_MAX_ITEMS)) {
        const li = template.content.firstElementChild.cloneNode(true);
        if (dismissed.has(alert.id)) li.classList.add("dismissed");
        const pills = li.querySelector(".brief-pills");
        pills.appendChild(makePill(alert.severity || "UNKNOWN", String(alert.severity || "UNKNOWN").toLowerCase()));
        const src = document.createElement("span");
        src.className = "source-tag";
        src.textContent = sourceShort[alert.source] || alert.source;
        pills.appendChild(src);
        if (alert.ransomware) pills.appendChild(makePill("Ransomware", "ransomware"));
        if (isNewAlert(alert)) pills.appendChild(makePill("NEW", "new"));

        const link = li.querySelector(".brief-title");
        const href = safeUrl(alert.url);
        const titleText = alert.source === "kev" && alert.cve_id ? `${alert.cve_id} ${alert.title}` : alert.title;
        link.textContent = titleText;
        if (href) {
            link.href = href;
        } else {
            link.removeAttribute("href");
        }

        const meta = li.querySelector(".brief-meta");
        const bits = [];
        if (alert.vendor && !titleText.toLowerCase().includes(alert.vendor.toLowerCase())) bits.push(alert.vendor);
        if (alert.product && alert.source !== "kev" && !titleText.toLowerCase().includes(alert.product.toLowerCase())) bits.push(alert.product);
        if (alert.source !== "kev" && cveLabel(alert) && !titleText.includes(cveLabel(alert))) bits.push(cveLabel(alert));
        if (alert.epss !== null && alert.epss !== undefined) bits.push(`EPSS ${formatEpss(alert)}`);
        if (listName === "due" && alert.due_date) {
            bits.push(alert.due_date < today ? `OVERDUE ${alert.due_date}` : `due ${alert.due_date}`);
        } else {
            bits.push(`${alert.published_date} (${relativeTime(alert.published_date)})`);
        }
        if (alert.matched && alert.matched.length && scope === "all") bits.push(`stack: ${alert.matched.join(", ")}`);
        meta.textContent = bits.join(" · ");
        if (listName === "due" && alert.required_action) {
            const action = document.createElement("div");
            action.className = "brief-action";
            action.textContent = alert.required_action;
            li.appendChild(action);
        }

        const btn = li.querySelector(".dismiss");
        if (dismissed.has(alert.id)) {
            btn.textContent = "↺";
            btn.title = "Restore to brief";
        }
        btn.addEventListener("click", () => toggleDismiss(alert.id));
        ul.appendChild(li);
    }
    if (alerts.length > BRIEF_MAX_ITEMS) {
        const li = document.createElement("li");
        li.className = "brief-empty";
        li.textContent = `+${alerts.length - BRIEF_MAX_ITEMS} more in the table below.`;
        ul.appendChild(li);
    }
}

function renderBrief() {
    const lists = computeBrief();
    for (const name of Object.keys(lists)) renderBriefList(name, lists[name]);
    document.getElementById("dismissed-count").textContent = String(dismissed.size);
    const subtitle = document.getElementById("brief-subtitle");
    subtitle.textContent = scope === "stack"
        ? `Filtered to ${summaryData.watchlist ? summaryData.watchlist.length : 0} watchlist products. Switch to "Everything" for the full feed.`
        : "Showing every source. Switch to \"My stack\" to filter to the watchlist.";
}

function toggleDismiss(id) {
    if (dismissed.has(id)) {
        dismissed.delete(id);
    } else {
        dismissed.set(id, new Date().toISOString());
    }
    persistDismissed();
    renderBrief();
    applyAndRender();
}

// --- Scope and chips ---

function setScope(next) {
    scope = next === "all" ? "all" : "stack";
    storageSet(STORAGE_KEYS.scope, scope);
    document.getElementById("scope-stack").dataset.active = String(scope === "stack");
    document.getElementById("scope-all").dataset.active = String(scope === "all");
    renderBrief();
    applyAndRender();
    if (scope === "all") ensureTailLoaded();
}

function renderChips() {
    const container = document.getElementById("stack-chips");
    container.innerHTML = "";
    const counts = new Map();
    const cutoff = isoCutoff(defaultWindowDays);
    for (const alert of allAlerts) {
        if (alert.published_date < cutoff) continue;
        for (const name of alert.matched || []) counts.set(name, (counts.get(name) || 0) + 1);
    }
    const names = [...(summaryData.watchlist || [])].sort((a, b) => (counts.get(b) || 0) - (counts.get(a) || 0) || a.localeCompare(b));
    for (const name of names) {
        const chip = document.createElement("button");
        chip.className = "chip";
        chip.dataset.active = String(activeChip === name);
        const n = counts.get(name) || 0;
        chip.textContent = n ? `${name} ${n}` : name;
        if (!n) chip.classList.add("quiet");
        chip.title = `${n} alert${n === 1 ? "" : "s"} in the last ${defaultWindowDays} days`;
        chip.addEventListener("click", () => {
            activeChip = activeChip === name ? null : name;
            renderChips();
            renderBrief();
            applyAndRender();
        });
        container.appendChild(chip);
    }
}

// --- Filters / table ---

function renderSourceFilters(sources) {
    const container = document.getElementById("source-filters");
    container.innerHTML = "";
    const ordered = [...sources].sort((a, b) => (sourceLabels[a] || a).localeCompare(sourceLabels[b] || b));
    for (const source of ordered) {
        const label = document.createElement("label");
        label.className = "checkbox";
        const input = document.createElement("input");
        input.className = "source-filter";
        input.type = "checkbox";
        input.value = source;
        input.checked = true;
        label.appendChild(input);
        label.appendChild(document.createTextNode(` ${sourceLabels[source] || source}`));
        container.appendChild(label);
    }
    container.querySelectorAll(".source-filter").forEach((node) => {
        node.addEventListener("change", () => {
            clearQuickFilter();
            applyAndRender();
        });
    });
}

function getFilteredAlerts() {
    const days = Number(document.getElementById("days-filter").value);
    const cutoff = isoCutoff(days);
    const search = document.getElementById("search-filter").value.trim().toLowerCase();
    const exploitedOnly = document.getElementById("exploited-filter").checked;
    const hideDismissed = document.getElementById("hide-dismissed-filter").checked;
    const hideShadowed = document.getElementById("hide-shadowed-filter").checked;
    const newOnly = quickFilterActive === "new";
    const activeSeverities = new Set(
        [...document.querySelectorAll(".severity-filter:checked")].map((node) => node.value)
    );
    const activeSources = new Set(
        [...document.querySelectorAll(".source-filter:checked")].map((node) => node.value)
    );

    return allAlerts.filter((alert) => {
        const matchesSearch = !search || alert.search_text.includes(search);
        if (!matchesSearch) return false;
        const withinWindow = alert.published_date >= cutoff;
        // A search widens the window so an old CVE can be found; scope still applies.
        if (!withinWindow && !search) return false;
        if (!inScope(alert) || !matchesChip(alert)) return false;
        if (!activeSeverities.has(alert.severity || "UNKNOWN")) return false;
        if (!activeSources.has(alert.source)) return false;
        if (exploitedOnly && !alert.actively_exploited) return false;
        if (hideDismissed && dismissed.has(alert.id)) return false;
        if (hideShadowed && alert.shadowed) return false;
        if (newOnly && !isNewAlert(alert)) return false;
        return true;
    });
}

function sortAlerts(alerts) {
    const { key, desc } = currentSort;
    return [...alerts].sort((a, b) => {
        let left = a[key] ?? "";
        let right = b[key] ?? "";

        if (key === "severity") {
            left = severityOrder[a.severity || "UNKNOWN"] ?? 5;
            right = severityOrder[b.severity || "UNKNOWN"] ?? 5;
        } else if (key === "epss") {
            left = a.epss ?? -1;
            right = b.epss ?? -1;
        }

        if (left < right) return desc ? 1 : -1;
        if (left > right) return desc ? -1 : 1;
        // Stable tiebreak: newest first, then severity.
        if (a.published_date !== b.published_date) return a.published_date < b.published_date ? 1 : -1;
        return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
    });
}

function renderStaleness() {
    const banner = document.getElementById("staleness-banner");
    const ageSpan = document.getElementById("staleness-age");
    const genDate = parseDateValue(generatedAt);
    if (!genDate) {
        banner.classList.add("hidden");
        return;
    }
    const hoursOld = (Date.now() - genDate.getTime()) / 3600000;
    if (hoursOld >= STALENESS_HOURS) {
        const display = hoursOld >= 24
            ? `${Math.floor(hoursOld / 24)} day${Math.floor(hoursOld / 24) !== 1 ? "s" : ""}`
            : `${Math.floor(hoursOld)} hours`;
        ageSpan.textContent = display;
        banner.classList.remove("hidden");
    } else {
        banner.classList.add("hidden");
    }

    const warning = document.getElementById("feed-warning");
    const broken = allStatus.filter((s) => s.status === "error" || s.status === "stale");
    if (broken.length) {
        warning.textContent = `Feed problems: ${broken.map((s) => `${sourceLabels[s.source] || s.source} (${s.status})`).join(", ")}. See Feed Status below.`;
        warning.classList.remove("hidden");
    } else {
        warning.classList.add("hidden");
    }
}

function renderSummary(alerts) {
    document.getElementById("generated-at").textContent = formatTimestamp(generatedAt);
    document.getElementById("visible-count").textContent = alerts.length.toLocaleString();
    const newCount = (summaryData.week && summaryData.week.new_since_last_build) || 0;
    document.getElementById("new-count").textContent = newCount.toLocaleString();

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    let exploited = 0;
    for (const alert of alerts) {
        const sev = alert.severity || "UNKNOWN";
        counts[sev] = (counts[sev] || 0) + 1;
        if (alert.actively_exploited) exploited += 1;
    }
    document.getElementById("count-critical").textContent = counts.CRITICAL.toLocaleString();
    document.getElementById("count-high").textContent = counts.HIGH.toLocaleString();
    document.getElementById("count-medium").textContent = counts.MEDIUM.toLocaleString();
    document.getElementById("count-low").textContent = counts.LOW.toLocaleString();
    document.getElementById("count-unknown").textContent = counts.UNKNOWN.toLocaleString();
    document.getElementById("count-exploited").textContent = exploited.toLocaleString();
}

function renderTableMeta(totalAlerts, grouped) {
    const tableMeta = document.getElementById("table-meta");
    const parts = [];
    if (totalAlerts > MAX_RENDERED_ALERTS) {
        parts.push(`Showing the first ${MAX_RENDERED_ALERTS} of ${totalAlerts.toLocaleString()} matching alerts. Narrow the filters or search to reduce the result set.`);
    }
    if (grouped) parts.push("Grouped by vendor because a search is active.");
    const search = document.getElementById("search-filter").value.trim();
    if (search && !tailLoaded && scope === "stack") {
        parts.push("Searching watchlist rows only. Switch to \"Everything\" to search the full NVD feed.");
    }
    tableMeta.textContent = parts.join(" ");
}

function buildRow(alert, template) {
    const row = template.content.firstElementChild.cloneNode(true);
    row.dataset.severity = alert.severity || "UNKNOWN";
    row.dataset.source = alert.source;
    if (alert.actively_exploited) row.dataset.exploited = "true";
    if (dismissed.has(alert.id)) row.dataset.dismissed = "true";

    row.querySelector(".severity-cell").appendChild(makePill(alert.severity || "UNKNOWN", String(alert.severity || "UNKNOWN").toLowerCase()));
    if (alert.cvss_score !== null && alert.cvss_score !== undefined) {
        const score = document.createElement("small");
        score.textContent = `CVSS ${alert.cvss_score}`;
        row.querySelector(".severity-cell").appendChild(score);
    }

    const sourceTag = document.createElement("span");
    sourceTag.className = "source-tag";
    sourceTag.textContent = sourceShort[alert.source] || alert.source;
    sourceTag.title = sourceLabels[alert.source] || alert.source;
    row.querySelector(".source-cell").appendChild(sourceTag);

    const cveCell = row.querySelector(".cve-cell");
    const ids = alert.cve_ids && alert.cve_ids.length ? alert.cve_ids : (alert.cve_id ? [alert.cve_id] : []);
    if (ids.length) {
        const cveLink = document.createElement("a");
        cveLink.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(ids[0])}`;
        cveLink.target = "_blank";
        cveLink.rel = "noreferrer";
        cveLink.textContent = ids[0];
        cveCell.appendChild(cveLink);
        if (ids.length > 1) {
            const more = document.createElement("small");
            more.textContent = `+${ids.length - 1} more`;
            more.title = ids.slice(1, 40).join(", ");
            cveCell.appendChild(more);
        }
    }

    const titleCell = row.querySelector(".title-cell");
    const titleText = alert.title || "";
    const href = safeUrl(alert.url);
    if (href) {
        const link = document.createElement("a");
        link.href = href;
        link.target = "_blank";
        link.rel = "noreferrer";
        link.textContent = titleText;
        titleCell.appendChild(link);
    } else {
        titleCell.textContent = titleText;
    }
    if (isNewAlert(alert)) {
        const newBadge = document.createElement("span");
        newBadge.className = "new-badge";
        newBadge.textContent = "NEW";
        titleCell.appendChild(newBadge);
    }
    if (alert.matched && alert.matched.length && scope === "all") {
        const stackBadge = document.createElement("span");
        stackBadge.className = "stack-badge";
        stackBadge.textContent = alert.matched.join(", ");
        stackBadge.title = "Matches watchlist";
        titleCell.appendChild(stackBadge);
    }
    if (alert.description) {
        const description = document.createElement("small");
        description.textContent = alert.description;
        titleCell.appendChild(description);
    }
    if (alert.source === "kev" && alert.required_action) {
        const action = document.createElement("small");
        action.className = "required-action";
        action.textContent = `CISA: ${alert.required_action}`;
        titleCell.appendChild(action);
    }

    const vendorCell = row.querySelector(".vendor-cell");
    vendorCell.textContent = alert.vendor || "";
    if (alert.product) {
        const product = document.createElement("small");
        product.textContent = alert.product;
        vendorCell.appendChild(product);
    }

    const epssCell = row.querySelector(".epss-cell");
    if (alert.epss !== null && alert.epss !== undefined) {
        const epss = document.createElement("span");
        epss.className = `epss ${alert.epss >= epssThreshold ? "hot" : alert.epss >= 0.1 ? "warm" : ""}`.trim();
        epss.textContent = formatEpss(alert);
        epss.title = `EPSS ${alert.epss} (percentile ${Math.round((alert.epss_percentile || 0) * 100)})`;
        epssCell.appendChild(epss);
    }

    const publishedCell = row.querySelector(".published-cell");
    const dateText = alert.published_date || "";
    const rel = relativeTime(alert.published_date);
    publishedCell.textContent = rel ? `${dateText} (${rel})` : dateText;
    if (alert.due_date) {
        const due = document.createElement("small");
        due.className = alert.due_date < todayIso() ? "overdue" : "";
        due.textContent = `KEV due ${alert.due_date}`;
        publishedCell.appendChild(due);
    }

    const exploitedCell = row.querySelector(".exploited-cell");
    if (alert.actively_exploited) {
        const bits = [];
        if (alert.exploit_source === "vendor") bits.push("Vendor");
        if (alert.source === "kev" || alert.exploit_source === "kev" || alert.due_date) bits.push("KEV");
        exploitedCell.textContent = bits.length ? bits.join(" + ") : "YES";
        if (alert.ransomware) {
            const r = document.createElement("small");
            r.className = "ransomware-note";
            r.textContent = "Ransomware use";
            exploitedCell.appendChild(r);
        }
    } else if (alert.publicly_disclosed) {
        exploitedCell.textContent = "Disclosed";
    }

    const actionCell = row.querySelector(".action-cell");
    const btn = document.createElement("button");
    btn.className = "dismiss";
    btn.textContent = dismissed.has(alert.id) ? "↺" : "×";
    btn.title = dismissed.has(alert.id) ? "Restore" : "Dismiss";
    btn.addEventListener("click", () => toggleDismiss(alert.id));
    actionCell.appendChild(btn);
    return row;
}

function renderAlerts(alerts) {
    const tbody = document.getElementById("alerts-body");
    const template = document.getElementById("alert-row-template");
    tbody.innerHTML = "";
    const search = document.getElementById("search-filter").value.trim();
    const grouped = Boolean(search) && alerts.length > 1 && currentSort.key === "published_date";
    renderTableMeta(alerts.length, grouped);
    const fragment = document.createDocumentFragment();
    const visible = alerts.slice(0, MAX_RENDERED_ALERTS);

    if (grouped) {
        const groups = new Map();
        for (const alert of visible) {
            const key = alert.vendor || "Unknown vendor";
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(alert);
        }
        const ordered = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
        for (const [vendor, rows] of ordered) {
            const header = document.createElement("tr");
            header.className = "group-row";
            const cell = document.createElement("td");
            cell.colSpan = 9;
            cell.textContent = `${vendor} · ${rows.length}`;
            header.appendChild(cell);
            fragment.appendChild(header);
            for (const alert of rows) fragment.appendChild(buildRow(alert, template));
        }
    } else {
        for (const alert of visible) fragment.appendChild(buildRow(alert, template));
    }
    tbody.appendChild(fragment);
}

function renderStatus() {
    const tbody = document.getElementById("status-body");
    const template = document.getElementById("status-row-template");
    tbody.innerHTML = "";

    for (const item of allStatus) {
        const row = template.content.firstElementChild.cloneNode(true);
        row.dataset.status = item.status;
        row.querySelector(".status-source").textContent = sourceLabels[item.source] || item.source;
        row.querySelector(".status-fetched").textContent = formatTimestamp(item.last_fetched);
        row.querySelector(".status-state").textContent = item.status;
        row.querySelector(".status-count").textContent = Number(item.count ?? 0).toLocaleString();
        row.querySelector(".status-error").textContent = [item.error_message, item.note].filter(Boolean).join(" — ");
        tbody.appendChild(row);
    }
}

// --- Quick filters ---

function clearQuickFilter() {
    quickFilterActive = null;
    for (const id of ["qf-critical", "qf-exploited", "qf-new"]) {
        document.getElementById(id).dataset.active = "false";
    }
}

function resetAllFilters() {
    clearQuickFilter();
    activeChip = null;
    document.getElementById("days-filter").value = String(defaultWindowDays);
    document.getElementById("search-filter").value = "";
    document.getElementById("exploited-filter").checked = false;
    document.querySelectorAll(".severity-filter").forEach((node) => { node.checked = true; });
    document.querySelectorAll(".source-filter").forEach((node) => { node.checked = true; });
    renderChips();
    renderBrief();
    applyAndRender();
}

function activateQuickFilter(mode) {
    if (quickFilterActive === mode) {
        resetAllFilters();
        return;
    }
    document.getElementById("search-filter").value = "";
    document.querySelectorAll(".source-filter").forEach((node) => { node.checked = true; });
    document.querySelectorAll(".severity-filter").forEach((node) => { node.checked = mode !== "critical" || node.value === "CRITICAL"; });
    document.getElementById("exploited-filter").checked = mode === "exploited";
    clearQuickFilter();
    quickFilterActive = mode;
    document.getElementById(`qf-${mode}`).dataset.active = "true";
    applyAndRender();
}

function applyAndRender() {
    const filtered = sortAlerts(getFilteredAlerts());
    renderSummary(filtered);
    renderAlerts(filtered);
}

function scheduleSearchRender() {
    if (searchInputTimer) {
        window.clearTimeout(searchInputTimer);
    }
    searchInputTimer = window.setTimeout(() => {
        searchInputTimer = null;
        clearQuickFilter();
        applyAndRender();
    }, SEARCH_INPUT_DELAY_MS);
}

function bindEvents() {
    document.getElementById("days-filter").addEventListener("change", () => {
        clearQuickFilter();
        applyAndRender();
    });
    document.getElementById("search-filter").addEventListener("input", scheduleSearchRender);
    document.getElementById("exploited-filter").addEventListener("change", () => {
        clearQuickFilter();
        applyAndRender();
    });
    document.getElementById("hide-shadowed-filter").addEventListener("change", () => applyAndRender());
    document.getElementById("hide-dismissed-filter").addEventListener("change", (event) => {
        storageSet(STORAGE_KEYS.hideDismissed, event.target.checked);
        applyAndRender();
    });
    document.querySelectorAll(".severity-filter").forEach((node) => {
        node.addEventListener("change", () => {
            clearQuickFilter();
            applyAndRender();
        });
    });
    document.querySelectorAll("#alerts-table th[data-sort]").forEach((th) => {
        th.addEventListener("click", () => {
            const key = th.dataset.sort;
            const isSame = currentSort.key === key;
            currentSort = { key, desc: isSame ? !currentSort.desc : key === "published_date" || key === "epss" };
            document.querySelectorAll("#alerts-table th").forEach((node) => node.classList.remove("sorted"));
            th.classList.add("sorted");
            applyAndRender();
        });
    });
    document.getElementById("qf-critical").addEventListener("click", () => activateQuickFilter("critical"));
    document.getElementById("qf-exploited").addEventListener("click", () => activateQuickFilter("exploited"));
    document.getElementById("qf-new").addEventListener("click", () => activateQuickFilter("new"));
    document.getElementById("qf-reset").addEventListener("click", resetAllFilters);
    document.getElementById("scope-stack").addEventListener("click", () => setScope("stack"));
    document.getElementById("scope-all").addEventListener("click", () => setScope("all"));
    document.getElementById("show-dismissed").addEventListener("change", (event) => {
        showDismissedInBrief = event.target.checked;
        renderBrief();
    });
    document.getElementById("clear-dismissed").addEventListener("click", () => {
        if (!dismissed.size) return;
        dismissed.clear();
        persistDismissed();
        renderBrief();
        applyAndRender();
    });
}

function normalizeAlert(alert) {
    return {
        ...alert,
        severity: alert.severity || "UNKNOWN",
        relevant: Boolean(alert.relevant),
        matched: alert.matched || [],
        cve_ids: alert.cve_ids || (alert.cve_id ? [alert.cve_id] : []),
        epss: typeof alert.epss === "number" ? alert.epss : null,
        actively_exploited: alert.actively_exploited ? 1 : 0,
        search_text: buildSearchText(alert),
    };
}

async function ensureTailLoaded() {
    if (tailLoaded) return;
    if (!tailLoading) {
        const meta = document.getElementById("table-meta");
        meta.textContent = `Loading the full NVD feed (${Number(summaryData.tail_alerts || 0).toLocaleString()} more rows)...`;
        tailLoading = loadJson("./data/alerts-tail.json")
            .then((rows) => {
                allAlerts = allAlerts.concat(rows.map(normalizeAlert));
                tailLoaded = true;
                pruneDismissed();
                renderChips();
                renderBrief();
                applyAndRender();
            })
            .catch((error) => {
                meta.textContent = `Could not load the full NVD feed: ${error.message}`;
                tailLoading = null;
            });
    }
    await tailLoading;
}

async function init() {
    try {
        loadState();
        const [alerts, status, summary] = await Promise.all([
            loadJson("./data/alerts.json"),
            loadJson("./data/status.json"),
            loadJson("./data/summary.json"),
        ]);
        allAlerts = alerts.map(normalizeAlert);
        allStatus = status;
        summaryData = summary || {};
        generatedAt = summary.generated_at || allStatus[0]?.last_fetched || "";
        defaultWindowDays = Number(summary.default_view_days || summary.default_days || 30);
        epssThreshold = Number(summary.epss_threshold || 0.5);
        pruneDismissed();

        renderSourceFilters(summary.sources || []);
        renderStatus();
        renderStaleness();
        bindEvents();

        const daysFilter = document.getElementById("days-filter");
        if (![...daysFilter.options].some((o) => Number(o.value) === defaultWindowDays)) {
            const opt = document.createElement("option");
            opt.value = String(defaultWindowDays);
            opt.textContent = `Last ${defaultWindowDays} days`;
            daysFilter.appendChild(opt);
        }
        daysFilter.value = String(defaultWindowDays);
        document.getElementById("scope-stack").dataset.active = String(scope === "stack");
        document.getElementById("scope-all").dataset.active = String(scope === "all");

        renderChips();
        renderBrief();
        applyAndRender();
        if (scope === "all") ensureTailLoaded();
    } catch (error) {
        const tbody = document.getElementById("alerts-body");
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 9;
        cell.textContent = `Failed to load dashboard data: ${error.message}`;
        row.appendChild(cell);
        tbody.innerHTML = "";
        tbody.appendChild(row);
    }
}

init();

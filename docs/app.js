const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const sourceLabels = {
    apple: "Apple Security Updates",
    kev: "CISA Known Exploited Vulnerabilities",
    msrc: "Microsoft Security Updates",
    nvd: "NIST National Vulnerability Database",
};

const STALENESS_HOURS = 8;
const NEW_ALERT_HOURS = 48;

let allAlerts = [];
let allStatus = [];
let generatedAt = "";
let currentSort = { key: "published_date", desc: true };
let quickFilterActive = null; // "critical" | "exploited" | null

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
    const response = await fetch(path, { cache: "no-store" });
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
    now.setHours(0, 0, 0, 0);
    now.setDate(now.getDate() - days);
    return now.toISOString().slice(0, 10);
}

function isNewAlert(alert) {
    if (!alert.published_date) return false;
    const cutoff = new Date(Date.now() - NEW_ALERT_HOURS * 3600000);
    const published = parseDateValue(alert.published_date);
    if (!published) return false;
    return published >= cutoff;
}

function renderSourceFilters(sources) {
    const container = document.getElementById("source-filters");
    container.innerHTML = "";
    for (const source of sources) {
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
    const activeSeverities = new Set(
        [...document.querySelectorAll(".severity-filter:checked")].map((node) => node.value)
    );
    const activeSources = new Set(
        [...document.querySelectorAll(".source-filter:checked")].map((node) => node.value)
    );

    return allAlerts.filter((alert) => {
        const haystack = [
            alert.cve_id,
            alert.title,
            alert.vendor,
            alert.product,
            alert.description,
            alert.source,
        ].join(" ").toLowerCase();

        return alert.published_date >= cutoff
            && activeSeverities.has(alert.severity || "UNKNOWN")
            && activeSources.has(alert.source)
            && (!exploitedOnly || Boolean(alert.actively_exploited))
            && (!search || haystack.includes(search));
    });
}

function sortAlerts(alerts) {
    const { key, desc } = currentSort;
    return [...alerts].sort((a, b) => {
        let left = a[key] || "";
        let right = b[key] || "";

        if (key === "severity") {
            left = severityOrder[a.severity || "UNKNOWN"] ?? 5;
            right = severityOrder[b.severity || "UNKNOWN"] ?? 5;
        }

        if (left < right) return desc ? 1 : -1;
        if (left > right) return desc ? -1 : 1;
        return 0;
    });
}

function renderStaleness() {
    const banner = document.getElementById("staleness-banner");
    const ageSpan = document.getElementById("staleness-age");
    if (!generatedAt) {
        banner.classList.add("hidden");
        return;
    }
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
}


function renderSummary(alerts) {
    document.getElementById("generated-at").textContent = formatTimestamp(generatedAt);
    document.getElementById("visible-count").textContent = String(alerts.length);

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const alert of alerts) {
        counts[alert.severity || "UNKNOWN"] = (counts[alert.severity || "UNKNOWN"] || 0) + 1;
    }
    document.getElementById("count-critical").textContent = String(counts.CRITICAL);
    document.getElementById("count-high").textContent = String(counts.HIGH);
    document.getElementById("count-medium").textContent = String(counts.MEDIUM);
    document.getElementById("count-low").textContent = String(counts.LOW);
    document.getElementById("count-unknown").textContent = String(counts.UNKNOWN);
}

function renderAlerts(alerts) {
    const tbody = document.getElementById("alerts-body");
    const template = document.getElementById("alert-row-template");
    tbody.innerHTML = "";

    for (const alert of alerts) {
        const row = template.content.firstElementChild.cloneNode(true);
        row.dataset.severity = alert.severity || "UNKNOWN";
        row.dataset.source = alert.source;
        if (alert.actively_exploited) {
            row.dataset.exploited = "true";
        }

        const severityCell = row.querySelector(".severity-cell");
        const severityPill = document.createElement("span");
        severityPill.className = `pill ${String(alert.severity || "UNKNOWN").toLowerCase()}`;
        severityPill.textContent = alert.severity || "UNKNOWN";
        severityCell.appendChild(severityPill);

        const sourceCell = row.querySelector(".source-cell");
        const sourceTag = document.createElement("span");
        sourceTag.className = "source-tag";
        sourceTag.textContent = sourceLabels[alert.source] || alert.source;
        sourceCell.appendChild(sourceTag);

        const cveCell = row.querySelector(".cve-cell");
        if (alert.cve_id) {
            const cveLink = document.createElement("a");
            cveLink.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}`;
            cveLink.target = "_blank";
            cveLink.rel = "noreferrer";
            cveLink.textContent = alert.cve_id;
            cveCell.appendChild(cveLink);
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

        if (alert.description) {
            const description = document.createElement("small");
            description.textContent = alert.description;
            titleCell.appendChild(description);
        }

        row.querySelector(".vendor-cell").textContent = alert.vendor || "";

        const publishedCell = row.querySelector(".published-cell");
        const dateText = alert.published_date || "";
        const rel = relativeTime(alert.published_date);
        publishedCell.textContent = rel ? `${dateText} (${rel})` : dateText;

        row.querySelector(".exploited-cell").textContent = alert.actively_exploited ? "YES" : "";
        tbody.appendChild(row);
    }
}

function renderStatus() {
    const tbody = document.getElementById("status-body");
    const template = document.getElementById("status-row-template");
    tbody.innerHTML = "";

    for (const item of allStatus) {
        const row = template.content.firstElementChild.cloneNode(true);
        row.querySelector(".status-source").textContent = sourceLabels[item.source] || item.source;
        row.querySelector(".status-fetched").textContent = formatTimestamp(item.last_fetched);
        row.querySelector(".status-state").textContent = item.status;
        row.querySelector(".status-count").textContent = String(item.count ?? 0);
        row.querySelector(".status-error").textContent = item.error_message || "";
        tbody.appendChild(row);
    }
}

// --- Quick filters ---

function clearQuickFilter() {
    quickFilterActive = null;
    document.getElementById("qf-critical").dataset.active = "false";
    document.getElementById("qf-exploited").dataset.active = "false";
}

function resetAllFilters() {
    clearQuickFilter();
    document.getElementById("days-filter").value = "30";
    document.getElementById("search-filter").value = "";
    document.getElementById("exploited-filter").checked = false;
    document.querySelectorAll(".severity-filter").forEach((node) => { node.checked = true; });
    document.querySelectorAll(".source-filter").forEach((node) => { node.checked = true; });
    applyAndRender();
}

function activateQuickFilter(mode) {
    if (quickFilterActive === mode) {
        resetAllFilters();
        return;
    }
    // Reset to baseline first
    document.getElementById("search-filter").value = "";
    document.querySelectorAll(".source-filter").forEach((node) => { node.checked = true; });

    if (mode === "critical") {
        document.querySelectorAll(".severity-filter").forEach((node) => {
            node.checked = node.value === "CRITICAL";
        });
        document.getElementById("exploited-filter").checked = false;
        quickFilterActive = "critical";
        document.getElementById("qf-critical").dataset.active = "true";
        document.getElementById("qf-exploited").dataset.active = "false";
    } else if (mode === "exploited") {
        document.querySelectorAll(".severity-filter").forEach((node) => { node.checked = true; });
        document.getElementById("exploited-filter").checked = true;
        quickFilterActive = "exploited";
        document.getElementById("qf-exploited").dataset.active = "true";
        document.getElementById("qf-critical").dataset.active = "false";
    }

    applyAndRender();
}

function applyAndRender() {
    const filtered = sortAlerts(getFilteredAlerts());
    renderSummary(filtered);
    renderAlerts(filtered);
}

async function init() {
    try {
        const [alerts, status, summary] = await Promise.all([
            loadJson("./data/alerts.json"),
            loadJson("./data/status.json"),
            loadJson("./data/summary.json"),
        ]);
        allAlerts = alerts;
        allStatus = status;
        generatedAt = summary.generated_at || allStatus[0]?.last_fetched || "";

        renderSourceFilters(summary.sources || []);
        renderStatus();
        renderStaleness();

        document.getElementById("days-filter").value = String(summary.default_days || 30);
        document.getElementById("days-filter").addEventListener("change", () => {
            clearQuickFilter();
            applyAndRender();
        });
        document.getElementById("search-filter").addEventListener("input", () => {
            clearQuickFilter();
            applyAndRender();
        });
        document.getElementById("exploited-filter").addEventListener("change", () => {
            clearQuickFilter();
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
                currentSort = { key, desc: isSame ? !currentSort.desc : key === "published_date" };
                document.querySelectorAll("#alerts-table th").forEach((node) => node.classList.remove("sorted"));
                th.classList.add("sorted");
                applyAndRender();
            });
        });

        // Quick filter buttons
        document.getElementById("qf-critical").addEventListener("click", () => activateQuickFilter("critical"));
        document.getElementById("qf-exploited").addEventListener("click", () => activateQuickFilter("exploited"));
        document.getElementById("qf-reset").addEventListener("click", resetAllFilters);

        applyAndRender();
    } catch (error) {
        const tbody = document.getElementById("alerts-body");
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.textContent = `Failed to load dashboard data: ${error.message}`;
        row.appendChild(cell);
        tbody.innerHTML = "";
        tbody.appendChild(row);
    }
}

init();

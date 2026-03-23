const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

let allAlerts = [];
let allStatus = [];
let currentSort = { key: "published_date", desc: true };

async function loadJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) {
        throw new Error(`Failed to load ${path}: ${response.status}`);
    }
    return response.json();
}

function formatTimestamp(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
}

function isoCutoff(days) {
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    now.setDate(now.getDate() - days);
    return now.toISOString().slice(0, 10);
}

function renderSourceFilters(sources) {
    const container = document.getElementById("source-filters");
    container.innerHTML = "";
    for (const source of sources) {
        const label = document.createElement("label");
        label.className = "checkbox";
        label.innerHTML = `<input class="source-filter" type="checkbox" value="${source}" checked> ${source.toUpperCase()}`;
        container.appendChild(label);
    }
    container.querySelectorAll(".source-filter").forEach((node) => {
        node.addEventListener("change", applyAndRender);
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

function renderSummary(alerts, generatedAt) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const alert of alerts) {
        counts[alert.severity || "UNKNOWN"] = (counts[alert.severity || "UNKNOWN"] || 0) + 1;
    }
    document.getElementById("generated-at").textContent = formatTimestamp(generatedAt);
    document.getElementById("visible-count").textContent = String(alerts.length);
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

        row.querySelector(".severity-cell").innerHTML =
            `<span class="pill ${String(alert.severity || "UNKNOWN").toLowerCase()}">${alert.severity || "UNKNOWN"}</span>`;
        row.querySelector(".source-cell").innerHTML =
            `<span class="source-tag">${alert.source.toUpperCase()}</span>`;

        row.querySelector(".cve-cell").innerHTML = alert.cve_id
            ? `<a href="https://nvd.nist.gov/vuln/detail/${alert.cve_id}" target="_blank" rel="noreferrer">${alert.cve_id}</a>`
            : "";

        const titleCell = row.querySelector(".title-cell");
        const titleText = alert.title || "";
        const description = alert.description ? `<small>${alert.description}</small>` : "";
        if (alert.url) {
            titleCell.innerHTML = `<a href="${alert.url}" target="_blank" rel="noreferrer">${titleText}</a>${description}`;
        } else {
            titleCell.innerHTML = `${titleText}${description}`;
        }

        row.querySelector(".vendor-cell").textContent = alert.vendor || "";
        row.querySelector(".published-cell").textContent = alert.published_date || "";
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
        row.querySelector(".status-source").textContent = item.source.toUpperCase();
        row.querySelector(".status-fetched").textContent = formatTimestamp(item.last_fetched);
        row.querySelector(".status-state").textContent = item.status;
        row.querySelector(".status-count").textContent = String(item.count ?? 0);
        row.querySelector(".status-error").textContent = item.error_message || "";
        tbody.appendChild(row);
    }
}

function applyAndRender() {
    const filtered = sortAlerts(getFilteredAlerts());
    renderSummary(filtered, allStatus[0]?.last_fetched || "");
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
        renderSourceFilters(summary.sources || []);
        renderStatus();

        document.getElementById("days-filter").value = String(summary.default_days || 30);
        document.getElementById("days-filter").addEventListener("change", applyAndRender);
        document.getElementById("search-filter").addEventListener("input", applyAndRender);
        document.getElementById("exploited-filter").addEventListener("change", applyAndRender);
        document.querySelectorAll(".severity-filter").forEach((node) => {
            node.addEventListener("change", applyAndRender);
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

        renderSummary(allAlerts, summary.generated_at);
        applyAndRender();
    } catch (error) {
        const tbody = document.getElementById("alerts-body");
        tbody.innerHTML = `<tr><td colspan="7">Failed to load dashboard data: ${error.message}</td></tr>`;
    }
}

init();


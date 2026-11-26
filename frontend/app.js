// State
let selectedFile = null;

// DOM Elements
const tabFileBtn = document.getElementById("tab-file-btn");
const tabUrlBtn = document.getElementById("tab-url-btn");
const tabFileContent = document.getElementById("tab-file-content");
const tabUrlContent = document.getElementById("tab-url-content");

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const browseBtn = document.getElementById("browse-btn");
const previewArea = document.getElementById("preview-area");
const imagePreview = document.getElementById("image-preview");
const previewFilename = document.getElementById("preview-filename");
const previewFilesize = document.getElementById("preview-filesize");
const clearFileBtn = document.getElementById("clear-file-btn");
const dropzoneContent = document.querySelector(".dropzone-content");

const urlInput = document.getElementById("url-input");
const scanUrlBtn = document.getElementById("scan-url-btn");

const actionBar = document.getElementById("action-bar");
const submitScanBtn = document.getElementById("submit-scan-btn");
const scanProgress = document.getElementById("scan-progress");
const progressFill = document.getElementById("progress-fill");
const progressText = document.getElementById("progress-text");

const resultsSection = document.getElementById("results-section");
const rescanBtn = document.getElementById("rescan-btn");

// Tabs
tabFileBtn.addEventListener("click", () => {
    tabFileBtn.classList.add("active");
    tabUrlBtn.classList.remove("active");
    tabFileContent.classList.remove("hidden");
    tabUrlContent.classList.add("hidden");
    if (selectedFile) actionBar.classList.remove("hidden");
});

tabUrlBtn.addEventListener("click", () => {
    tabUrlBtn.classList.add("active");
    tabFileBtn.classList.remove("active");
    tabUrlContent.classList.remove("hidden");
    tabFileContent.classList.add("hidden");
    actionBar.classList.add("hidden");
});

// File Browse & Drag/Drop
browseBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
        handleFileSelect(e.target.files[0]);
    }
});

dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag-over");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("drag-over");
});

dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag-over");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

function handleFileSelect(file) {
    if (!file.type.startsWith("image/")) {
        alert("Please upload an image file (PNG, JPG, WEBP).");
        return;
    }
    selectedFile = file;
    previewFilename.textContent = file.name;
    previewFilesize.textContent = (file.size / 1024).toFixed(1) + " KB";

    const reader = new FileReader();
    reader.onload = (e) => {
        imagePreview.src = e.target.result;
        dropzoneContent.classList.add("hidden");
        previewArea.classList.remove("hidden");
        actionBar.classList.remove("hidden");
    };
    reader.readAsDataURL(file);
}

clearFileBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    selectedFile = null;
    fileInput.value = "";
    previewArea.classList.add("hidden");
    dropzoneContent.classList.remove("hidden");
    actionBar.classList.add("hidden");
});

// Action Buttons
submitScanBtn.addEventListener("click", () => {
    if (!selectedFile) return;
    performScanFile(selectedFile);
});

scanUrlBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) {
        alert("Please enter a valid URL to inspect.");
        return;
    }
    performScanUrl(url);
});

rescanBtn.addEventListener("click", () => {
    resultsSection.classList.add("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
});

// API Calls with Animated Progress
async function performScanFile(file) {
    startProgress("Decoding QR code matrix...");
    const formData = new FormData();
    formData.append("file", file);

    try {
        updateProgress(40, "Extracting payload & checking SSRF firewall...");
        const response = await fetch("/api/scan-file?perform_network_checks=true", {
            method: "POST",
            body: formData
        });

        updateProgress(70, "Auditing redirects, SSL & detonating page in sandbox...");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Scan request failed");
        }

        updateProgress(100, "Rendering threat assessment...");
        setTimeout(() => {
            finishProgress();
            renderReport(data);
        }, 300);
    } catch (err) {
        finishProgress();
        alert("Error during scan: " + err.message);
    }
}

async function performScanUrl(url) {
    startProgress("Submitting URL to security pipeline...");
    try {
        updateProgress(50, "Evaluating structural heuristics & redirect paths...");
        const response = await fetch("/api/scan-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url, perform_network_checks: true })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Scan request failed");
        }

        updateProgress(100, "Aggregating threat intelligence...");
        setTimeout(() => {
            finishProgress();
            // Adapt URL response structure
            renderReport({
                success: data.success,
                payload: data.target_url,
                classification: "url",
                details: data.report
            });
        }, 300);
    } catch (err) {
        finishProgress();
        alert("Error during scan: " + err.message);
    }
}

// Progress Helpers
function startProgress(text) {
    scanProgress.classList.remove("hidden");
    progressFill.style.width = "20%";
    progressText.textContent = text;
    submitScanBtn.disabled = true;
    scanUrlBtn.disabled = true;
}

function updateProgress(percent, text) {
    progressFill.style.width = percent + "%";
    progressText.textContent = text;
}

function finishProgress() {
    scanProgress.classList.add("hidden");
    submitScanBtn.disabled = false;
    scanUrlBtn.disabled = false;
}

// Report Rendering
function renderReport(data) {
    resultsSection.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth" });

    document.getElementById("report-timestamp").textContent = "Scanned on: " + new Date().toLocaleString();

    // Guard: a failed decode / missing analysis must NEVER be shown as "safe".
    if (data.success === false || !data.details || !data.details.risk_assessment) {
        showScanError(data.message || "No QR code could be decoded from this image. Could not assess safety — do not assume it is safe.");
        return;
    }

    const details = data.details || {};
    const risk = details.risk_assessment || { score: 0, verdict: "safe", summary: "Clean payload", breakdown: [] };
    const score = risk.score || 0;
    const verdict = (risk.verdict || "safe").toLowerCase();

    // 1. Verdict Banner & Radial Gauge
    const verdictBanner = document.getElementById("verdict-banner");
    verdictBanner.className = "verdict-banner " + verdict;

    const verdictBadge = document.getElementById("verdict-badge");
    verdictBadge.className = "verdict-badge " + verdict;
    verdictBadge.textContent = verdict.toUpperCase();

    document.getElementById("verdict-summary").textContent = risk.summary || "Scan complete";

    const verdictDesc = {
        safe: "No significant phishing indicators were found across the static, infrastructure, and live sandbox-render layers.",
        caution: "Some suspicious indicators were detected. Review the findings below before deciding whether to proceed.",
        dangerous: "Strong phishing indicators were detected — including live content signals. Do not visit this destination or enter credentials."
    };
    document.getElementById("verdict-desc").textContent = verdictDesc[verdict] || verdictDesc.safe;

    const gaugeScore = document.getElementById("gauge-score");
    gaugeScore.textContent = score;

    const gauge = document.getElementById("radial-gauge");
    let gaugeColor = "#10b981";
    if (verdict === "caution") gaugeColor = "#f59e0b";
    if (verdict === "dangerous") gaugeColor = "#ef4444";
    gauge.style.background = `conic-gradient(${gaugeColor} 0% ${score}%, var(--border-color) ${score}% 100%)`;

    // 2. Metrics Bar
    document.getElementById("metric-type").textContent = (data.classification || "UNKNOWN").toUpperCase();
    document.getElementById("metric-payload").textContent = data.payload || "-";
    document.getElementById("metric-payload").title = data.payload || "";

    const redirects = details.redirect_analysis;
    const hopCount = redirects && redirects.redirect_count !== undefined ? redirects.redirect_count : 0;
    document.getElementById("metric-hops").textContent = hopCount + (hopCount === 1 ? " hop" : " hops");

    const domainAge = details.domain_info && details.domain_info.domain_age;
    if (domainAge && domainAge.available && domainAge.age_days !== null) {
        document.getElementById("metric-age").textContent = domainAge.age_days + " days";
    } else {
        document.getElementById("metric-age").textContent = "N/A";
    }

    // 3. Detected Indicators List
    const indicatorsList = document.getElementById("indicators-list");
    indicatorsList.innerHTML = "";
    const breakdown = risk.breakdown || [];
    document.getElementById("indicator-count").textContent = breakdown.length;

    if (breakdown.length === 0) {
        indicatorsList.innerHTML = `<div class="info-row"><span class="text-muted">No threat indicators flagged. Target appears clean.</span></div>`;
    } else {
        breakdown.forEach(item => {
            const div = document.createElement("div");
            div.className = "indicator-item";
            const sev = (item.severity || "medium").toLowerCase();
            div.innerHTML = `
                <span>${escapeHtml(item.indicator)}</span>
                <span class="severity-tag severity-${sev}">+${item.points} pts &bull; ${sev.toUpperCase()}</span>
            `;
            indicatorsList.appendChild(div);
        });
    }

    // 4. Redirect Chain Timeline
    const timeline = document.getElementById("redirect-timeline");
    timeline.innerHTML = "";
    if (redirects && redirects.redirect_chain && redirects.redirect_chain.length > 0) {
        redirects.redirect_chain.forEach((hop, i) => {
            const step = document.createElement("div");
            step.className = "timeline-step";
            step.innerHTML = `
                <div>
                    <span class="timeline-code mono">${hop.status_code || "GET"}</span>
                    <span class="mono" style="word-break: break-all;">${escapeHtml(hop.url)}</span>
                </div>
            `;
            timeline.appendChild(step);
        });

        if (redirects.domain_changed) {
            const warningHop = document.createElement("div");
            warningHop.className = "timeline-step";
            warningHop.innerHTML = `<span class="severity-tag severity-high">⚠️ Destination Domain Changed From Original</span>`;
            timeline.appendChild(warningHop);
        }
    } else {
        timeline.innerHTML = `<div class="info-row"><span class="text-muted">No redirect hops recorded (direct single request).</span></div>`;
    }

    // 5. Host & SSL Certificate Table
    const sslTable = document.getElementById("ssl-info-table");
    sslTable.innerHTML = "";
    const sslInfo = details.domain_info && details.domain_info.ssl;
    const safety = details.safety_check;

    addTableRow(sslTable, "IP Addresses", (safety && safety.resolved_ips && safety.resolved_ips.length) ? safety.resolved_ips.join(", ") : "Resolved via DNS");
    addTableRow(sslTable, "SSL Valid", sslInfo && sslInfo.available ? (sslInfo.valid ? "✅ Trusted" : "❌ Untrusted / Invalid") : "N/A");
    addTableRow(sslTable, "SSL Issuer", sslInfo && sslInfo.issuer ? sslInfo.issuer : "Unknown / N/A");
    addTableRow(sslTable, "SSL Expiry", sslInfo && sslInfo.not_after ? `${sslInfo.not_after} (${sslInfo.days_until_expiry} days left)` : "N/A");
    addTableRow(sslTable, "Self-Signed", sslInfo && sslInfo.self_signed ? "⚠️ Yes (Self-Signed)" : "No");

    // 5b. Live Page Inspection (Dynamic Sandbox Layer)
    renderContentAnalysis(details.content_analysis);

    // 5c. Threat Intelligence (VirusTotal reputation)
    renderReputation(details.reputation);

    // 6. Static URL Heuristics Table
    const heuristicsTable = document.getElementById("heuristics-table");
    heuristicsTable.innerHTML = "";
    const urlAnalysis = details.url_analysis;
    const shortener = details.shortener_info;

    if (urlAnalysis) {
        addTableRow(heuristicsTable, "Protocol Scheme", urlAnalysis.scheme ? urlAnalysis.scheme.toUpperCase() : "N/A");
        addTableRow(heuristicsTable, "Uses HTTPS", urlAnalysis.uses_https ? "✅ Yes" : "⚠️ No (Insecure HTTP)");
        addTableRow(heuristicsTable, "Is Shortener", shortener && shortener.is_shortener ? `⚠️ Yes (${shortener.service})` : "No");
        addTableRow(heuristicsTable, "Punycode (Homograph)", urlAnalysis.contains_punycode ? "⚠️ Detected (xn--)" : "None");
        addTableRow(heuristicsTable, "Raw IP as Hostname", urlAnalysis.contains_ip_address ? "⚠️ Yes" : "No");
        addTableRow(heuristicsTable, "Embedded Credentials", urlAnalysis.contains_credentials ? "⚠️ Yes" : "No");
    } else {
        heuristicsTable.innerHTML = `<div class="info-row"><span class="text-muted">Not applicable for this payload type.</span></div>`;
    }
}

// Live Page Inspection (dynamic sandbox render) renderer
function renderContentAnalysis(content) {
    const card = document.getElementById("live-inspection-card");
    const findings = document.getElementById("live-findings");
    const statusEl = document.getElementById("live-status");
    const shot = document.getElementById("live-screenshot");
    const shotEmpty = document.getElementById("live-screenshot-empty");

    // Hide the whole panel if dynamic analysis did not run (e.g. non-URL payload).
    if (!content) {
        card.classList.add("hidden");
        return;
    }
    card.classList.remove("hidden");
    findings.innerHTML = "";

    if (!content.available) {
        statusEl.textContent = "UNAVAILABLE";
        statusEl.className = "live-status mono status-warn";
        shot.classList.add("hidden");
        shotEmpty.classList.remove("hidden");
        shotEmpty.textContent = "Sandbox render unavailable (" + (content.error || "unknown") + ")";
        findings.innerHTML = `<div class="info-row"><span class="text-muted">The page could not be rendered in the sandbox, so content signals were skipped. The verdict relies on the static and infrastructure layers only.</span></div>`;
        return;
    }

    statusEl.textContent = "RENDERED";
    statusEl.className = "live-status mono status-ok";

    // Screenshot
    if (content.screenshot_base64) {
        shot.src = "data:image/png;base64," + content.screenshot_base64;
        shot.classList.remove("hidden");
        shotEmpty.classList.add("hidden");
    } else {
        shot.classList.add("hidden");
        shotEmpty.classList.remove("hidden");
        shotEmpty.textContent = "No screenshot captured";
    }

    // Findings as status chips
    const brands = content.claimed_brands || [];
    const mismatch = content.brand_domain_mismatch;
    const hasPw = content.has_password_field;
    const crossDomain = content.cross_domain_form;

    addFinding(
        findings,
        "Scan Origin",
        content.proxied ? "🛡️ Anonymized (proxy/Tor)" : "⚠️ Direct — your IP was exposed",
        content.proxied ? "good" : "bad"
    );
    addFinding(findings, "Page Title", content.page_title || "—", "neutral");
    addFinding(findings, "Password Field", hasPw ? "⚠️ Present" : "None", hasPw ? "bad" : "good");
    addFinding(findings, "Claimed Brand", brands.length ? brands.join(", ") : "None detected", brands.length ? "neutral" : "good");
    addFinding(
        findings,
        "Brand vs Domain",
        mismatch ? "🚨 IMPERSONATION — brand does not match host" : "Consistent",
        mismatch ? "bad" : "good"
    );
    if (crossDomain) {
        const targets = (content.cross_domain_targets || []).join(", ");
        addFinding(findings, "Form Destination", "⚠️ Cross-domain → " + (targets || "external"), "bad");
    } else {
        addFinding(findings, "Form Destination", "Same domain", "good");
    }
    addFinding(findings, "Final URL", content.final_url || "—", "neutral");
}

// Error state: decode failed or analysis unavailable — explicitly NOT "safe".
function showScanError(message) {
    const banner = document.getElementById("verdict-banner");
    banner.className = "verdict-banner error";

    const badge = document.getElementById("verdict-badge");
    badge.className = "verdict-badge caution";
    badge.textContent = "SCAN FAILED";

    document.getElementById("verdict-summary").textContent = "Could not decode / analyse this QR code";
    document.getElementById("verdict-desc").textContent = message;

    const gauge = document.getElementById("radial-gauge");
    gauge.style.background = "conic-gradient(var(--text-muted) 0% 100%)";
    document.getElementById("gauge-score").textContent = "–";

    // Reset metric tiles.
    document.getElementById("metric-type").textContent = "UNKNOWN";
    document.getElementById("metric-payload").textContent = "–";
    document.getElementById("metric-hops").textContent = "–";
    document.getElementById("metric-age").textContent = "–";

    // Show the message in the indicators card; clear/hide the rest.
    document.getElementById("indicator-count").textContent = "0";
    document.getElementById("indicators-list").innerHTML =
        `<div class="info-row"><span class="text-muted">${escapeHtml(message)}</span></div>`;
    ["redirect-timeline", "ssl-info-table", "heuristics-table", "reputation-table"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = `<div class="info-row"><span class="text-muted">Not available — scan did not complete.</span></div>`;
    });
    const live = document.getElementById("live-inspection-card");
    if (live) live.classList.add("hidden");
}

// Threat-intelligence (VirusTotal) renderer
function renderReputation(rep) {
    const table = document.getElementById("reputation-table");
    if (!table) return;
    table.innerHTML = "";

    if (!rep || !rep.available) {
        const err = rep && rep.error;
        if (err === "not_found") {
            // Key worked; target simply isn't in VirusTotal's database.
            addTableRow(table, "VT Verdict", "📭 No record in VirusTotal");
            addTableRow(table, "Note", "Not a known threat — but new phishing is not yet listed, so this is not proof of safety.");
        } else {
            const reason = err === "no_api_key"
                ? "VirusTotal not configured. Add QI_VT_API_KEY to your .env to enable."
                : err === "rate_limited"
                    ? "VirusTotal rate limit reached — try again shortly."
                    : "Threat-intelligence lookup unavailable for this target.";
            table.innerHTML = `<div class="info-row"><span class="text-muted">${escapeHtml(reason)}</span></div>`;
        }
        return;
    }

    const verdict = (rep.verdict || "unknown").toLowerCase();
    let verdictStr = "Unknown";
    if (verdict === "malicious") verdictStr = "🚨 Malicious";
    else if (verdict === "suspicious") verdictStr = "⚠️ Suspicious";
    else if (verdict === "clean") verdictStr = "✅ Listed, no engine flagged it";

    addTableRow(table, "VT Verdict", verdictStr);
    addTableRow(table, "Malicious detections", String(rep.malicious || 0));
    addTableRow(table, "Suspicious detections", String(rep.suspicious || 0));
    addTableRow(table, "Engines reporting", String(rep.total_engines || 0));
    if (verdict === "clean") {
        addTableRow(table, "Note", "Clean is not proof of safety: new phishing is not yet in any feed.");
    }
}

function addFinding(container, label, value, tone) {
    const row = document.createElement("div");
    row.className = "finding-row tone-" + (tone || "neutral");
    row.innerHTML = `
        <span class="finding-label">${escapeHtml(label)}</span>
        <span class="finding-value mono">${escapeHtml(value)}</span>
    `;
    container.appendChild(row);
}

function addTableRow(container, label, value) {
    const row = document.createElement("div");
    row.className = "info-row";
    row.innerHTML = `
        <span class="info-label">${escapeHtml(label)}</span>
        <span class="info-value mono">${escapeHtml(value)}</span>
    `;
    container.appendChild(row);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, (m) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[m]);
}

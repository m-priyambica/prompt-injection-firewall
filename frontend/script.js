
/* ==========================================================
   PROMPT INJECTION FIREWALL
   FRONTEND APPLICATION LOGIC
========================================================== */

const API = {
    chat: "/api/chat",
    metrics: "/api/metrics",
    reviews: "/api/reviews",
    health: "/api/health"
};

const $ = (id) => document.getElementById(id);

let latestMetrics = null;
let resizeTimeout = null;


// ==========================================================
// 1. GENERAL HELPERS
// ==========================================================

function setText(id, value) {
    const element = $(id);

    if (element) {
        element.textContent = value ?? "—";
    }
}

function formatNumber(value) {
    return Number(value || 0).toLocaleString();
}

function formatPercent(value) {
    if (value === null || value === undefined || value === "") {
        return "—";
    }

    return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatTime(value) {
    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function showElement(id, visible = true) {
    const element = $(id);

    if (element) {
        element.style.display = visible ? "" : "none";
    }
}

function safeJSON(value) {
    try {
        return JSON.stringify(value, null, 2);
    } catch {
        return String(value);
    }
}

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.error || `Request failed: ${response.status}`
        );
    }

    return data;
}


// ==========================================================
// 2. NAVIGATION
// ==========================================================

function initializeNavigation() {
    const links = document.querySelectorAll(
        ".sidebar a, .sidebar button, nav a"
    );

    links.forEach(link => {
        link.addEventListener("click", () => {
            links.forEach(item => item.classList.remove("active"));
            link.classList.add("active");
        });
    });
}


// ==========================================================
// 3. PROMPT CHARACTER COUNT
// ==========================================================

function initializeCharacterCount() {
    const promptInput = $("prompt-input");
    const counter = $("character-count");

    if (!promptInput || !counter) return;

    function updateCount() {
        counter.textContent = `${promptInput.value.length} / 10000`;
    }

    promptInput.addEventListener("input", updateCount);

    updateCount();
}


// ==========================================================
// 4. PROMPT SUBMISSION
// ==========================================================

function getSelectedMode() {
    const selected = document.querySelector(
        'input[name="execution-mode"]:checked'
    );

    return selected ? selected.value : "protected";
}

function setLoading(loading) {
    const button = $("send-button");

    if (!button) return;

    button.disabled = loading;

    button.textContent = loading
        ? "Analyzing..."
        : "Run Security Test";
}

async function submitPrompt() {
    const promptInput = $("prompt-input");

    if (!promptInput) return;

    const prompt = promptInput.value.trim();

    if (!prompt) {
        alert("Please enter a prompt first.");
        return;
    }

    if (prompt.length > 10000) {
        alert("Prompt cannot exceed 10,000 characters.");
        return;
    }

    const mode = getSelectedMode();

    setLoading(true);
    showElement("result-section", true);

    setText("result-status", "PROCESSING");
    setText("result-message", "Analyzing your prompt...");
    setText("llm-response", "Waiting for model response...");

    try {
        const result = await fetchJSON(API.chat, {
            method: "POST",
            body: JSON.stringify({
                prompt,
                mode
            })
        });

        displayResult(result);

        await refreshDashboard();

    } catch (error) {
        console.error("Prompt submission failed:", error);

        setText("result-status", "ERROR");
        setText("result-message", error.message);
        setText("llm-response", "Unable to complete the request.");

        setText("risk-score", "—");
        setText("firewall-decision", "ERROR");
        setText("rule-score", "—");
        setText("ml-score", "—");

    } finally {
        setLoading(false);
    }
}


// ==========================================================
// 5. RESULT DISPLAY
// ==========================================================

function displayResult(result) {
    const status = String(
        result.status || "unknown"
    ).toLowerCase();

    const mode = result.mode || getSelectedMode();

    setText("result-status", status.toUpperCase());

    setText(
        "result-message",
        result.message || "Request completed."
    );

    setText(
        "processing-time",
        result.latency_ms != null
            ? `${Number(result.latency_ms).toFixed(2)} ms`
            : "—"
    );

    const statusElement = $("result-status");

    if (statusElement) {
        statusElement.className = `status-${status}`;
    }

    // Display a response only when the backend returns one.
    setText(
        "llm-response",
        result.response || "No model response was returned."
    );

    displayInputAnalysis(result.analysis, mode);

    displayOutputInspection(
        result.output_inspection,
        mode
    );

    const section = $("result-section");

    if (section) {
        section.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });
    }
}


// ==========================================================
// 6. INPUT SECURITY ANALYSIS
// ==========================================================

function displayInputAnalysis(analysis, mode) {

    // Baseline mode does not perform firewall analysis.
    if (mode !== "protected" || !analysis) {

        setText("risk-score", "N/A");
        setText("firewall-decision", "Not performed");
        setText("rule-score", "N/A");
        setText("ml-score", "N/A");
        setText("highest-variant", "N/A");
        setText("analysis-decision", "Not performed");

        setText(
            "rule-findings",
            "Input firewall analysis is not performed in baseline mode."
        );

        setText(
            "normalization-variants",
            "Not available in baseline mode."
        );

        return;
    }

    // Get the highest-risk variant.
    const highest = analysis.highest_risk_analysis || {};

    // Get the actual nested detector results.
    const ruleAnalysis = highest.rule_analysis || {};
    const mlAnalysis = highest.ml_analysis || {};
    const riskAnalysis = highest.risk_analysis || {};

    // ------------------------------------------------------
    // RISK SCORE
    // ------------------------------------------------------

    const risk = analysis.final_risk_score;

    setText(
        "risk-score",
        risk != null
            ? formatPercent(risk)
            : "—"
    );

    // ------------------------------------------------------
    // FIREWALL DECISION
    // ------------------------------------------------------

    setText(
        "firewall-decision",
        analysis.decision || "—"
    );

    setText(
        "analysis-decision",
        highest.decision || analysis.decision || "—"
    );

    // ------------------------------------------------------
    // RULE SCORE
    //
    // Actual pipeline path:
    // highest_risk_analysis
    //     -> rule_analysis
    //         -> rule_score
    // ------------------------------------------------------

    const ruleScore =
        analysis.rule_score ??
        ruleAnalysis.rule_score ??
        riskAnalysis.rule_score;

    setText(
        "rule-score",
        ruleScore != null
            ? formatPercent(ruleScore)
            : "—"
    );

    // ------------------------------------------------------
    // ML SCORE
    //
    // Actual pipeline path:
    // highest_risk_analysis
    //     -> ml_analysis
    //         -> injection_probability
    // ------------------------------------------------------

    const mlScore =
        analysis.ml_score ??
        mlAnalysis.injection_probability ??
        riskAnalysis.ml_injection_probability;

    setText(
        "ml-score",
        mlScore != null
            ? formatPercent(mlScore)
            : "—"
    );

    // ------------------------------------------------------
    // HIGHEST RISK VARIANT
    // ------------------------------------------------------

    setText(
        "highest-variant",
        highest.source || highest.text || "Original prompt"
    );

    // ------------------------------------------------------
    // RULE FINDINGS
    // ------------------------------------------------------

    const findings =
        ruleAnalysis.findings ||
        ruleAnalysis.matches ||
        [];

    let findingsText = findings.length
        ? safeJSON(findings)
        : "No structural rule findings reported.";

    // ------------------------------------------------------
    // CONFIDENTIAL-DATA DETECTION
    // ------------------------------------------------------

    const sensitiveDetection =
        analysis.sensitive_request_detection;

    if (sensitiveDetection?.is_sensitive) {

        const categories =
            sensitiveDetection.categories || [];

        findingsText =
            "CONFIDENTIAL-DATA POLICY TRIGGERED\n\n" +
            safeJSON(categories) +
            "\n\nReason: " +
            (sensitiveDetection.reason || "Protected information requested.");
    }

    setText("rule-findings", findingsText);

    // ------------------------------------------------------
    // NORMALIZATION VARIANTS
    // ------------------------------------------------------

    const variants = analysis.normalization_variants;

    setText(
        "normalization-variants",
        variants
            ? safeJSON(variants)
            : "No normalization variants returned."
    );
}


// ==========================================================
// 7. OUTPUT SECURITY INSPECTION
// ==========================================================

function displayOutputInspection(inspection, mode) {

    if (mode !== "protected" || !inspection) {

        setText(
            "output-inspection",
            "Output inspection is not available for this request."
        );

        setText(
            "output-findings",
            "Not performed."
        );

        return;
    }

    setText(
        "output-inspection",
        inspection.is_safe ? "SAFE" : "UNSAFE"
    );

    const findings = inspection.findings || [];

    setText(
        "output-findings",
        findings.length
            ? safeJSON(findings)
            : "No confidential information detected."
    );
}


// ==========================================================
// 8. DASHBOARD METRICS
// ==========================================================

async function loadMetrics() {

    try {
        const metrics = await fetchJSON(API.metrics);

        latestMetrics = metrics;

        // Main overview cards
        setText(
            "total-requests",
            formatNumber(metrics.total_requests)
        );

        setText(
            "allowed-count",
            formatNumber(metrics.allowed)
        );

        setText(
            "blocked-count",
            formatNumber(metrics.blocked)
        );

        setText(
            "review-count",
            formatNumber(metrics.review)
        );

        setText(
            "output-blocked-count",
            formatNumber(metrics.output_blocked)
        );

        setText(
            "average-latency",
            `${Number(metrics.average_latency_ms || 0).toFixed(2)} ms`
        );

        // Model comparison
        setText(
            "baseline-requests",
            formatNumber(metrics.baseline_requests)
        );

        setText(
            "protected-requests",
            formatNumber(metrics.protected_requests)
        );

        // Analytics summary
        setText(
            "analytics-baseline",
            formatNumber(metrics.baseline_requests)
        );

        setText(
            "analytics-protected",
            formatNumber(metrics.protected_requests)
        );

        setText(
            "analytics-output-blocked",
            formatNumber(metrics.output_blocked)
        );

        setText(
            "analytics-errors",
            formatNumber(metrics.errors)
        );

        drawCharts(metrics);

        renderEvents(metrics.recent_events || []);

    } catch (error) {
        console.error("Metrics loading failed:", error);
    }
}


// ==========================================================
// 9. CHART HELPERS
// ==========================================================

function prepareCanvas(canvas) {

    if (!canvas) return null;

    const rect = canvas.getBoundingClientRect();

    if (!rect.width || !rect.height) return null;

    const ratio = window.devicePixelRatio || 1;

    canvas.width = rect.width * ratio;
    canvas.height = rect.height * ratio;

    const context = canvas.getContext("2d");

    context.scale(ratio, ratio);

    return {
        context,
        width: rect.width,
        height: rect.height
    };
}


// ==========================================================
// 10. REQUEST COMPARISON BAR CHART
// ==========================================================

function drawRequestChart(metrics) {

    const canvas = $("request-chart");

    const prepared = prepareCanvas(canvas);

    if (!prepared) return;

    const {
        context: ctx,
        width,
        height
    } = prepared;

    const baseline = Number(
        metrics.baseline_requests || 0
    );

    const protectedRequests = Number(
        metrics.protected_requests || 0
    );

    const total = baseline + protectedRequests;

    const empty = $("request-chart-empty");

    if (empty) {
        empty.style.display = total === 0 ? "" : "none";
    }

    ctx.clearRect(0, 0, width, height);

    if (total === 0) return;

    const items = [
        {
            label: "Baseline",
            value: baseline,
            color: "#64818a"
        },
        {
            label: "Protected",
            value: protectedRequests,
            color: "#16d6c2"
        }
    ];

    const maxValue = Math.max(
        ...items.map(item => item.value),
        1
    );

    const chartHeight = height - 55;
    const barWidth = Math.min(65, width / 5);
    const gap = width / 4;

    items.forEach((item, index) => {

        const x = gap * (index + 0.65);

        const barHeight =
            (item.value / maxValue) * chartHeight;

        ctx.fillStyle = item.color;

        ctx.beginPath();

        ctx.roundRect(
            x,
            chartHeight - barHeight + 8,
            barWidth,
            barHeight,
            7
        );

        ctx.fill();

        ctx.fillStyle = "#e5f5f2";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";

        ctx.fillText(
            formatNumber(item.value),
            x + barWidth / 2,
            chartHeight - barHeight
        );

        ctx.fillStyle = "#91aaa6";

        ctx.fillText(
            item.label,
            x + barWidth / 2,
            height - 12
        );
    });
}


// ==========================================================
// 11. SECURITY DECISION DONUT CHART
// ==========================================================

function drawDecisionChart(metrics) {

    const canvas = $("decision-chart");

    const prepared = prepareCanvas(canvas);

    if (!prepared) return;

    const {
        context: ctx,
        width,
        height
    } = prepared;

    const values = [
        {
            label: "Allowed",
            value: Number(metrics.allowed || 0),
            color: "#27d9a0"
        },
        {
            label: "Blocked",
            value: Number(metrics.blocked || 0),
            color: "#ff6478"
        },
        {
            label: "Review",
            value: Number(metrics.review || 0),
            color: "#f4c66a"
        }
    ];

    const total = values.reduce(
        (sum, item) => sum + item.value,
        0
    );

    const empty = $("decision-chart-empty");

    if (empty) {
        empty.style.display = total === 0 ? "" : "none";
    }

    ctx.clearRect(0, 0, width, height);

    if (total === 0) return;

    const centerX = width / 2;
    const centerY = height / 2;

    const radius = Math.min(width, height) * 0.32;
    const thickness = radius * 0.42;

    let startAngle = -Math.PI / 2;

    values.forEach(item => {

        if (item.value <= 0) return;

        const slice =
            (item.value / total) * Math.PI * 2;

        ctx.beginPath();

        ctx.arc(
            centerX,
            centerY,
            radius,
            startAngle,
            startAngle + slice
        );

        ctx.strokeStyle = item.color;
        ctx.lineWidth = thickness;
        ctx.stroke();

        startAngle += slice;
    });

    ctx.fillStyle = "#e5f5f2";
    ctx.textAlign = "center";
    ctx.font = "bold 20px sans-serif";

    ctx.fillText(
        formatNumber(total),
        centerX,
        centerY + 5
    );

    ctx.font = "11px sans-serif";
    ctx.fillStyle = "#91aaa6";

    ctx.fillText(
        "Requests",
        centerX,
        centerY + 23
    );
}


// ==========================================================
// 12. DRAW BOTH CHARTS
// ==========================================================

function drawCharts(metrics) {
    drawRequestChart(metrics);
    drawDecisionChart(metrics);
}


// ==========================================================
// 13. RECENT SECURITY EVENTS
// ==========================================================

function renderEvents(events) {

    const table = $("events-table");

    if (!table) return;

    table.replaceChildren();

    if (!events.length) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "No security events recorded yet.";

        row.appendChild(cell);
        table.appendChild(row);

        return;
    }

    events.forEach(event => {

        const row = document.createElement("tr");

        const values = [
            formatTime(event.timestamp),
            event.mode || "—",
            event.status || "—",
            event.decision || "—",

            event.risk_score != null
                ? formatPercent(event.risk_score)
                : "—",

            event.latency_ms != null
                ? `${Number(event.latency_ms).toFixed(2)} ms`
                : "—"
        ];

        values.forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);
        });

        table.appendChild(row);
    });
}


// ==========================================================
// 14. REVIEW QUEUE
// ==========================================================

async function loadReviews() {

    const list = $("review-list");

    try {

        const data = await fetchJSON(API.reviews);

        const reviews = Array.isArray(data)
            ? data
            : data.reviews || data.pending_reviews || [];

        setText(
            "pending-review-count",
            reviews.length
        );

        if (!list) return;

        list.replaceChildren();

        if (!reviews.length) {

            const empty = document.createElement("p");

            empty.textContent = "No pending reviews.";

            list.appendChild(empty);

            return;
        }

        reviews.forEach(review => {

            const item = document.createElement("div");

            item.className = "review-item";

            const prompt = document.createElement("p");

            prompt.textContent =
                review.prompt || "Prompt unavailable";

            const date = document.createElement("small");

            date.textContent = formatTime(review.timestamp);

            const approve = document.createElement("button");

            approve.textContent = "Approve";

            approve.addEventListener("click", () => {
                updateReview(
                    review.id,
                    "APPROVED"
                );
            });

            const reject = document.createElement("button");

            reject.textContent = "Reject";

            reject.addEventListener("click", () => {
                updateReview(
                    review.id,
                    "REJECTED"
                );
            });

            item.append(
                prompt,
                date,
                approve,
                reject
            );

            list.appendChild(item);
        });

    } catch (error) {

        console.error("Review queue loading failed:", error);

        setText(
            "pending-review-count",
            "Unavailable"
        );

        if (list) {
            list.textContent = "Unable to load the review queue.";
        }
    }
}


// ==========================================================
// 15. UPDATE REVIEW STATUS
// ==========================================================

async function updateReview(reviewId, status) {

    if (!reviewId) {
        alert("Review ID is missing.");
        return;
    }

    try {

        await fetchJSON(
            `${API.reviews}/${encodeURIComponent(reviewId)}`,
            {
                method: "POST",
                body: JSON.stringify({ status })
            }
        );

        await loadReviews();
        await loadMetrics();

    } catch (error) {

        alert(
            `Unable to update review: ${error.message}`
        );
    }
}


// ==========================================================
// 16. MODEL HEALTH
// ==========================================================

async function loadHealth() {

    try {

        const health = await fetchJSON(API.health);

        const model =
            health.model ||
            health.model_name;

        if (model) {
            setText("model-name", model);
        }

    } catch (error) {

        console.error("Health check failed:", error);
    }
}


// ==========================================================
// 17. DASHBOARD REFRESH
// ==========================================================

async function refreshDashboard() {

    await Promise.all([
        loadMetrics(),
        loadReviews(),
        loadHealth()
    ]);
}


// ==========================================================
// 18. PROMPT TESTING EVENTS
// ==========================================================

function initializePromptTesting() {

    const button = $("send-button");
    const promptInput = $("prompt-input");

    if (button) {
        button.addEventListener(
            "click",
            submitPrompt
        );
    }

    if (promptInput) {

        promptInput.addEventListener("keydown", event => {

            if (
                event.key === "Enter" &&
                !event.shiftKey
            ) {
                event.preventDefault();
                submitPrompt();
            }
        });
    }
}


// ==========================================================
// 19. WINDOW RESIZE
// ==========================================================

window.addEventListener("resize", () => {

    clearTimeout(resizeTimeout);

    resizeTimeout = setTimeout(() => {

        if (latestMetrics) {
            drawCharts(latestMetrics);
        }

    }, 150);
});


// ==========================================================
// 20. APPLICATION INITIALIZATION
// ==========================================================

document.addEventListener("DOMContentLoaded", () => {

    initializeNavigation();

    initializeCharacterCount();

    initializePromptTesting();

    refreshDashboard();

});

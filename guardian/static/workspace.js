"use strict";
const viewNames = {overview: "Overview", pipeline: "Live pipeline", dependencies: "Dependencies", findings: "Findings and evidence", remediation: "Remediation", reports: "Reports and settings"};
const stageNames = {discover: "Discover", detect: "Detect", analyze: "Analyze", remediate: "Remediate", validate: "Validate"};
let workspaceScan = null, workspaceGeneration = 0, workspacePipeline = null, reportGeneration = 0;
let workspaceTimer = null, currentView = "overview", stageSignature = "";
let workspaceSummary = null, selectedPipelineStage = null;

function refreshPipelineStatus() {
  if (!workspacePipeline) return;
  const text = guardianPipelineState.headline(workspacePipeline, workspaceSummary);
  $("pipeline-status").textContent = text;
  showStatus(text);
}

function renderStageDetails(state) {
  const key = selectedPipelineStage || guardianPipelineState.activeStage(state) ||
    (state?.modules?.validate && state.modules.validate.status !== "not_started" ? "validate" : "discover");
  const module = state?.modules?.[key];
  for (const id of ["pipeline-stage-detail", "remediation-stage-detail"]) {
    const panel = $(id); panel.replaceChildren();
    panel.hidden = id === "remediation-stage-detail" && !selectedPipelineStage;
    addText(panel, "h3", `${stageNames[key]} · ${guardianPipelineState.stageLabel(state, key, workspaceSummary)}`);
    if (module?.status === "running") addText(panel, "p", state.stage, "hint");
    else if (!module || module.status === "not_started") addText(panel, "p", "This stage has not started. Its results will appear here.", "hint");
    else {
      for (const line of guardianPipelineState.resultLines(key, workspaceSummary)) addText(panel, "p", line, "hint");
      const routes = {discover: "dependencies", detect: "findings", analyze: "findings", remediate: "remediation", validate: "reports"};
      const link = addText(panel, "a", `Open ${viewNames[routes[key]]} →`); link.href = "#" + routes[key];
    }
  }
}

function navigateView(name, updateHash = true) {
  const previousView = currentView;
  currentView = Object.hasOwn(viewNames, name) ? name : "overview";
  document.querySelectorAll("[data-view]").forEach(section => section.hidden = section.dataset.view !== currentView);
  document.querySelectorAll("[data-route]").forEach(link => {
    if (link.dataset.route === currentView) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
    link.setAttribute("aria-label", viewNames[link.dataset.route]);
  });
  $("view-label").textContent = viewNames[currentView];
  document.title = `${viewNames[currentView]} · Guardian`;
  if (updateHash && location.hash !== "#" + currentView) history.pushState(null, "", `${location.pathname}${location.search}#${currentView}`);
  if (currentView === "dependencies" && graph) drawGraph();
  if (currentView === "reports") refreshReport().catch(error => $("report-status").textContent = error.message);
  if (previousView !== currentView) window.scrollTo(0, 0);
}
window.addEventListener("hashchange", () => navigateView(location.hash.slice(1), false));
window.addEventListener("popstate", () => {
  const scan = new URLSearchParams(location.search).get("scan");
  if (scan && scan !== workspaceScan) selectWorkspaceScan(scan, location.hash.slice(1), false);
  else if (!scan && workspaceScan) {
    clearTimeout(workspaceTimer); workspaceGeneration++; reportGeneration++; workspaceScan = null; resetWorkspace();
    drawPipeline(null); $("pipeline-status").textContent = "Choose a scan or start a pipeline.";
    showStatus("Ready for a repository."); navigateView(location.hash.slice(1), false);
  }
  else navigateView(location.hash.slice(1), false);
});
document.querySelectorAll("[data-route]").forEach(link => link.addEventListener("click", event => {
  event.preventDefault(); navigateView(link.dataset.route);
}));

function statusTag(parent, value) {
  const tag = addText(parent, "span", displayStatus(value), "status-tag"); tag.dataset.state = value; return tag;
}
function resetWorkspace() {
  scanGeneration++; detectionGeneration++; analysisGeneration++;
  window.guardianRemediation.reset();
  window.guardianRepositoryValidation?.reset();
  graph = null; currentScanId = currentReport = detectionReport = analysisData = analysisReachability = null;
  document.querySelectorAll("[data-needs-scan]").forEach(node => node.hidden = true);
  document.querySelectorAll("[data-empty-scan]").forEach(node => node.hidden = false);
  $("results").hidden = true;
  $("overview-components").textContent = $("overview-advisories").textContent = "—";
  $("overview-verification").textContent = "Not run";
  $("pipeline-events").replaceChildren();
  $("pipeline-status").textContent = "Loading pipeline…";
  $("pipeline-cancel").disabled = $("pipeline-resume").disabled = true;
  $("report-artifacts").replaceChildren(); $("report-outcome").replaceChildren();
  $("analysis-exports").hidden = true;
  for (const link of document.querySelectorAll(".exports a")) {link.removeAttribute("href"); link.setAttribute("aria-disabled", "true");}
  stageSignature = ""; workspacePipeline = null; workspaceSummary = null; selectedPipelineStage = null;
}
async function selectWorkspaceScan(scan, view = currentView, updateUrl = true) {
  if (!/^[0-9a-f]{32}$/.test(scan)) throw new Error("Invalid scan ID");
  clearTimeout(workspaceTimer);
  const generation = ++workspaceGeneration;
  reportGeneration++;
  workspaceScan = scan;
  resetWorkspace();
  if (updateUrl) history.pushState(null, "", `?scan=${scan}#${view || "overview"}`);
  navigateView(view, false);
  followWorkspacePipeline(generation).catch(error => {if (generation === workspaceGeneration) $("pipeline-status").textContent = error.message;});
  try {
    await followScan(scan);
    if (generation !== workspaceGeneration) return;
    await refreshReport();
  } catch (error) {if (generation === workspaceGeneration) showStatus(error.message);}
  refreshHistory().catch(error => $("history-status").textContent = error.message);
}

async function refreshHistory() {
  const data = await getJSON("/api/scans");
  $("scan-history").replaceChildren();
  for (const row of data.scans) {
    const tr = document.createElement("tr");
    const repository = addText(tr, "td", row.repo_url);
    if (row.controlled_fixture || row.repo_url.startsWith("fixture://")) addText(repository, "span", "CONTROLLED FIXTURE", "controlled-label");
    addText(tr, "td", row.commit ? row.commit.slice(0, 8) : "Not recorded");
    const state = addText(tr, "td", ""); statusTag(state, row.status);
    addText(tr, "td", row.updated_at ? new Date(row.updated_at).toLocaleString() : new Date(row.modified * 1000).toLocaleString());
    const action = addText(tr, "td", ""); const button = addText(action, "button", "Open scan →", "quiet"); button.type = "button";
    button.addEventListener("click", () => selectWorkspaceScan(row.scan_id, "overview").catch(error => showStatus(error.message)));
    $("scan-history").append(tr);
  }
  $("history-status").textContent = data.scans.length ? `${data.scans.length} local scans. Workflow status is separate from security verification.` : "No scans yet. Start with a public repository or the controlled demo.";
}

function drawPipeline(state) {
  const applied = workspaceSummary?.repository_validation;
  if (!state && applied?.applied && applied.after_scan_id === workspaceScan) {
    state = {status: "completed", modules: {discover: {status: "completed"},
      detect: {status: applied.checks.advisory_coverage === "passed" ? "completed" : "incomplete"},
      analyze: {status: "not_run"}, remediate: {status: "completed"}, validate: {status: applied.status}}};
  }
  const focused = document.activeElement?.closest(".stage-select");
  const focusedRail = focused?.closest("ol")?.id, focusedStage = focused?.closest("li")?.dataset.stage;
  const active = guardianPipelineState.activeStage(state);
  for (const id of ["pipeline-stages", "remediation-flow"]) {
    $(id).replaceChildren();
    for (const [key, title] of Object.entries(stageNames)) {
      const module = state?.modules?.[key] || {status: "not_started", attempts: 0};
      const li = document.createElement("li"); li.dataset.state = module.status;
      li.dataset.stage = key;
      li.dataset.active = String(key === active);
      if (key === active) li.setAttribute("aria-current", "step");
      const button = addText(li, "button", "", "stage-select"); button.type = "button";
      button.setAttribute("aria-label", `${title}: ${guardianPipelineState.stageLabel(state, key, workspaceSummary)}. Show stage results`);
      button.setAttribute("aria-pressed", String(key === (selectedPipelineStage || active)));
      addText(button, "span", "", "stage-dot"); addText(button, "strong", title);
      addText(button, "span", guardianPipelineState.stageLabel(state, key, workspaceSummary), "stage-label");
      if (module.attempts) addText(button, "span", `Attempt ${module.attempts}`, "stage-attempt");
      if (module.error) addText(li, "p", module.error, "hint");
      button.addEventListener("click", () => {selectedPipelineStage = key; drawPipeline(workspacePipeline);});
      $(id).append(li);
    }
  }
  renderStageDetails(state);
  if (focusedRail && focusedStage) $(focusedRail).querySelector(`[data-stage="${focusedStage}"] .stage-select`)?.focus({preventScroll: true});
  $("pipeline-events").replaceChildren();
  const events = state?.events || [];
  if (!events.length) addText($("pipeline-events"), "li", state ? "Waiting for first module event." : "This scan used individual module controls. Start a pipeline for checkpoint activity.");
  for (const event of events.slice(-60).reverse()) {
    const li = document.createElement("li"); addText(li, "time", new Date(event.at).toLocaleString());
    addText(li, "p", `${event.module ? stageNames[event.module] + " · " : ""}${event.event.replaceAll("_", " ")}${event.status ? " · " + displayStatus(event.status) : ""}`);
    if (event.error) addText(li, "p", event.error, "hint");
    $("pipeline-events").append(li);
  }
  $("pipeline-cancel").disabled = !state || !["queued", "running"].includes(state.status);
  $("pipeline-resume").disabled = !state || !["failed", "interrupted", "cancelled", "blocked", "awaiting_approval"].includes(state.status);
}
async function followWorkspacePipeline(generation) {
  if (!workspaceScan || generation !== workspaceGeneration) return;
  const scan = workspaceScan;
  const response = await fetch(`/api/scans/${scan}/pipeline`);
  if (generation !== workspaceGeneration) return;
  if (response.status === 404) {
    workspacePipeline = null; drawPipeline(null); $("pipeline-status").textContent = "Individual-module scan. Full pipeline activity is unavailable."; return;
  }
  if (!response.ok) throw new Error("Pipeline state unavailable");
  const state = await response.json();
  if (generation !== workspaceGeneration) return;
  const previousStatus = workspacePipeline?.status;
  workspacePipeline = state;
  drawPipeline(state);
  refreshPipelineStatus();
  if (currentView === "pipeline" && (!previousStatus || ["queued", "running"].includes(previousStatus)) &&
      ["awaiting_approval", "completed"].includes(state.status)) navigateView("remediation");
  document.querySelectorAll("#run-detection,#run-analysis,#prepare-fixes,#validate-fixes").forEach(button => {
    if (["queued", "running", "cancelling"].includes(state.status)) button.disabled = true;
  });
  const signature = JSON.stringify(state.modules);
  if (signature !== stageSignature) {
    stageSignature = signature;
    if (currentScanId === scan && ["completed", "partial"].includes(state.modules.detect.status) && !detectionReport) {
      const detection = await getJSON(`/api/scans/${scan}/detection`);
      if (generation !== workspaceGeneration) return;
      if (detection.report) renderDetection(detection.report);
    }
    if (currentScanId === scan && analysisData && ["completed", "partial"].includes(state.modules.remediate.status)) window.guardianRemediation.load(scan);
    await refreshReport();
    if (generation !== workspaceGeneration) return;
  }
  if (["queued", "running", "cancelling"].includes(state.status)) workspaceTimer = setTimeout(() => followWorkspacePipeline(generation).catch(error => {
    if (generation === workspaceGeneration) $("pipeline-status").textContent = error.message + ". Use Refresh report to retry.";
  }), 1200);
  else {
    if (currentScanId === scan) {
      const detection = await getJSON(`/api/scans/${scan}/detection`);
      if (generation !== workspaceGeneration) return;
      if (detection.report) renderDetection(detection.report);
    }
    refreshHistory().catch(error => $("history-status").textContent = error.message);
  }
}

const artifactTitles = {"sbom": "Original Syft SBOM", "graph": "Dependency graph", "components": "Component inventory", "report": "Discovery report", "detection-report": "Detection report", "evidence": "Detection evidence", "analysis-report": "Analysis & priorities", "ai-notes": "Analysis AI notes", "remediation-report": "Fix plan & notes", "validation-report": "Validation results", "verified-report": "Evidence & audit report", "remediation-evidence": "Candidate evidence"};
async function refreshReport() {
  const scan = workspaceScan, generation = ++reportGeneration;
  if (!scan) {$("report-status").textContent = "Choose a scan to inspect its report."; return;}
  const report = await getJSON(`/api/scans/${scan}/summary`);
  if (generation !== reportGeneration || scan !== workspaceScan) return;
  workspaceSummary = report;
  refreshPipelineStatus(); drawPipeline(workspacePipeline);
  $("overview-components").textContent = report.statistics?.component_count ?? "—";
  $("overview-advisories").textContent = report.advisories ?? "—";
  const applied = report.repository_validation?.after_scan_id === scan ? report.repository_validation : null;
  const verification = applied?.status || report.validation?.status || "not_run";
  $("overview-verification").textContent = displayStatus(verification);
  $("report-status").textContent = report.controlled_fixture ? "Controlled demo fixture · live source intelligence · review decisions required." : "Original evidence and derived validation results are separate artifacts.";
  $("report-outcome").replaceChildren();
  statusTag($("report-outcome"), verification);
  addText($("report-outcome"), "p", applied ? `Local checkout updated. Rescanned vulnerability findings: ${applied.remaining_vulnerabilities}. Build/test results are listed in Remediation.` : verification === "passed" ? "Required verification checks passed for the reported independent proposals." : "Verification is scoped. Missing checks, remaining review signals, or unreviewed patches prevent a complete pass.");
  for (const [title, value] of [["Source coverage", report.coverage || "unknown"], ["Source policy", report.policy || "not_run"], ["Original SBOM", report.sbom || "not_run"], ["Evidence records", report.evidence_count ?? "—"]]) {
    addText($("report-outcome"), "p", `${title}: ${displayStatus(value)}`, "hint");
  }
  if (report.repository?.commit) addText($("report-outcome"), "p", `Base commit: ${report.repository.commit}`, "hint");
  for (const result of report.validation?.results || []) {
    addText($("report-outcome"), "p", `Dependency verification: ${result.dependency_verification || "not_run"}. Build/tests: ${result.tests?.status || "not_run"}.`);
    if (result.finding_diff) addText($("report-outcome"), "p", `Findings resolved ${result.finding_diff.resolved.length} · remaining ${result.finding_diff.remaining.length} · introduced ${result.finding_diff.introduced.length}`);
  }
  $("report-artifacts").replaceChildren();
  for (const artifact of report.available_artifacts) {
    if (!artifactTitles[artifact]) continue;
    const link = addText($("report-artifacts"), "a", artifactTitles[artifact]); link.href = `/api/scans/${scan}/${artifact}`; link.download = "";
  }
  const usage = document.createElement("div"); usage.className = "usage-values";
  const analysis = report.analysis_ai?.usage || {}, remediation = report.remediation_ai?.usage || {};
  const tasks = [...(report.analysis_ai?.tasks || []), ...(report.remediation_ai?.task ? [report.remediation_ai.task] : [])];
  for (const [number, label] of [[(analysis.requests || 0) + (remediation.requests || 0), "requests in saved tasks"], [(analysis.cache_hits || 0) + (remediation.cache_hits || 0), "cache hits"], [(analysis.fallbacks || 0) + (remediation.fallbacks || 0), "template fallbacks"]]) {
    const metric = addText(usage, "div", ""); addText(metric, "strong", String(number)); addText(metric, "span", label);
  }
  const existingUsage = $("gateway-summary").querySelector(".usage-values"); if (existingUsage) existingUsage.remove();
  $("gateway-summary").append(usage);
  const existingTaskNote = $("gateway-summary").querySelector(".task-provenance"); if (existingTaskNote) existingTaskNote.remove();
  addText($("gateway-summary"), "p", tasks.map(task => `${task.task}: ${task.provider}${task.cache_hit ? " (cached)" : ""}`).join(" · ") || "No AI task has run for this scan.", "hint task-provenance");
  for (const link of document.querySelectorAll(".exports a[href]")) link.removeAttribute("aria-disabled");
}
async function loadGatewayStatus() {
  const state = await getJSON("/api/ai/status");
  $("gateway-summary").replaceChildren();
  addText($("gateway-summary"), "p", `Preferred model: ${state.model || state.primary_model || "Not configured"}`, "hint");
  addText($("gateway-summary"), "p", `Daily requests: ${state.daily_requests} / ${state.daily_limit}. Generation access remains unchecked.`, "hint");
  $("gateway-slots").replaceChildren();
  for (const slot of state.slots) {
    const card = addText($("gateway-slots"), "div", "", "key-slot"); addText(card, "strong", `Gemini key ${slot.slot}`);
    addText(card, "span", `${slot.configured ? "Configured" : "Not configured"}${slot.cooldown_seconds ? " · cooling down" : ""}`);
  }
  await refreshReport();
}

window.addEventListener("guardian:scan", event => {
  if (event.detail.scanId !== workspaceScan) return;
  window.guardianRepositoryValidation?.load(workspaceScan);
  document.querySelectorAll("[data-needs-scan]").forEach(node => node.hidden = false);
  document.querySelectorAll("[data-empty-scan]").forEach(node => node.hidden = true);
  for (const link of document.querySelectorAll(".exports a[href]")) link.removeAttribute("aria-disabled");
  if (currentView === "dependencies") drawGraph();
  refreshReport().catch(error => $("report-status").textContent = error.message);
});
window.addEventListener("guardian:findings", () => refreshReport().catch(error => $("report-status").textContent = error.message));
window.addEventListener("guardian:review", () => refreshReport().catch(error => $("report-status").textContent = error.message));
$("refresh-history").addEventListener("click", () => refreshHistory().catch(error => $("history-status").textContent = error.message));
$("refresh-report").addEventListener("click", () => {
  loadGatewayStatus().catch(error => $("report-status").textContent = error.message);
  followWorkspacePipeline(workspaceGeneration).catch(error => $("pipeline-status").textContent = error.message);
});
$("start-demo").addEventListener("click", async () => {
  $("start-demo").disabled = true;
  try {const state = await getJSON("/api/demo", {method:"POST"}); await selectWorkspaceScan(state.scan_id, "pipeline");}
  catch (error) {showStatus(error.message);}
  finally {$("start-demo").disabled = false;}
});
for (const [id, action] of [["pipeline-cancel", "cancel"], ["pipeline-resume", "resume"]]) $(id).addEventListener("click", async () => {
  const scan = workspaceScan, generation = workspaceGeneration; $(id).disabled = true;
  try {
    await getJSON(`/api/scans/${scan}/${action}`, {method:"POST", headers: {"Content-Type": "application/json"}, ...(action === "resume" ? {body: JSON.stringify({run_tests: $("validation-tests").checked})} : {})});
    if (generation !== workspaceGeneration) return;
    clearTimeout(workspaceTimer); await followWorkspacePipeline(generation);
  } catch (error) {if (generation === workspaceGeneration) $("pipeline-status").textContent = error.message;}
});
window.guardianShell = {select: selectWorkspaceScan, navigate: navigateView, pipeline: () => workspacePipeline, refreshStatus: refreshPipelineStatus,
  busy: () => ["queued", "running", "cancelling"].includes(workspacePipeline?.status)};
navigateView(location.hash.slice(1), false); drawPipeline(null);
refreshHistory().catch(error => $("history-status").textContent = error.message);
loadGatewayStatus().catch(error => $("gateway-summary").textContent = error.message);
const initialScan = new URLSearchParams(location.search).get("scan");
if (initialScan) selectWorkspaceScan(initialScan, location.hash.slice(1) || "overview", false).catch(error => showStatus(error.message));

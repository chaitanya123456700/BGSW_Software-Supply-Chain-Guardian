"use strict";
let detectionScan = null, detectionReport = null, detectionNodes = new Map(), detectionWholeGraph = null;
let detectionPolling = false, detectionGeneration = 0;

function detectionView(which) {
  window.guardianShell?.navigate(which === "discovery" ? "dependencies" : "findings");
}
$("tab-discovery").addEventListener("click", () => detectionView("discovery"));
$("tab-detection").addEventListener("click", () => detectionView("detection"));

function nodeLabel(id) {
  const node = detectionNodes.get(id);
  return node ? `${node.name}@${node.resolved_version || node.version || "unknown"} (${node.path})` : id;
}
function addText(parent, tag, text, className) {
  const item = document.createElement(tag); item.textContent = text;
  if (className) item.className = className;
  parent.append(item); return item;
}
function advisorySeverity(finding) {
  const values = (finding.source_metadata || []).map(source => source.database_specific?.severity).filter(value => typeof value === "string");
  return [...new Set(values)].join(", ") || "not supplied as a severity label; inspect source vectors";
}
function findingKind(finding) {
  if (finding.advisory_category === "malicious_package") return "Malicious-package advisory (MAL)";
  return {vulnerability: "Vulnerability advisory", install_script: "Installation script", typosquat: "Name similarity", policy_violation: "Policy violation"}[finding.finding_type] || "Change / review signal";
}
function showFinding(finding) {
  document.querySelectorAll(".finding-row").forEach(row => row.setAttribute("aria-pressed", String(row.dataset.findingId === finding.finding_id)));
  $("finding-hint").hidden = true;
  $("finding-detail").replaceChildren(); $("finding-evidence-links").replaceChildren();
  $("evidence-detail").hidden = true;
  addText($("finding-detail"), "h3", finding.title);
  addText($("finding-detail"), "p", findingKind(finding), "finding-kind");
  addText($("finding-detail"), "p", finding.explanation);
  addText($("finding-detail"), "p", `${finding.verification_status} · ${finding.classification} · Applicability: ${finding.version_applicability}`, "finding-meta");
  if (typeof finding.confidence === "number") addText($("finding-detail"), "p", `Heuristic confidence: ${Math.round(finding.confidence * 100)}%. Review ranking only; not malware probability.`);
  if (finding.finding_type === "vulnerability") {
    addText($("finding-detail"), "p", `Source severity: ${advisorySeverity(finding)}`);
    addText($("finding-detail"), "p", `Aliases: ${finding.aliases.join(", ") || "none supplied"}`);
    const packages = new Set(finding.component_instance_ids.map(id => detectionNodes.get(id)?.name));
    const fixes = (finding.source_metadata || []).flatMap(source => (source.affected || []).filter(item => item.package?.ecosystem === "npm" && packages.has(item.package?.name)).flatMap(item => (item.ranges || []).flatMap(range => (range.events || []).filter(event => typeof event.fixed === "string").map(event => event.fixed))));
    addText($("finding-detail"), "p", `Advisory fixed versions: ${[...new Set(fixes)].join(", ") || "not supplied"}. Review actual fixes and validation in Remediation.`);
  }
  for (const id of finding.component_instance_ids) {
    addText($("finding-detail"), "p", nodeLabel(id));
    const button = addText($("finding-detail"), "button", "Show exact instance in graph"); button.type = "button";
    button.addEventListener("click", () => {
      graph = detectionWholeGraph; $("project-select").value = "";
      $("classification").value = "all"; $("search").value = detectionNodes.get(id)?.name || "";
      detectionView("discovery"); drawGraph();
      const node = graph.nodes.find(item => item.id === id);
      if (node) selectNode(node);
      for (const stat of document.querySelectorAll("#stats [data-stat]")) stat.querySelector("strong").textContent = graph.statistics[stat.dataset.stat] ?? "—";
      $("download-graph").href = `/api/scans/${detectionScan}/graph`;
      $("coverage").textContent = `Whole repository: ${currentReport.dependency_status}. Coverage: ${currentReport.coverage_status}.`;
    });
  }
  if (!finding.component_instance_ids.length) addText($("finding-detail"), "p", "Source-level finding. Application/component ownership was not inferred.");
  for (const path of finding.dependency_paths) addText($("finding-detail"), "p", path.nodes.map(id => detectionNodes.get(id)?.name || id).join(" → "), "path-witness");
  for (const warning of finding.graph_coverage_warnings) addText($("finding-detail"), "p", warning, "uncertainty");
  for (const id of finding.advisory_ids) {
    const link = addText($("finding-detail"), "a", id); link.href = `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
    link.target = "_blank"; link.rel = "noopener noreferrer";
  }
  const source = addText($("finding-detail"), "details", "");
  addText(source, "summary", "Source metadata and detector observations");
  addText(source, "pre", JSON.stringify(finding.source_metadata, null, 2));
  addText($("finding-detail"), "p", `Package reachability: ${finding.reachability_status}. Priority: ${finding.priority_status}. Source consistency: ${finding.source_consistency}.`, "hint");
  if (typeof finding.risk_score === "number") {
    addText($("finding-detail"), "p", `Deterministic priority: ${finding.risk_score}/100 (${finding.priority_status}). Heuristic evidence confidence: ${Math.round(finding.risk_confidence * 100)}%. This is not a CVSS score or malware probability.`);
    const factors = addText($("finding-detail"), "details", "");
    addText(factors, "summary", "Inspect deterministic score factors");
    addText(factors, "pre", JSON.stringify(finding.score_factors, null, 2));
  }
  if (window.guardianAnalysis) window.guardianAnalysis.decorate(finding);
  addText($("finding-evidence-links"), "h3", "Inspect original evidence");
  for (const id of finding.evidence_ids) {
    const button = addText($("finding-evidence-links"), "button", id); button.type = "button";
    button.addEventListener("click", async () => {
      try {
        const evidence = await getJSON(`/api/scans/${detectionScan}/evidence/${encodeURIComponent(id)}`);
        $("evidence-detail").hidden = false;
        const raw = JSON.stringify(evidence, null, 2);
        $("evidence-detail").textContent = raw.length > 60000 ? raw.slice(0, 60000) + "\n[Preview truncated; use evidence JSON endpoint for full data.]" : raw;
      } catch (error) { $("detection-status").textContent = error.message; }
    });
  }
}

function renderFindingList() {
  $("finding-list").replaceChildren();
  const search = $("finding-search").value.trim().toLowerCase();
  const type = $("finding-type").value, verification = $("finding-verification").value;
  const findings = (detectionReport?.findings || []).filter(finding =>
    (type === "all" || (type === "malicious_package" ? finding.advisory_category === "malicious_package" :
      finding.finding_type === type && (type !== "vulnerability" || finding.advisory_category !== "malicious_package"))) && (verification === "all" || finding.verification_status === verification) &&
    (!search || `${finding.title} ${finding.advisory_ids.join(" ")} ${finding.aliases.join(" ")} ${finding.rule_id || ""} ${finding.component_instance_ids.map(nodeLabel).join(" ")}`.toLowerCase().includes(search)));
  $("finding-count").textContent = `${findings.length} matching findings${findings.length > 200 ? "; first 200 shown. Narrow your search or export JSON." : ""}`;
  if (!findings.length) {
    const scope = detectionReport?.vulnerabilities;
    addText($("finding-list"), "p", !detectionReport ? "Run detection to inspect known advisories and review signals." :
      scope?.no_match_statement && !((detectionReport.review_signals ?? detectionReport.change_signals) > 0) ? scope.no_match_statement + ". This is scoped to queried exact versions." :
      "No matching findings in this view. Check coverage and errors before concluding that nothing was detected.", "empty-findings");
  }
  for (const finding of findings.slice(0, 200)) {
    const button = document.createElement("button"); button.type = "button"; button.className = "finding-row";
    button.dataset.findingId = finding.finding_id;
    button.setAttribute("aria-pressed", "false");
    addText(button, "span", findingKind(finding), "finding-kind");
    addText(button, "strong", finding.title);
    addText(button, "span", finding.component_instance_ids.map(nodeLabel).join("; ") || finding.source_metadata?.[0]?.file || "Source-level observation", "finding-meta");
    addText(button, "span", `${finding.advisory_ids.join(", ") || finding.rule_id} · ${finding.verification_status}`, "finding-state");
    if (finding.finding_type === "vulnerability") addText(button, "span", `Source severity: ${advisorySeverity(finding)}`, "finding-meta");
    if (typeof finding.confidence === "number") addText(button, "span", `Review confidence: ${Math.round(finding.confidence * 100)}%`, "finding-meta");
    if (typeof finding.risk_score === "number") addText(button, "span", `Priority ${finding.risk_score}/100 · ${finding.priority_status} · ${finding.reachability_status}`, "finding-state");
    button.addEventListener("click", () => showFinding(finding)); $("finding-list").append(button);
  }
}

function renderDetection(report) {
  detectionReport = report;
  $("finding-detail").replaceChildren(); $("finding-evidence-links").replaceChildren(); $("finding-hint").hidden = false; $("evidence-detail").hidden = true;
  $("detection-metrics").replaceChildren();
  const metrics = [["Verified vulnerability matches", report.verified_vulnerabilities ?? "Unknown"], ["Verified malicious-package matches", report.verified_malicious_packages ?? 0], ["Change / review signals", report.review_signals ?? report.change_signals ?? "Unknown"], ["Policy violations", report.policy_violations ?? 0], ["Evidence records", report.evidence_count ?? 0]];
  for (const [label, value] of metrics) { const stat = addText($("detection-metrics"), "div", "", "stat"); addText(stat, "strong", String(value)); addText(stat, "span", label); }
  const vulnerability = report.vulnerabilities || {};
  $("detection-coverage").textContent = `Overall coverage: ${report.coverage_status || "unknown"}. Advisory checks: ${vulnerability.status || "unknown"}; ${vulnerability.completed_package_versions ?? 0}/${vulnerability.queried_package_versions ?? 0} exact package/version queries completed. Policy: ${report.policy_status || "not_run"}. ${report.suspicious_changes?.comparison_status || "comparison_unavailable"}. Code reachability and priority are not assessed.`;
  const warnings = [...(report.errors || []), ...(report.warnings || [])];
  $("detection-errors").hidden = !warnings.length; $("detection-error-list").replaceChildren();
  for (const warning of warnings) addText($("detection-error-list"), "li", warning);
  $("source-inspections").textContent = JSON.stringify({changes: report.suspicious_changes?.inspections || [], static_signals: report.static_signals || {status: "not_run"}}, null, 2);
  $("deliver-risks").textContent = `${(report.verified_vulnerabilities ?? 0) + (report.verified_malicious_packages ?? 0)} verified advisories · ${report.review_signals ?? report.change_signals ?? "Unknown"} review signals`;
  $("deliver-evidence").textContent = `${report.evidence_count ?? 0} source records · ${report.status}`;
  for (const [id, route] of [["download-vulnerabilities", "vulnerabilities"], ["download-changes", "suspicious-changes"], ["download-detection", "detection-report"], ["download-evidence", "evidence"], ["download-static-signals", "static-signals"]]) {
    $(id).href = `/api/scans/${detectionScan}/${route}`; $(id).download = "";
    if (id === "download-static-signals") $(id).hidden = !report.static_signals;
  }
  renderFindingList();
  const vulnerable = new Set(report.findings.filter(f => f.finding_type === "vulnerability").flatMap(f => f.component_instance_ids));
  document.querySelectorAll(".node").forEach(node => node.classList.toggle("vulnerable", vulnerable.has(node.dataset.id)));
  window.dispatchEvent(new CustomEvent("guardian:findings"));
  if (window.guardianAnalysis) window.guardianAnalysis.load(detectionScan, report);
}

async function followDetection(generation) {
  detectionPolling = true; $("run-detection").disabled = true;
  try {
    while (generation === detectionGeneration) {
      const state = await getJSON(`/api/scans/${detectionScan}/detection`);
      if (generation !== detectionGeneration) break;
      $("detection-status").textContent = `${state.status}: ${state.stage || ""}${state.error ? ". " + state.error : ""}`;
      if (!["queued", "running"].includes(state.status)) {
        if (state.report) renderDetection(state.report);
        else renderFindingList();
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  } catch (error) { $("detection-status").textContent = error.message; }
  finally { if (generation === detectionGeneration) {detectionPolling = false; $("run-detection").disabled = window.guardianShell?.busy() || !currentReport?.statistics;} }
}
$("run-detection").addEventListener("click", async () => {
  $("run-detection").disabled = true;
  try {
    const baseline = $("baseline").value.trim();
    if (baseline && !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(baseline)) throw new Error("Use a full 40- or 64-character lowercase Git SHA.");
    await getJSON(`/api/scans/${detectionScan}/detect`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({baseline_commit: baseline || null})});
    await followDetection(detectionGeneration);
  } catch (error) { $("detection-status").textContent = error.message; }
  finally { $("run-detection").disabled = false; }
});
for (const id of ["finding-search", "finding-type", "finding-verification"]) $(id).addEventListener(id === "finding-search" ? "input" : "change", renderFindingList);
window.guardianDetection = {load(scan, phase1, dependencyGraph) {
  detectionScan = scan; detectionReport = null; detectionGeneration += 1; detectionWholeGraph = dependencyGraph;
  detectionNodes = new Map(dependencyGraph.nodes.map(node => [node.id, node]));
  $("deliver-components").textContent = `${phase1.statistics?.component_count ?? "Unknown"} observations · ${phase1.coverage_status || phase1.status}`;
  $("deliver-sbom").textContent = phase1.sbom?.status === "completed" ? "CycloneDX validated" : "Unavailable / incomplete";
  $("deliver-graph").textContent = `${phase1.statistics?.edge_count ?? "Unknown"} resolved edges · ${phase1.statistics?.unresolved_edges ?? "Unknown"} unresolved`;
  $("deliver-risks").textContent = "Detection not run"; $("deliver-evidence").textContent = "Phase 1 source evidence available";
  $("run-detection").disabled = !phase1.statistics;
  followDetection(detectionGeneration);
}};

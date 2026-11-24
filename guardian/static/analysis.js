"use strict";
let analysisData = null, analysisReachability = null, analysisGeneration = 0;

async function loadAnalysis(scanId, generation, poll = false) {
  do {
    const state = await getJSON(`/api/scans/${scanId}/analysis`);
    if (generation !== analysisGeneration) return;
    $("analysis-status").textContent = `${state.status}: ${state.stage || ""}`;
    const running = ["queued", "running"].includes(state.status);
    $("run-analysis").disabled = running || window.guardianShell?.busy() || !["completed", "partial"].includes(detectionReport?.status);
    if (state.report && ["completed", "partial"].includes(state.report.status)) {
      const reachability = await getJSON(`/api/scans/${scanId}/reachability`);
      if (generation !== analysisGeneration) return;
      analysisData = state.report;
      analysisReachability = reachability;
      detectionReport = {...detectionReport, findings: state.report.findings};
      const usage = state.report.ai?.usage || {};
      $("analysis-status").textContent = `${state.status}: ${state.report.findings.length} findings prioritized. AI requests: ${usage.requests || 0}; cache hits: ${usage.cache_hits || 0}; template fallbacks: ${usage.fallbacks || 0}.`;
      window.guardianRemediation?.load(scanId);
      $("analysis-scope-hint").textContent = "Package reachability and deterministic priority were analyzed. Function-level exploitability remains unknown. AI notes do not change findings or scores.";
      $("detection-coverage").textContent = $("detection-coverage").textContent.replace("Code reachability and priority are not assessed.", "Package reachability and deterministic priorities were analyzed; function-level exploitability remains unknown.");
      $("analysis-exports").hidden = false;
      for (const artifact of ["analysis-report", "risk-scores", "reachability", "ai-notes", "analysis-evidence"]) {
        $("download-" + artifact).href = `/api/scans/${scanId}/${artifact}`;
      }
      renderFindingList();
      return;
    }
    if (state.report?.errors?.length) $("analysis-status").textContent += ". " + state.report.errors.join("; ");
    if (!running || !poll) return;
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (generation === analysisGeneration);
}

$("run-analysis").addEventListener("click", async () => {
  $("run-analysis").disabled = true;
  const scanId = detectionScan, generation = ++analysisGeneration;
  analysisData = analysisReachability = null;
  window.guardianRemediation?.reset();
  $("analysis-exports").hidden = true;
  $("finding-detail").replaceChildren(); $("finding-evidence-links").replaceChildren();
  try {
    await getJSON(`/api/scans/${scanId}/analyze`, {method: "POST"});
    await loadAnalysis(scanId, generation, true);
  } catch (error) { $("analysis-status").textContent = error.message; }
  finally { if (generation === analysisGeneration) $("run-analysis").disabled = false; }
});

$("ai-status-button").addEventListener("click", async () => {
  try { $("ai-settings-status").textContent = JSON.stringify(await getJSON("/api/ai/status"), null, 2); }
  catch (error) { $("ai-settings-status").textContent = error.message; }
});
$("ai-check-models").addEventListener("click", async () => {
  $("ai-check-models").disabled = true;
  $("ai-settings-status").textContent = "Checking configured model metadata within shared request limits. This does not test generation access.";
  try { $("ai-settings-status").textContent = JSON.stringify(await getJSON("/api/ai/check-models", {method: "POST"}), null, 2); }
  catch (error) { $("ai-settings-status").textContent = error.message; }
  finally { $("ai-check-models").disabled = false; }
});

window.guardianAnalysis = {
  load(scanId, report) {
    window.guardianRemediation?.reset();
    analysisData = analysisReachability = null;
    $("analysis-exports").hidden = true;
    $("analysis-scope-hint").textContent = "Run analysis to inspect package reachability, deterministic priority, and optional AI notes. Original advisory severity is preserved.";
    $("run-analysis").disabled = !["completed", "partial"].includes(report.status);
    const generation = ++analysisGeneration;
    loadAnalysis(scanId, generation, true).catch(error => { $("analysis-status").textContent = error.message; });
  },
  decorate(finding) {
    if (!analysisData) return;
    for (const task of analysisData.ai?.tasks || []) {
      const note = task.notes?.find(item => item.finding_id === finding.finding_id);
      if (!note) continue;
      const panel = addText($("finding-detail"), "section", "", "ai-note");
      addText(panel, "h3", task.provider === "template" ? "Deterministic fallback note" : "AI interpretation");
      addText(panel, "p", `${task.provider} · ${task.model || "no model"}${task.cache_hit ? " · cached" : ""}${task.fallback_reason ? " · " + task.fallback_reason : ""}`, "finding-meta");
      addText(panel, "p", note.summary);
      addText(panel, "p", note.limitations, "uncertainty");
    }
    for (const id of finding.component_instance_ids) {
      const reach = analysisReachability?.components?.[id];
      if (!reach) continue;
      addText($("finding-detail"), "p", `${nodeLabel(id)}: ${reach.status}. ${reach.reason}`);
      for (const witness of reach.witnesses || []) {
        addText($("finding-detail"), "p", `${witness.file}:${witness.line}${witness.inherited_from ? " · inherited possible dependency path" : " · package import observation"}`, "path-witness");
        for (const evidenceId of witness.evidence_ids || []) {
          const button = addText($("finding-detail"), "button", "Inspect import evidence"); button.type = "button";
          button.addEventListener("click", async () => {
            try {
              const evidence = await getJSON(`/api/scans/${detectionScan}/analysis-evidence/${encodeURIComponent(evidenceId)}`);
              $("evidence-detail").hidden = false;
              const preview = JSON.stringify(evidence, null, 2);
              $("evidence-detail").textContent = preview.length > 60000 ? preview.slice(0, 60000) + "\n[Preview truncated.]" : preview;
            } catch (error) { $("analysis-status").textContent = error.message; }
          });
        }
      }
    }
  }
};

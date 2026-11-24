"use strict";
let remediationGeneration = 0, remediationScan = null;

function remediationReset() {
  remediationGeneration++;
  remediationScan = null;
  $("prepare-fixes").disabled = $("validate-fixes").disabled = true;
  $("remediation-plans").replaceChildren();
  $("validation-summary").replaceChildren();
  $("remediation-exports").hidden = $("validation-results").hidden = true;
  $("remediation-status").textContent = "Fresh analysis is required.";
  $("validation-status").textContent = "Validation has not run.";
  $("fix-notes").textContent = "No remediation notes yet.";
  $("approval-guidance").textContent = "";
  $("download-validation-report").hidden = $("download-verified-report").hidden = true;
}

async function remediationRefresh(scan, generation, poll = false) {
  do {
    const state = await getJSON(`/api/scans/${scan}/remediation`);
    if (generation !== remediationGeneration) return;
    const running = ["queued", "running"].includes(state.status);
    $("prepare-fixes").disabled = running || window.guardianShell?.busy();
    $("remediation-status").textContent = `${state.status}: ${state.stage || ""}`;
    $("validate-fixes").disabled = true;
    $("remediation-plans").replaceChildren();
    if (state.report) {
      $("remediation-exports").hidden = false;
      $("download-remediation-report").href = `/api/scans/${scan}/remediation-report`;
      $("fix-notes").textContent = JSON.stringify({notes: state.report.ai, usage: state.report.ai_usage}, null, 2);
      const proposals = state.report.proposals || [];
      for (const proposal of proposals) renderProposal(scan, proposal, state.reviews?.[proposal.id], generation);
      const manual = (state.report.recommendations || []).filter(item => item.status === "manual_review");
      if (manual.length) {
        const details = document.createElement("details"); $("remediation-plans").append(details);
        addText(details, "summary", `${manual.length} manual review recommendation${manual.length === 1 ? "" : "s"}`);
        const groups = new Map();
        for (const recommendation of manual) {
          const key = JSON.stringify([recommendation.reason, recommendation.options]);
          if (!groups.has(key)) groups.set(key, []);
          groups.get(key).push(recommendation);
        }
        for (const group of groups.values()) {
          const item = addText(details, "section", "", "manual-review-group");
          addText(item, "strong", `${group.length} recommendation${group.length === 1 ? "" : "s"}`);
          addText(item, "p", group[0].reason);
          const names = [...new Set(group.map(recommendation => detectionNodes.get(recommendation.component_id)?.name || "Repository"))];
          addText(item, "p", `Includes: ${names.slice(0, 5).join(", ")}${names.length > 5 ? ` and ${names.length - 5} more` : ""}. Options: ${group[0].options.map(option => option.replaceAll("_", " ")).join(", ")}.`, "hint");
        }
      }
      $("validate-fixes").disabled = window.guardianShell?.busy() || !proposals.length || proposals.some(proposal => !state.reviews?.[proposal.id]);
      const reviewed = proposals.filter(proposal => state.reviews?.[proposal.id]).length;
      $("remediation-status").textContent += `. ${proposals.length} independent patch proposals · ${reviewed} reviewed · ${proposals.length - reviewed} pending.`;
      $("approval-guidance").textContent = !proposals.length ? "No automatic patch is available to approve. Open the manual review reasons below. To try the full approval flow, choose Overview → Run controlled demo."
        : proposals.length > reviewed ? "Your decision is needed. Review each exact diff, then approve, reject, or accept the existing risk. Nothing is applied to the original checkout."
        : "Every patch has a decision. Validate reviewed patches to rebuild only approved changes in temporary copies.";
    }
    if (!running || !poll) return;
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (generation === remediationGeneration);
}

function renderProposal(scan, proposal, review, generation) {
  const card = document.createElement("article"); card.className = "patch-card";
  $("remediation-plans").append(card);
  addText(card, "h3", `${proposal.name}: ${proposal.from_version} → ${proposal.to_version}`);
  const layout = addText(card, "div", "", "patch-review-layout");
  const diffPanel = addText(layout, "div", "");
  const inspector = addText(layout, "div", "", "patch-inspector");
  addText(inspector, "h3", "Review this patch");
  for (const [title, text] of [
    ["Constraint change", `${proposal.constraint_change_required ? "Outside original constraints. " : "Within original constraints. "}${proposal.major_change ? "Major version change. " : ""}`],
    ["Exact pin", `${proposal.name}: ${proposal.from_version} → ${proposal.to_version}. All direct declarations become exact pins.`],
    ["Candidate check", proposal.candidate_check], ["Rollback", proposal.rollback]]) {
    const fact = addText(inspector, "section", "", "patch-fact"); addText(fact, "strong", title); addText(fact, "p", text);
  }
  addText(inspector, "p", `${proposal.finding_ids.length} related findings · ${proposal.manifest_path} and ${proposal.lockfile_path}`, "hint");
  addText(inspector, "p", `Digest: ${proposal.digest}`, "hint");
  const details = document.createElement("details"); diffPanel.append(details); details.open = true;
  addText(details, "summary", "Inspect exact manifest and lockfile diff");
  const preview = addText(details, "div", "Loading exact diff…", "patch-diff-lines");
  let loaded = false;
  details.addEventListener("toggle", async () => {
    if (!details.open || loaded) return;
    try {
      const response = await fetch(`/api/scans/${scan}/remediation/${proposal.id}/diff`);
      if (!response.ok) throw new Error("Diff unavailable; prepare a fresh plan.");
      const value = await response.text();
      if (generation !== remediationGeneration) return;
      preview.replaceChildren();
      for (const line of value.split("\n")) {
        addText(preview, "span", line || " ", "diff-line" + (line.startsWith("---") || line.startsWith("+++") || line.startsWith("@@") ? " file-header" : line.startsWith("+") ? " added" : line.startsWith("-") ? " removed" : ""));
      }
      loaded = true;
    } catch (error) { preview.textContent = error.message; }
  });
  const download = addText(diffPanel, "a", "Download patch");
  download.href = `/api/scans/${scan}/remediation/${proposal.id}/diff`;
  if (review) { addText(inspector, "p", `Decision: ${review.decision}. ${review.reason || ""} ${review.at}`); return; }
  const label = document.createElement("label"), check = document.createElement("input");
  check.type = "checkbox"; label.append(check, " I reviewed this exact diff and approve a temporary rebuild."); inspector.append(label);
  const reasonLabel = addText(inspector, "label", "Review reason (required to accept risk)");
  const reason = document.createElement("textarea"); reason.maxLength = 2000; reasonLabel.append(reason);
  const buttons = [];
  for (const [decision, title] of [["approve", "Approve exact patch"], ["reject", "Reject patch"], ["accepted_risk", "Accept existing risk"]]) {
    const button = addText(inspector, "button", title, decision === "approve" ? "primary" : "secondary"); button.type = "button"; buttons.push(button);
    button.addEventListener("click", async () => {
      if (decision === "approve" && (!check.checked || !loaded)) {
        $("remediation-status").textContent = "Open and review the diff, then select the approval checkbox."; return;
      }
      if (decision === "accepted_risk" && !reason.value.trim()) {
        $("remediation-status").textContent = "Provide a reason before accepting risk."; return;
      }
      buttons.forEach(item => item.disabled = true);
      try {
        await getJSON(`/api/scans/${scan}/remediation/${proposal.id}/decision`, {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({digest: proposal.digest, decision, reviewed_diff: check.checked, reason: reason.value})});
        await remediationRefresh(scan, generation);
        window.dispatchEvent(new CustomEvent("guardian:review"));
      } catch (error) { $("remediation-status").textContent = error.message; buttons.forEach(item => item.disabled = false); }
    });
  }
}

async function validationRefresh(scan, generation, poll = false) {
  do {
    const state = await getJSON(`/api/scans/${scan}/validation`);
    if (generation !== remediationGeneration) return;
    const running = ["queued", "running"].includes(state.status);
    $("validation-status").textContent = `${state.status}: ${state.stage || ""}`;
    if (state.report) {
      $("validation-summary").replaceChildren();
      addText($("validation-summary"), "p", state.report.results?.some(result => result.decision === "approve")
        ? "Approved patches were checked independently. Original checkout was not changed."
        : "No approved patches were rebuilt. Original checkout was not changed.");
      for (const result of state.report.results || []) {
        const card = document.createElement("article"); card.className = "patch-card";
        $("validation-summary").append(card);
        addText(card, "h3", `Validation: ${result.status}`);
        addText(card, "p", `Decision: ${result.decision}. Dependency verification: ${result.dependency_verification || "not_run"}. Build/tests: ${result.tests?.status || "not_run"}.`);
        if (result.tests?.reason) addText(card, "p", result.tests.reason);
        if (result.finding_diff) addText(card, "p", `Findings resolved: ${result.finding_diff.resolved.length}; remaining: ${result.finding_diff.remaining.length}; introduced: ${result.finding_diff.introduced.length}.`);
        if (result.dependency_diff) addText(card, "p", `Removed: ${result.dependency_diff.removed.join(", ") || "none"}. Added: ${result.dependency_diff.added.join(", ") || "none"}.`);
        for (const error of result.errors || []) addText(card, "p", error);
        if (result.artifacts_directory) {
          const id = result.artifacts_directory.split("/").pop();
          for (const [artifact, title] of [["detection", "After-scan findings"], ["evidence", "After-scan evidence index"], ...(result.sbom_diff?.status === "completed" ? [["sbom", "After-scan SBOM"]] : [])]) {
            const link = addText(card, "a", title + " JSON ");
            link.href = `/api/scans/${scan}/validation/${id}/${artifact}`;
          }
        }
      }
      for (const error of state.report.errors || []) addText($("validation-summary"), "p", error);
      $("validation-results").hidden = false;
      $("validation-results").textContent = JSON.stringify(state.report, null, 2);
      for (const name of ["validation-report", "verified-report"]) {
        $("download-" + name).hidden = false;
        $("download-" + name).href = `/api/scans/${scan}/${name}`;
      }
    }
    if (!running || !poll) return;
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (generation === remediationGeneration);
}

$("prepare-fixes").addEventListener("click", async () => {
  const scan = remediationScan, generation = ++remediationGeneration;
  $("prepare-fixes").disabled = $("validate-fixes").disabled = true;
  $("remediation-plans").replaceChildren();
  $("validation-summary").replaceChildren();
  $("validation-results").hidden = $("remediation-exports").hidden = true;
  $("download-validation-report").hidden = $("download-verified-report").hidden = true;
  try { await getJSON(`/api/scans/${scan}/remediate`, {method: "POST"}); await remediationRefresh(scan, generation, true); }
  catch (error) { $("remediation-status").textContent = error.message; }
  finally { if (generation === remediationGeneration) $("prepare-fixes").disabled = false; }
});
$("validate-fixes").addEventListener("click", async () => {
  const scan = remediationScan, generation = remediationGeneration;
  $("validate-fixes").disabled = true;
  try {
    if (window.guardianShell?.pipeline()?.status === "awaiting_approval") {
      await getJSON(`/api/scans/${scan}/resume`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({run_tests: $("validation-tests").checked})});
      await window.guardianShell.select(scan, "pipeline");
      return;
    }
    await getJSON(`/api/scans/${scan}/validate`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({run_tests: $("validation-tests").checked})});
    await validationRefresh(scan, generation, true);
  } catch (error) { $("validation-status").textContent = error.message; }
  finally { if (generation === remediationGeneration) $("validate-fixes").disabled = false; }
});
window.guardianRemediation = {
  reset: remediationReset,
  load(scan) {
    remediationScan = scan; const generation = ++remediationGeneration;
    $("prepare-fixes").disabled = false;
    Promise.all([remediationRefresh(scan, generation, true), validationRefresh(scan, generation, true)])
      .catch(error => { if (generation === remediationGeneration) $("remediation-status").textContent = error.message; });
  }
};

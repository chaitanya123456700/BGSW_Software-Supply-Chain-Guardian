"use strict";
let remediationGeneration = 0, remediationScan = null;
let patchChoices = new Map(), activeProposal = null, reviewInFlight = false;

function remediationReset() {
  remediationGeneration++;
  remediationScan = null;
  patchChoices.clear(); activeProposal = null;
  window.guardianDraftPreview?.reset();
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
    $("remediation-status").textContent = `${displayStatus(state.status)} · ${state.stage || ""}`;
    $("validate-fixes").disabled = true;
    $("remediation-plans").replaceChildren();
    if (state.report) {
      $("remediation-exports").hidden = false;
      $("download-remediation-report").href = `/api/scans/${scan}/remediation-report`;
      $("fix-notes").textContent = JSON.stringify({notes: state.report.ai, usage: state.report.ai_usage}, null, 2);
      const proposals = state.report.proposals || [];
      if (proposals.length) {
        const validationReview = addText($("remediation-plans"), "details", "", "validation-review");
        addText(validationReview, "summary", "Optional: approve independent patches for validation");
        addText(validationReview, "p", "Exporting a working draft does not approve these independent rebuilds. Use these controls only when you also want validation.", "hint");
        renderPatchWorkbench(scan, proposals, state.reviews || {}, generation, validationReview);
      }
      const manual = (state.report.recommendations || []).filter(item => item.status === "manual_review");
      if (manual.length) {
        const details = document.createElement("details"); $("remediation-plans").append(details);
        addText(details, "summary", `${manual.length} manual review recommendation${manual.length === 1 ? "" : "s"}`);
        addText(details, "p", "These are component-level recommendations, not ready-to-apply patches or a count of unique vulnerabilities. Several findings can belong to one component. Investigate the source evidence, or record risk acceptance in your review process; neither action fixes a vulnerability.", "hint");
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
          addText(item, "p", group[0].reason.includes("non-registry") ? "A dependency declaration somewhere in this project uses a Git/URL/file reference, alias, tag, or unsupported version rule. This blocks safe automatic lockfile regeneration for the project; it does not mean every listed package uses that reference." : "The scanner has no supported, source-verified automatic update for these observations. Heuristic signals require investigation; they do not establish a confirmed exploit.", "hint");
          const names = [...new Set(group.map(recommendation => detectionNodes.get(recommendation.component_id)?.name || "Repository"))];
          addText(item, "p", `Includes: ${names.slice(0, 5).join(", ")}${names.length > 5 ? ` and ${names.length - 5} more` : ""}. Options: ${group[0].options.map(option => option.replaceAll("_", " ")).join(", ")}.`, "hint");
        }
      }
      $("validate-fixes").disabled = window.guardianShell?.busy() || !proposals.length || proposals.some(proposal => !state.reviews?.[proposal.id]);
      const reviewed = proposals.filter(proposal => state.reviews?.[proposal.id]).length;
      $("remediation-status").textContent += `. ${proposals.length} independent patch proposals · ${reviewed} reviewed · ${proposals.length - reviewed} pending.`;
      $("approval-guidance").textContent = "Automatic rebuild validation is separate from the downloadable draft. Manual recommendations remain below for findings without a supported edit.";
      try {
        const available = await window.guardianDraftPreview?.load(scan, () => generation === remediationGeneration);
        if (generation !== remediationGeneration) return;
        if (available != null) $("remediation-status").textContent = `Remediation ready · ${available} selectable file changes · ${proposals.length} patches eligible for independent validation.`;
      } catch (error) {
        if (generation === remediationGeneration) addText($("remediation-preview"), "p", `Draft unavailable: ${error.message}`, "hint");
      }
    }
    if (!running || !poll) return;
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (generation === remediationGeneration);
}

function renderPatchWorkbench(scan, proposals, reviews, generation, parent = $("remediation-plans")) {
  patchChoices = new Map(); reviewInFlight = false;
  const pending = proposals.filter(proposal => !reviews[proposal.id]);
  if (!proposals.some(proposal => proposal.id === activeProposal)) activeProposal = pending[0]?.id || proposals[0].id;
  const toolbar = addText(parent, "div", "", "patch-toolbar");
  const allLabel = addText(toolbar, "label", ""), all = document.createElement("input");
  all.type = "checkbox"; allLabel.append(all, " Select all reviewed diffs");
  const accept = addText(toolbar, "button", "Accept selected changes", "primary"); accept.type = "button";
  const reject = addText(toolbar, "button", "Reject selected", "secondary"); reject.type = "button";
  const count = addText(toolbar, "span", "", "hint"); count.setAttribute("aria-live", "polite");
  const workbench = addText(parent, "div", "", "patch-workbench");
  const list = addText(workbench, "section", "", "patch-list");
  addText(list, "h3", `Proposed updates (${proposals.length})`);
  const previewArea = addText(workbench, "div", "", "patch-preview");
  const panels = new Map(), rows = new Map();
  function updateSelection() {
    const choices = [...patchChoices.values()], selected = choices.filter(item => item.check.checked);
    count.textContent = `${selected.length} selected · ${pending.length} pending`;
    accept.disabled = reject.disabled = reviewInFlight || !selected.length;
    all.disabled = reviewInFlight || !choices.some(item => item.loaded);
    all.checked = !!choices.length && selected.length === choices.length;
    all.indeterminate = selected.length > 0 && !all.checked;
    for (const item of choices) item.check.disabled = reviewInFlight || !item.loaded;
  }
  function activate(id) {
    activeProposal = id;
    for (const [key, panel] of panels) panel.hidden = key !== id;
    for (const [key, row] of rows) row.setAttribute("aria-pressed", String(key === id));
  }
  all.addEventListener("change", () => {
    for (const item of patchChoices.values()) if (item.loaded) item.check.checked = all.checked;
    updateSelection();
  });
  async function decide(items, decision) {
    if (reviewInFlight || generation !== remediationGeneration) return;
    reviewInFlight = true; updateSelection();
    try {
      for (const item of items) {
        if (generation !== remediationGeneration) return;
        if (decision === "approve" && (!item.loaded || !item.check.checked)) throw new Error("Review and select the exact diff first.");
        if (decision === "accepted_risk" && !item.reason.value.trim()) throw new Error("Provide a reason before accepting risk.");
        await getJSON(`/api/scans/${scan}/remediation/${item.proposal.id}/decision`, {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({digest: item.proposal.digest, decision, reviewed_diff: item.loaded && item.check.checked, reason: item.reason.value})});
      }
      if (generation !== remediationGeneration) return;
      await remediationRefresh(scan, generation);
      window.dispatchEvent(new CustomEvent("guardian:review"));
    } catch (error) {
      if (generation !== remediationGeneration) return;
      await remediationRefresh(scan, generation);
      $("remediation-status").textContent = error.message;
    } finally { reviewInFlight = false; }
  }
  accept.addEventListener("click", () => decide([...patchChoices.values()].filter(item => item.check.checked), "approve"));
  reject.addEventListener("click", () => decide([...patchChoices.values()].filter(item => item.check.checked), "reject"));
  for (const proposal of proposals) {
    const row = addText(list, "div", "", "patch-choice");
    const check = document.createElement("input"); check.type = "checkbox"; check.disabled = true;
    check.setAttribute("aria-label", `Select ${proposal.name}: I reviewed the exact diff`); row.append(check);
    const open = addText(row, "button", "", "patch-open"); open.type = "button";
    addText(open, "strong", proposal.name);
    addText(open, "span", `${proposal.from_version} → ${proposal.to_version}`);
    addText(open, "small", reviews[proposal.id] ? displayStatus(reviews[proposal.id].decision) : "Pending review");
    rows.set(proposal.id, open); open.addEventListener("click", () => activate(proposal.id));
    const panel = addText(previewArea, "article", "", "patch-card"); panels.set(proposal.id, panel);
    const heading = addText(panel, "div", "", "diff-heading");
    addText(heading, "h3", `${proposal.name} · exact patch`);
    addText(heading, "span", "− Removed   + Added", "diff-legend");
    addText(panel, "p", `${proposal.manifest_path} · ${proposal.lockfile_path}`, "hint");
    const preview = addText(panel, "div", "Loading exact manifest and lockfile diff…", "patch-diff-lines");
    preview.tabIndex = 0; preview.setAttribute("role", "region"); preview.setAttribute("aria-label", `${proposal.name} manifest and lockfile diff`);
    const download = addText(panel, "a", "Download exact patch"); download.href = `/api/scans/${scan}/remediation/${proposal.id}/diff`;
    const facts = addText(panel, "details", ""); addText(facts, "summary", "Patch checks, constraints and rollback");
    for (const text of [
      `${proposal.constraint_change_required ? "Outside" : "Within"} original constraints.${proposal.major_change ? " Major version change." : ""} Direct declarations become exact pins.`,
      proposal.candidate_check, proposal.rollback, `${proposal.finding_ids.length} related findings. Digest: ${proposal.digest}`
    ]) addText(facts, "p", text, "hint");
    const reasonLabel = addText(panel, "label", "Review reason (required to accept risk)");
    const reason = document.createElement("textarea"); reason.maxLength = 2000; reason.rows = 2; reasonLabel.append(reason);
    const item = {proposal, check, reason, loaded: false};
    if (reviews[proposal.id]) {
      check.hidden = reasonLabel.hidden = true;
      addText(panel, "p", `Decision: ${reviews[proposal.id].decision}. ${reviews[proposal.id].reason || ""} ${reviews[proposal.id].at}`, "review-decision");
    } else {
      patchChoices.set(proposal.id, item);
      addText(panel, "p", "Selecting this remedy confirms you reviewed its exact diff. Accepted patches are validated independently in temporary copies.", "hint");
      const actions = addText(panel, "div", "", "actions");
      for (const [decision, title] of [["approve", "Accept this change"], ["reject", "Reject this change"], ["accepted_risk", "Accept existing risk"]]) {
        const button = addText(actions, "button", title, decision === "approve" ? "primary" : "secondary"); button.type = "button";
        button.addEventListener("click", () => {
          if (decision === "approve" && (!item.loaded || !check.checked)) {
            $("remediation-status").textContent = "Review the exact diff, then select the remedy checkbox before accepting."; return;
          }
          if (decision === "accepted_risk" && !reason.value.trim()) {
            $("remediation-status").textContent = "Provide a reason before accepting risk."; return;
          }
          decide([item], decision);
        });
      }
      check.addEventListener("change", updateSelection);
    }
    // Fetch directly: opening a details element before attaching its toggle listener can miss the event.
    (async () => {
      try {
        const response = await fetch(download.href);
        if (!response.ok) throw new Error("Diff unavailable; prepare a fresh plan.");
        const value = await response.text();
        if (generation !== remediationGeneration) return;
        preview.replaceChildren();
        for (const line of value.split("\n")) {
          addText(preview, "span", line || " ", "diff-line" + (line.startsWith("---") || line.startsWith("+++") || line.startsWith("@@") ? " file-header" : line.startsWith("+") ? " added" : line.startsWith("-") ? " removed" : ""));
        }
        item.loaded = true; updateSelection();
      } catch (error) { if (generation === remediationGeneration) preview.textContent = error.message; }
    })();
  }
  activate(activeProposal); updateSelection();
}

async function validationRefresh(scan, generation, poll = false) {
  do {
    const state = await getJSON(`/api/scans/${scan}/validation`);
    if (generation !== remediationGeneration) return;
    const running = ["queued", "running"].includes(state.status);
    $("validation-status").textContent = `${displayStatus(state.status)} · ${state.stage || ""}`;
    if (state.report) {
      if (state.status === "not_run") $("validation-status").textContent = "Validation not run · no approved changes were rebuilt.";
      $("validation-summary").replaceChildren();
      addText($("validation-summary"), "p", state.report.results?.some(result => result.decision === "approve")
        ? "Approved patches were checked independently. Original checkout was not changed."
        : "Validation not run: no patch was approved for rebuilding. Rejected changes and accepted risks do not fix findings. Original checkout was not changed.");
      for (const result of state.report.results || []) {
        const card = document.createElement("article"); card.className = "patch-card";
        $("validation-summary").append(card);
        addText(card, "h3", `Validation: ${displayStatus(result.status)}`);
        addText(card, "p", `Decision: ${result.decision}. Dependency verification: ${displayStatus(result.dependency_verification || "not_run")}. Build/tests: ${displayStatus(result.tests?.status || "not_run")}.`);
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

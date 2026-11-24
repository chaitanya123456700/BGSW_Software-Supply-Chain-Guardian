"use strict";
window.guardianRepositoryValidation = (() => {
  let generation = 0;
  function reset() {
    generation++;
    $("repository-validation").replaceChildren();
    $("repository-validation").hidden = true;
  }
  function render(scan, state) {
    const panel = $("repository-validation"); panel.replaceChildren(); panel.hidden = state.status === "not_started";
    if (panel.hidden) return;
    panel.dataset.state = state.status;
    addText(panel, "h2", "Repository remediation validation");
    addText(panel, "strong", state.status === "passed" ? "Passed: no known vulnerability findings in the rescanned dependency tree"
      : state.status === "failed" ? "Validation failed: review the remaining findings or errors"
      : state.status === "incomplete" ? "Validation incomplete: required checks are unavailable"
      : state.status === "stale" ? "Repository changed since validation"
      : "Applying reviewed changes and rescanning…");
    addText(panel, "p", state.stage, "hint");
    const report = state.report;
    if (!report) { if (state.error) addText(panel, "p", state.error); return; }
    addText(panel, "p", report.applied ? `Changes written to: ${report.repository_path}` : "The repository was not changed.");
    const metrics = addText(panel, "div", "", "stats");
    for (const [title, value] of [["Original scan findings", report.before_vulnerabilities ?? "Not checked"],
      ["After-scan findings", report.remaining_vulnerabilities ?? "Not checked"],
      ["Resolved findings", report.finding_diff?.resolved.filter(item => item.type === "vulnerability").length ?? "Not checked"]]) {
      const metric = addText(metrics, "div", "", "stat"); addText(metric, "strong", String(value)); addText(metric, "span", title);
    }
    addText(panel, "p", "The after-scan includes direct and transitive dependencies. Zero is accepted only with complete advisory coverage.", "hint");
    const checks = addText(panel, "ul", "", "draft-checks");
    for (const [name, status] of Object.entries(report.checks || {})) addText(checks, "li", `${displayStatus(name)}: ${displayStatus(status)}`);
    for (const item of report.tests || []) addText(panel, "p", `Build/tests (${item.manifest}): ${displayStatus(item.status)}${item.reason ? ". " + item.reason : ""}`, "hint");
    for (const error of report.errors || []) addText(panel, "p", error, "repository-error");
    if (report.after_scan_id) {
      const open = addText(panel, "button", "Open updated findings", "primary"); open.type = "button";
      open.addEventListener("click", () => window.guardianShell.select(report.after_scan_id, "findings"));
    }
    const download = addText(panel, "a", "Download repository validation report", "button secondary");
    download.href = `/api/scans/${scan}/repository-validation/report`;
    const details = addText(panel, "details", ""); addText(details, "summary", "Source hashes, backup location and validation evidence");
    addText(details, "pre", JSON.stringify(report, null, 2));
    addText(panel, "p", report.limitations, "hint");
  }
  async function follow(scan, token, poll) {
    while (token === generation) {
      const state = await getJSON(`/api/scans/${scan}/repository-validation`);
      if (token !== generation) return null;
      render(scan, state);
      if (!poll || !["queued", "running"].includes(state.status)) return state;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return null;
  }
  return {
    reset,
    async load(scan) {
      const token = ++generation;
      try { await follow(scan, token, true); }
      catch (error) { if (token === generation) render(scan, {status: "failed", stage: error.message}); }
    },
    async start(scan, body) {
      const token = ++generation;
      try {
        await getJSON(`/api/scans/${scan}/repository-validation`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
        const state = await follow(scan, token, true);
        if (token === generation && state?.report?.applied && state.report.after_scan_id) {
          await window.guardianShell.select(state.report.after_scan_id, "remediation");
        }
      } catch (error) { if (token === generation) render(scan, {status: "failed", stage: error.message}); }
    }
  };
})();

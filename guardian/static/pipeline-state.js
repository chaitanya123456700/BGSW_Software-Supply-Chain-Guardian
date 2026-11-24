"use strict";
// Shared presentation rules keep live headers, checkpoint rails, and tests consistent.
const guardianPipelineState = (() => {
  const titles = {discover: "Discover", detect: "Detect", analyze: "Analyze", remediate: "Remediate", validate: "Validate"};
  const label = value => value === "partial" ? "review required" : String(value).replaceAll("_", " ");
  function activeStage(state) {
    if (!state) return null;
    if (state.status === "awaiting_approval") return "remediate";
    if (!["running", "cancelling"].includes(state.status)) return null;
    return Object.keys(titles).find(key => state.modules?.[key]?.status === "running") || null;
  }
  function headline(state, summary) {
    if (!state) return "Individual-module scan. Full pipeline activity is unavailable.";
    const active = activeStage(state), plan = summary?.remediation;
    if (state.status === "awaiting_approval") {
      if (plan?.pending_review_count === 0) return "Review complete · ready to validate reviewed patches.";
      return `Your approval is required before validation${plan?.pending_review_count != null ? ` · ${plan.pending_review_count} ${plan.pending_review_count === 1 ? "patch" : "patches"} awaiting review` : ""}.`;
    }
    if (state.status === "completed") {
      if (plan?.proposals_count === 0) return `Scan finished · review and export remediation changes${plan.manual_review_count ? ` · ${plan.manual_review_count} recommendations need manual review` : ""}.`;
      return `Scan finished · validation ${label(summary?.validation?.status || state.modules?.validate?.status || "not_run")}.`;
    }
    if (state.status === "queued") return "Pipeline queued · waiting for a worker.";
    if (state.status === "failed") return `Pipeline failed · ${state.stage || "open Activity for details"}.`;
    if (state.status === "cancelled") return "Pipeline cancelled · completed evidence is preserved.";
    if (state.status === "interrupted") return "Pipeline interrupted · resume to continue from checkpoints.";
    if (active) return `${state.status === "cancelling" ? "Stopping" : "Current stage:"} ${titles[active]} · ${state.stage}`;
    return `${state.status.replaceAll("_", " ")} · ${state.stage || "Waiting for the next module"}`;
  }
  function stageLabel(state, key, summary) {
    if (state?.status === "awaiting_approval" && summary?.remediation?.pending_review_count === 0) {
      if (key === "remediate") return "Review complete";
      if (key === "validate") return "Ready to validate";
    }
    if (state?.status === "awaiting_approval" && key === "remediate") return "Needs your approval";
    if (state?.status === "awaiting_approval" && key === "validate") return "Waiting for approval";
    const status = state?.modules?.[key]?.status || "not_started";
    return {running: "Running now", partial: "Finished", incomplete: "Checks unavailable", completed: "Finished", passed: "Passed", not_started: "Not started", not_run: "Not run"}[status] || status.replaceAll("_", " ");
  }
  function resultLines(key, summary) {
    if (!summary) return ["Results appear here as each stage finishes."];
    const applied = summary.repository_validation;
    if (applied?.applied && key === "validate") return [`Vulnerability findings: ${applied.before_vulnerabilities} before · ${applied.remaining_vulnerabilities} after.`,
      `Actual checkout: ${applied.repository_path}. Advisory coverage: ${applied.checks.advisory_coverage}. Build/tests are reported separately.`];
    if (applied?.applied && key === "remediate") return ["Reviewed changes were written to the local checkout. A backup was retained."];
    if (applied?.applied && key === "analyze") return ["The updated dependency tree was rescanned. AI analysis was not rerun for this validation scan."];
    const count = value => value ?? "Not recorded";
    if (key === "discover") return [`${count(summary.statistics?.component_count)} component observations · ${count(summary.statistics?.edge_count)} dependency edges.`,
      `SBOM: ${summary.sbom || "not generated"}. Coverage: ${summary.coverage || "unknown"}.`];
    if (key === "detect") return [`${count(summary.advisories)} verified advisory matches · ${count(summary.signals)} review signals.`, `Source policy: ${summary.policy || "not assessed"}. These are findings, not approved fixes.`];
    if (key === "analyze") return [`${count(summary.analysis?.findings_count)} findings prioritized. ${count(summary.analysis?.reachability ? summary.analysis.reachability.reachable || 0 : undefined)} packages have an observed import path.`, "Scores are deterministic; AI notes explain evidence and do not approve changes."];
    if (key === "remediate") return [`Automatic patches: ${count(summary.remediation?.proposals_count)} · manual review recommendations: ${count(summary.remediation?.manual_review_count)}.`,
      summary.remediation?.proposals_count === 0 ? "Open Remediation to inspect source-backed edits, apply selected changes to a working draft, and download the changed files. Independent rebuild validation is unavailable for unsupported projects." : `Awaiting review: ${count(summary.remediation?.pending_review_count)} · approved: ${count(summary.remediation?.approved_count)}. Review the exact diff before validation.`];
    const results = summary.validation?.results || [];
    if (!results.length) return ["No approved patch was rebuilt.", "Validation requires an approved exact diff. Rejected patches and accepted risks are not fixes."];
    return results.map(result => `${label(result.status)}: dependencies ${result.dependency_verification || "not_run"} · build/tests ${result.tests?.status || "not_run"}${result.finding_diff ? ` · findings resolved ${result.finding_diff.resolved.length}, remaining ${result.finding_diff.remaining.length}, introduced ${result.finding_diff.introduced.length}` : ""}.`);
  }
  return {titles, activeStage, headline, stageLabel, resultLines};
})();
if (typeof module !== "undefined") module.exports = guardianPipelineState;

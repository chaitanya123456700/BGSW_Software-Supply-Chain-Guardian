"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const state = require("../guardian/static/pipeline-state.js");
const pipeline = status => ({status, stage: "Generating and validating Syft SBOM", modules: {
  discover: {status: "completed"}, detect: {status: "partial"}, analyze: {status: "partial"},
  remediate: {status: "partial"}, validate: {status: "not_run"}}});

test("finished scan never repeats an old running discovery message", () => {
  const job = pipeline("completed");
  const summary = {remediation: {proposals_count: 0, manual_review_count: 206}, validation: {status: "not_run"}};
  assert.equal(state.activeStage(job), null);
  assert.match(state.headline(job, summary), /Scan finished · review and export remediation changes · 206/);
  assert.doesNotMatch(state.headline(job, summary), /Syft|Generating|Current stage/);
  assert.equal(state.stageLabel(job, "detect"), "Finished");
});
test("only the module actually running is the current stage", () => {
  const job = pipeline("running"); job.modules.detect.status = "running"; job.stage = "Querying OSV";
  assert.equal(state.activeStage(job), "detect");
  assert.equal(state.headline(job), "Current stage: Detect · Querying OSV");
  assert.equal(state.stageLabel(job, "detect"), "Running now");
});
test("human review highlights remediation as a pause, never running validation", () => {
  const job = pipeline("awaiting_approval"); job.modules.validate.status = "awaiting_approval";
  assert.equal(state.activeStage(job), "remediate");
  assert.equal(state.stageLabel(job, "remediate"), "Needs your approval");
  assert.equal(state.stageLabel(job, "validate"), "Waiting for approval");
  assert.match(state.headline(job, {remediation: {pending_review_count: 1}}), /1 patch awaiting review/);
});
test("queued and terminal states have no moving current stage", () => {
  for (const status of ["queued", "failed", "interrupted", "cancelled", "completed"]) assert.equal(state.activeStage(pipeline(status)), null);
  assert.match(state.headline(pipeline("queued")), /queued/);
  assert.match(state.headline(pipeline("cancelled")), /cancelled/);
});
test("completed review offers validation without asking for approval again", () => {
  const job = pipeline("awaiting_approval");
  const summary = {remediation: {pending_review_count: 0}};
  assert.match(state.headline(job, summary), /Review complete/);
  assert.equal(state.stageLabel(job, "remediate", summary), "Review complete");
  assert.equal(state.stageLabel(job, "validate", summary), "Ready to validate");
});
test("no proposals means nothing was validated; missing counts stay unknown", () => {
  const summary = {remediation: {proposals_count: 0, manual_review_count: 206}, validation: {results: []}};
  assert.match(state.resultLines("remediate", summary)[1], /apply selected changes to a working draft/);
  assert.match(state.resultLines("validate", summary)[0], /No approved patch was rebuilt/);
  assert.match(state.resultLines("detect", {})[0], /Not recorded/);
});
test("validation summary preserves partial and skipped tests", () => {
  const summary = {remediation: {proposals_count: 1}, validation: {status: "partial", results: [
    {status: "partial", dependency_verification: "passed", tests: {status: "not_run"}, finding_diff: {resolved: [1, 2], remaining: [1], introduced: []}}]}};
  assert.match(state.headline(pipeline("completed"), summary), /validation review required/);
  assert.match(state.resultLines("validate", summary)[0], /dependencies passed · build\/tests not_run · findings resolved 2, remaining 1, introduced 0/);
});

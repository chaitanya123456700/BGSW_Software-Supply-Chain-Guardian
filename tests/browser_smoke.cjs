/* Optional live browser verification. Only the generated controlled fixture is reviewed. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {chromium} = require(process.env.GUARDIAN_PLAYWRIGHT || "playwright");
const root = process.env.GUARDIAN_URL || "http://127.0.0.1:8000";
const url = new URL(root);
assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(url.hostname), "QA only targets a local Guardian server");
assert.equal(url.protocol, "http:");
const output = path.resolve(process.env.GUARDIAN_QA_OUTPUT || "output/verification/milestone6");
fs.mkdirSync(output, {recursive: true});

(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}, timezoneId: "Asia/Kolkata"});
    const page = await context.newPage(), errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(root);
    await page.getByRole("button", {name: "Run controlled demo", exact: true}).click();
    await page.waitForFunction(() => document.querySelector("#pipeline-status").textContent.startsWith("Your approval is required"), {}, {timeout: 180000});
    const scan = new URL(page.url()).searchParams.get("scan");
    const summary = await context.request.get(`${root}/api/scans/${scan}/summary`).then(response => response.json());
    assert.equal(summary.controlled_fixture, true, "Never approve a user repository in automated QA");
    const source = await context.request.get(`${root}/api/scans/${scan}/pipeline`).then(response => response.json());
    assert.equal(source.repo_url, "fixture://guardian-controlled-demo");
    await page.locator('[data-route="remediation"]').click();
    await page.locator(".diff-line.added").first().waitFor();
    await page.getByText("Optional: approve independent patches for validation", {exact: true}).click();
    await page.getByRole("button", {name: "Accept this change", exact: true}).click();
    await page.waitForFunction(() => document.querySelector("#remediation-status").textContent.includes("checkbox"));
    assert.equal(await page.locator("#validate-fixes").isEnabled(), false);
    await page.getByLabel("Review reason (required to accept risk)").fill("AUTOMATED CONTROLLED FIXTURE TEST ONLY: not approval for a user repository");
    await page.getByLabel("Select lodash: I reviewed the exact diff", {exact: true}).check();
    await page.getByRole("button", {name: "Accept selected changes", exact: true}).click();
    await page.waitForFunction(() => document.querySelector("#remediation-plans").textContent.includes("Decision: approve."));
    await page.getByText("Optional: dependency rebuild and Docker build/tests", {exact: true}).click();
    await page.locator("#validation-tests").check();
    await page.locator("#validate-fixes").click();
    await page.waitForFunction(() => location.hash === "#pipeline");
    await page.waitForFunction(() => document.querySelector("#pipeline-status").textContent.startsWith("Scan finished"), {}, {timeout: 180000});
    const report = await context.request.get(`${root}/api/scans/${scan}/verified-report`).then(response => response.json());
    assert.equal(report.results[0].dependency_verification, "passed");
    assert.ok(report.results[0].finding_diff.resolved.some(finding => finding.type === "vulnerability"));
    assert.equal(report.results[0].finding_diff.introduced.filter(finding => finding.type === "vulnerability").length, 0);
    assert.equal(report.original_checkout_modified, false);
    for (const route of ["overview", "pipeline", "dependencies", "findings", "remediation", "reports"]) {
      await page.locator(`[data-route="${route}"]`).click();
      if (route === "findings") {
        await page.locator(".finding-row").first().click();
        await page.locator("#finding-detail .ai-note").first().waitFor();
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({path: path.join(output, `${route}-desktop.png`), fullPage: true, animations: "disabled"});
      assert.equal(await page.locator(`[data-route="${route}"]`).getAttribute("aria-current"), "page");
    }
    const exports = await page.locator("#report-artifacts a").evaluateAll(nodes => nodes.map(node => node.href));
    for (const link of exports) assert.equal((await context.request.get(link)).status(), 200, link);
    await page.getByText("AI gateway settings and usage", {exact: true}).click();
    await page.locator("#ai-status-button").click();
    await page.waitForFunction(() => document.querySelector("#ai-settings-status").textContent.includes('"slots"'));
    assert.equal(await page.locator(".key-slot").count(), 4);
    const mobile = await browser.newContext({viewport: {width: 375, height: 812}, reducedMotion: "reduce", timezoneId: "Asia/Kolkata"});
    const phone = await mobile.newPage();
    phone.on("pageerror", error => errors.push(error.message));
    await phone.goto(`${root}/?scan=${scan}#overview`);
    await phone.waitForFunction(() => document.querySelector("#overview-components").textContent === "1");
    for (const route of ["overview", "pipeline", "dependencies", "findings", "remediation", "reports"]) {
      await phone.locator(`[data-route="${route}"]`).click();
      const sizes = await phone.evaluate(() => ({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth}));
      assert.ok(sizes.scroll <= sizes.client + 1, `${route}: page overflow ${JSON.stringify(sizes)}`);
      await phone.evaluate(() => window.scrollTo(0, 0));
      await phone.screenshot({path: path.join(output, `${route}-mobile.png`), fullPage: true});
    }
    await phone.setViewportSize({width: 812, height: 375});
    await phone.locator('[data-route="overview"]').click();
    await phone.evaluate(() => window.scrollTo(0, 0));
    await phone.screenshot({path: path.join(output, "overview-landscape.png"), fullPage: true});
    assert.deepEqual(errors, []);
    const result = {scan_id: scan, views: 6, desktop: "1440x1000", mobile: "375x812", landscape: "812x375",
      errors, export_checks: exports.length, validation: report.status, tests: report.results[0].tests.status,
      fixture_approval: "automated controlled test only"};
    fs.writeFileSync(path.join(output, "browser-result.json"), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});

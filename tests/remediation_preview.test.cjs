"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.dataset = {}; this.listeners = {}; this.value = ""; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(key, callback) { this.listeners[key] = callback; }
}
const descendants = root => [root, ...root.children.filter(child => child instanceof Element).flatMap(descendants)];
async function setup() {
  const root = new Element("section"), requests = [];
  const plan = {digest: "a".repeat(64), note: "Review only", options: ["ejs", "handlebars"].map(name => ({id: name, name, files: ["package.json"], from_version: "1", to_version: "2", kind: "advisory_draft", note: "Review only"}))};
  const context = vm.createContext({
    document: {createElement: tag => new Element(tag)}, $: () => root, window: {}, URLSearchParams, displayStatus: value => value,
    addText(parent, tag, text, className) { const item = new Element(tag); item.textContent = text; item.className = className; parent.append(item); return item; },
    getJSON: async (url, options) => {
      if (!options) return plan;
      const body = JSON.parse(options.body); requests.push(body);
      return {selected: body.selected, diff: body.selected.length ? '- old\n+ ' + body.selected.join(",") : "", files: body.selected.length ? [{path: "package.json", content: JSON.stringify({selected: body.selected})}] : [],
        validation: {status: "passed", passed_checks: 4, checks: ["Source unchanged", "Valid JSON", "Exact selected edits", "SHA-256 file hashes"].map(name => ({name, status: "passed"})),
          proof: {actual_edits: body.selected.length, expected_edits: body.selected.length, unexpected_edits: 0}, elapsed_ms: 1,
          receipt_sha256: "b".repeat(64), lockfile: {status: "needs_regeneration", message: "Lockfile regeneration required"}}};
    },
  });
  vm.runInContext(fs.readFileSync(require.resolve("../guardian/static/remediation-preview.js"), "utf8"), context);
  await context.window.guardianDraftPreview.load("actual-repo", () => true);
  const nodes = () => descendants(root);
  const button = text => nodes().find(item => item.tag === "button" && item.textContent === text);
  const check = name => nodes().find(item => item.attributes["aria-label"]?.startsWith(`Select ${name} for export`));
  const downloadPanel = () => nodes().find(item => item.className === "exports draft-downloads");
  return {context, root, requests, nodes, button, check, downloadPanel};
}

test("selection updates the CLI draft and downloads contain only applied remedies", async () => {
  const app = await setup();
  assert.equal(app.downloadPanel().hidden, true, "Proposed previews are not applied downloads");
  app.check("handlebars").checked = true; app.check("handlebars").listeners.change();
  await app.button("Apply selected changes").listeners.click();
  assert.deepEqual(app.requests.at(-1).selected, ["handlebars"]);
  assert.equal(app.downloadPanel().hidden, false);
  const zip = app.nodes().find(item => item.textContent === "Download selected files (ZIP)");
  assert.equal(new URL(zip.href, "http://localhost").searchParams.get("selected"), "handlebars");
  assert.ok(app.nodes().some(item => item.className === "diff-line added" && item.textContent === "+ handlebars"));
  app.button("Updated file").listeners.click();
  assert.equal(app.nodes().find(item => item.id === "draft-terminal").textContent, '{"selected":["handlebars"]}');
  app.check("ejs").checked = true; app.check("ejs").listeners.change();
  assert.equal(app.downloadPanel().hidden, true, "Changed selection must be reapplied before download");
});

test("clearing selections removes all applied file changes", async () => {
  const app = await setup();
  app.check("ejs").checked = true; app.check("ejs").listeners.change();
  await app.button("Apply selected changes").listeners.click();
  app.check("ejs").checked = false; app.check("ejs").listeners.change();
  assert.equal(app.button("Apply selected changes").disabled, false, "Clearing an applied draft is supported");
  await app.button("Apply selected changes").listeners.click();
  assert.deepEqual(app.requests.at(-1).selected, []);
  assert.equal(app.downloadPanel().hidden, true);
  assert.ok(app.nodes().some(item => item.textContent?.includes("working draft matches the original")));
});

test("loading the same plan again preserves an editable draft", async () => {
  const app = await setup();
  await app.context.window.guardianDraftPreview.load("actual-repo", () => true);
  app.check("ejs").checked = true; app.check("ejs").listeners.change();
  await app.button("Apply selected changes").listeners.click();
  assert.equal(app.downloadPanel().hidden, false);
});

test("validation runs on apply and disappears when the selection changes", async () => {
  const app = await setup();
  const validation = () => app.nodes().find(item => item.className === "draft-validation");
  assert.equal(validation().hidden, true);
  app.check("ejs").checked = true; app.check("ejs").listeners.change();
  await app.button("Apply selected changes").listeners.click();
  assert.equal(validation().hidden, false);
  assert.equal(validation().dataset.state, "passed");
  assert.ok(app.nodes().some(item => item.textContent === "Export integrity passed · 4/4 checks"));
  assert.ok(app.nodes().some(item => item.textContent === "Lockfile regeneration required"));
  const report = app.nodes().find(item => item.textContent === "Download validation report");
  assert.equal(new URL(report.href, "http://localhost").searchParams.get("file"), "guardian-draft-validation.json");
  app.check("handlebars").checked = true; app.check("handlebars").listeners.change();
  assert.equal(validation().hidden, true, "A changed selection must not retain a passed verdict");
});

test("actual checkout writes require explicit review of the current applied selection", async () => {
  const app = await setup(), writes = [];
  app.context.window.guardianRepositoryValidation = {start: async (scan, body) => writes.push({scan, body})};
  app.check("ejs").checked = true; app.check("ejs").listeners.change();
  await app.button("Apply selected changes").listeners.click();
  const write = app.button("Apply to repository and rescan");
  assert.equal(write.disabled, true);
  await write.listeners.click(); assert.equal(writes.length, 0);
  const reviewLabel = app.nodes().find(item => item.tag === "label" && item.children.some(child => typeof child === "string" && child.includes("I approve writing")));
  const reviewed = reviewLabel.children.find(item => item.tag === "input");
  reviewed.checked = true; reviewed.listeners.change();
  assert.equal(write.disabled, false);
  await write.listeners.click();
  assert.equal(writes.length, 1);
  assert.equal(writes[0].scan, "actual-repo");
  assert.deepEqual(Array.from(writes[0].body.selected), ["ejs"]);
  assert.equal(writes[0].body.reviewed_changes, true);
  assert.equal(writes[0].body.receipt, "b".repeat(64));
});

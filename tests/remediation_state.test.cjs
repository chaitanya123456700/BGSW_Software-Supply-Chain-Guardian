"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");

// A minimal DOM isolates review-state logic from a browser and from live services.
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.listeners = {}; this.checked = false; this.disabled = false; this.value = ""; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(event, listener) { this.listeners[event] = listener; }
}
const descendants = node => [node, ...node.children.filter(child => child instanceof Element).flatMap(descendants)];
const flush = () => new Promise(resolve => setImmediate(resolve));
function setup({failDiff = false, delayDiff = false} = {}) {
  const nodes = new Map(), requests = [], pendingDiffs = [];
  const context = vm.createContext({
    document: {createElement: tag => new Element(tag)},
    $: id => { if (!nodes.has(id)) nodes.set(id, new Element("div")); return nodes.get(id); },
    displayStatus: value => value,
    addText(parent, tag, text, className) { const node = new Element(tag); node.textContent = text; node.className = className; parent.append(node); return node; },
    fetch: async () => {
      if (delayDiff) await new Promise(resolve => pendingDiffs.push(resolve));
      return {ok: !failDiff, text: async () => '--- a/package-lock.json\n+++ b/package-lock.json\n- old\n+ new\n'};
    },
    getJSON: async (url, options) => { requests.push({url, body: JSON.parse(options.body)}); },
    window: {dispatchEvent() {}}, CustomEvent: class {},
  });
  vm.runInContext(fs.readFileSync(require.resolve("../guardian/static/remediation.js"), "utf8"), context);
  vm.runInContext('remediationRefresh = async () => {};', context);
  const proposals = ["lodash", "minimist"].map(name => ({id: name, name, digest: `digest-${name}`, from_version: "1.0.0", to_version: "1.0.1", finding_ids: [], manifest_path: "package.json", lockfile_path: "package-lock.json"}));
  context.renderPatchWorkbench("fixture-only", proposals, {}, 0);
  const elements = () => descendants(nodes.get("remediation-plans"));
  const button = text => elements().find(node => node.tag === "button" && node.textContent === text);
  const choice = name => elements().find(node => node.attributes["aria-label"] === `Select ${name}: I reviewed the exact diff`);
  return {context, nodes, requests, pendingDiffs, elements, button, choice};
}

test("diffs load directly and only the selected remedy gets approval", async () => {
  const app = setup(); await flush();
  assert.equal(app.elements().filter(node => node.className === "diff-line added").length, 2);
  assert.equal(app.elements().filter(node => node.className === "diff-line removed").length, 2);
  assert.equal(app.button("Accept selected changes").disabled, true);
  const check = app.choice("minimist"); assert.equal(check.disabled, false);
  check.checked = true; check.listeners.change();
  assert.equal(app.button("Accept selected changes").disabled, false);
  await app.button("Accept selected changes").listeners.click();
  assert.equal(app.requests.length, 1);
  assert.match(app.requests[0].url, /minimist\/decision$/);
  assert.deepEqual(app.requests[0].body, {digest: "digest-minimist", decision: "approve", reviewed_diff: true, reason: ""});
  assert.equal(app.choice("lodash").checked, false);
});

test("missing diff blocks selection and approval", async () => {
  const app = setup({failDiff: true}); await flush();
  assert.equal(app.choice("lodash").disabled, true);
  await app.button("Accept this change").listeners.click();
  assert.equal(app.requests.length, 0);
  assert.match(app.nodes.get("remediation-status").textContent, /checkbox/);
  assert.equal(app.button("Accept selected changes").disabled, true);
});

test("risk acceptance requires a reason and does not become approval", async () => {
  const app = setup(); await flush();
  await app.button("Accept existing risk").listeners.click();
  assert.equal(app.requests.length, 0);
  app.elements().find(node => node.tag === "textarea").value = "Tracked by the owner for follow-up";
  await app.button("Accept existing risk").listeners.click();
  assert.equal(app.requests[0].body.decision, "accepted_risk");
  assert.equal(app.requests[0].body.reviewed_diff, false);
});

test("a late diff response cannot enable approval after the scan changes", async () => {
  const app = setup({delayDiff: true});
  app.context.guardianRemediation = app.context.window.guardianRemediation;
  app.context.guardianRemediation.reset();
  app.pendingDiffs.forEach(resolve => resolve()); await flush();
  assert.equal(app.choice("lodash"), undefined);
  assert.equal(app.requests.length, 0);
});

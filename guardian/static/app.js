"use strict";
const $ = id => document.getElementById(id);
const namespace = "http://www.w3.org/2000/svg";
let graph = null, selected = null, view = [0, 0, 1000, 620], drag = null;
let currentScanId = null, currentReport = null;
let scanGeneration = 0;

async function getJSON(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
  return data;
}

function showStatus(message) { $("status").textContent = message; }
function element(name, attrs = {}) {
  const node = document.createElementNS(namespace, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}
function setView() { $("graph").setAttribute("viewBox", view.join(" ")); }
function zoom(factor) {
  const width = Math.max(80, Math.min(20000, view[2] * factor));
  const height = width * view[3] / view[2];
  view = [view[0] + (view[2] - width) / 2, view[1] + (view[3] - height) / 2, width, height];
  setView();
}

function selectNode(node) {
  selected = node.id;
  document.querySelectorAll(".node").forEach(item => item.classList.toggle("selected", item.dataset.id === selected));
  $("details-hint").hidden = true;
  $("details").hidden = false;
  const names = new Map(graph.nodes.map(item => [item.id, item.name]));
  $("details").textContent = JSON.stringify({
    ...node,
    shortest_path: (graph.paths[node.id] || []).map(id => ({ id, name: names.get(id) })),
    incoming_declarations: [...graph.edges, ...(graph.declared || []), ...(graph.inferred || [])].filter(edge => edge.child === node.id),
    unresolved_declarations: graph.unresolved.filter(edge => edge.parent === node.id),
    resolution_note: "Solid edges show lockfile placement. Dashed edges show declarations or external inference. Declared and inferred versions do not prove installation."
  }, null, 2);
}

function drawGraph() {
  if (!graph) return;
  const search = $("search").value.toLowerCase().trim();
  const filter = $("classification").value;
  const matches = graph.nodes.filter(node =>
    (filter === "all" || node.classification === filter || node.classification === "root") &&
    (!search || `${node.name} ${node.version || ""} ${node.declared_version || ""} ${node.inferred_version || ""} ${node.trust_tier || ""} ${node.requested_constraint || ""} ${node.path}`.toLowerCase().includes(search)));
  $("trust-table").replaceChildren();
  for (const node of matches.filter(item => item.kind === "package").slice(0, 200)) {
    const row = document.createElement("tr");
    for (const value of [node.name, node.trust_tier || "unknown", node.declared_version || node.requested_constraint || "—", node.resolved_version || "—", node.inferred_version || "—"]) {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }
    $("trust-table").append(row);
  }
  const visible = matches.slice(0, 500);
  const layers = new Map(), positions = new Map();
  for (const node of visible) {
    const depth = node.classification === "unreachable" ? 5 : Math.min((graph.paths[node.id]?.length || 1) - 1, 5);
    if (!layers.has(depth)) layers.set(depth, []);
    layers.get(depth).push(node);
  }
  let layerOffset = 90;
  for (const [, nodes] of [...layers].sort((a, b) => a[0] - b[0])) {
    const rows = Math.min(16, nodes.length);
    nodes.forEach((node, index) => positions.set(node.id, {
      x: layerOffset + Math.floor(index / rows) * 220, y: 65 + (index % rows) * 65
    }));
    layerOffset += Math.ceil(nodes.length / rows) * 220;
  }
  const scene = $("scene");
  scene.replaceChildren();
  const matchingEdges = [...graph.edges, ...(graph.declared || []), ...(graph.inferred || []), ...(graph.containment || [])].filter(edge => positions.has(edge.parent) && positions.has(edge.child));
  for (const edge of matchingEdges.slice(0, 3000)) {
    const a = positions.get(edge.parent), b = positions.get(edge.child);
    const path = element("path", {class: `edge ${edge.status === "inferred" ? "inferred-edge" : edge.status === "declared_only" ? "declared-edge" : edge.relationship_type === "contains_project" ? "containment-edge" : ""}`, d: `M ${a.x} ${a.y} Q ${(a.x + b.x) / 2 + 20} ${(a.y + b.y) / 2 - 20} ${b.x} ${b.y}`});
    const title = element("title");
    title.textContent = `${edge.relationship_type || edge.dependency_type}: ${edge.constraint || ""} (${edge.status})`;
    path.append(title); scene.append(path);
  }
  const colors = {root: "#073b55", direct: "#007e87", transitive: "#7c9fb3", unreachable: "#b6a28c"};
  for (const node of visible) {
    const position = positions.get(node.id);
    const group = element("g", {class: `node${selected === node.id ? " selected" : ""}`, transform: `translate(${position.x},${position.y})`, tabindex: "0", role: "button", "aria-label": `${node.name}, ${node.trust_tier || "unknown"}, lockfile version ${node.resolved_version || "unknown"}, declared ${node.declared_version || node.requested_constraint || "unknown"}, inferred ${node.inferred_version || "none"}, ${node.classification}`});
    group.dataset.id = node.id;
    if (typeof detectionReport !== "undefined" && detectionReport?.findings.some(finding => finding.finding_type === "vulnerability" && finding.component_instance_ids.includes(node.id))) group.classList.add("vulnerable");
    const fill = node.classification === "root" || node.node_type === "application" ? "#a58aff" : node.inferred_version ? "#a58aff" : node.resolution_status === "declared_only" || node.resolution_status === "unresolved" ? "#efc181" : node.classification === "unreachable" || node.resolution_status === "unknown" ? "#87949b" : "#66dcd2";
    group.append(element("circle", {r: node.classification === "root" ? 14 : 10, fill}));
    const title = element("title");
    title.textContent = `${node.name}\nTrust: ${node.trust_tier || "unknown"}\nLockfile: ${node.resolved_version || "unknown"}\nDeclared: ${node.declared_version || node.requested_constraint || "unknown"}\nInferred: ${node.inferred_version || "none"}\n${node.path}`;
    group.append(title);
    const label = element("text", {x: 0, y: 30, "text-anchor": "middle"});
    label.textContent = node.name.length > 26 ? node.name.slice(0, 24) + "…" : node.name;
    group.append(label);
    if (node.kind === "package" && node.trust_tier) {
      const provenance = element("text", {x: 0, y: 45, "text-anchor": "middle", class: "provenance"});
      provenance.textContent = node.inferred_version ? `inferred ${node.inferred_version}` : node.trust_tier.replaceAll("_", " ");
      group.append(provenance);
    }
    group.addEventListener("click", () => selectNode(node));
    group.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(node); }
    });
    scene.append(group);
  }
  $("graph-info").textContent = `${visible.length} of ${matches.length} matching instances shown; ${Math.min(matchingEdges.length, 3000)} edges. ${matches.length > 500 ? "View capped at 500 nodes. Narrow your search; exports contain the full graph." : ""} ${matchingEdges.length > 3000 ? "View capped at 3,000 edges." : ""}`;
  fitGraph();
}

function fitGraph() {
  const bounds = $("scene").getBBox();
  const width = Math.max(1000, bounds.width + 150), height = Math.max(620, bounds.height + 120);
  view = [bounds.x - 75, bounds.y - 60, width, height];
  setView();
}

function showReport(scanId, report, dependencyGraph) {
  currentScanId = scanId; currentReport = report;
  graph = dependencyGraph;
  selected = null;
  $("details-hint").hidden = false;
  $("details").hidden = true;
  $("results").hidden = false;
  $("repo-name").textContent = report.repository?.url || "Repository scan";
  $("commit").textContent = `Commit ${report.repository?.commit || "unavailable"}`;
  $("coverage").textContent = `Dependency status: ${report.dependency_status || "not recorded in this older scan"}. Coverage: ${report.coverage_status || report.status}.`;
  $("project-select").replaceChildren(new Option("Whole repository", ""));
  $("project-table").replaceChildren();
  for (const project of report.projects || []) {
    $("project-select").append(new Option(`${project.name} (${project.path}) · ${project.completeness_status}`, project.id));
    const row = document.createElement("tr");
    for (const value of [project.name + " · " + project.path, project.manifest_path || "Missing", project.lockfile_path || "Missing", project.workspace_membership || "Independent", project.dependency_status, project.completeness_status]) {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }
    $("project-table").append(row);
  }
  $("unresolved-list").textContent = JSON.stringify(graph.unresolved || [], null, 2);
  $("ecosystems").replaceChildren();
  for (const ecosystem of report.ecosystems || []) {
    const label = document.createElement("span");
    label.className = `ecosystem${ecosystem.supported ? "" : " unsupported"}`;
    label.textContent = `${ecosystem.package_manager} · ${ecosystem.project_root} · ${ecosystem.supported ? "adapter supported" : "detected, unsupported"}`;
    $("ecosystems").append(label);
  }
  $("stats").replaceChildren();
  const labels = {component_count: "Component observations", distinct_package_versions: "Package / versions", direct_dependencies: "Direct", transitive_dependencies: "Transitive", edge_count: "Resolved edges", unresolved_edges: "Unresolved edges"};
  for (const [key, label] of Object.entries(labels)) {
    const stat = document.createElement("div"); stat.className = "stat";
    stat.dataset.stat = key;
    const value = document.createElement("strong"); value.textContent = report.statistics?.[key] ?? "—";
    const caption = document.createElement("span"); caption.textContent = label;
    stat.append(value, caption); $("stats").append(stat);
  }
  const warnings = [...(report.errors || []), ...(report.warnings || [])];
  $("warning-list").replaceChildren();
  $("warnings").hidden = warnings.length === 0;
  for (const message of warnings) {
    const item = document.createElement("li"); item.textContent = message; $("warning-list").append(item);
  }
  for (const artifact of ["sbom", "graph", "components", "report"]) {
    const link = $("download-" + artifact);
    link.href = `/api/scans/${scanId}/${artifact}`;
    link.download = "";
    const disabled = artifact === "sbom" && report.sbom?.status !== "completed";
    link.setAttribute("aria-disabled", String(disabled));
    if (disabled) link.removeAttribute("href");
  }
  $("download-discovery-evidence").href = `/api/scans/${scanId}/discovery-evidence`;
  $("download-discovery-evidence").hidden = !report.discovery_inference?.requests;
  $("search").value = ""; $("classification").value = "all";
  drawGraph();
  if (window.guardianDetection) window.guardianDetection.load(scanId, report, dependencyGraph);
  window.dispatchEvent(new CustomEvent("guardian:scan", {detail: {scanId, report}}));
}

$("project-select").addEventListener("change", async () => {
  const projectId = $("project-select").value;
  $("project-select").disabled = true;
  try {
    graph = await getJSON(`/api/scans/${currentScanId}/graph${projectId ? "?project_id=" + encodeURIComponent(projectId) : ""}`);
    selected = null; $("details").hidden = true; $("details-hint").hidden = false;
    for (const stat of document.querySelectorAll("[data-stat]")) stat.querySelector("strong").textContent = graph.statistics[stat.dataset.stat] ?? "—";
    const project = (currentReport.projects || []).find(item => item.id === projectId);
    $("coverage").textContent = project ? `${project.name}: ${project.dependency_status}. Completeness: ${project.completeness_status}. Observed paths can include declarations and inference; verified reachability excludes them.` : `Dependency status: ${currentReport.dependency_status}. Coverage: ${currentReport.coverage_status}.`;
    $("unresolved-list").textContent = JSON.stringify(graph.unresolved || [], null, 2);
    $("download-graph").href = `/api/scans/${currentScanId}/graph${projectId ? "?project_id=" + encodeURIComponent(projectId) : ""}`;
    drawGraph();
  } catch (error) { showStatus(error.message); }
  finally { $("project-select").disabled = false; }
});

async function followScan(scanId) {
  const generation = ++scanGeneration;
  while (true) {
    const state = await getJSON(`/api/scans/${scanId}`);
    if (generation !== scanGeneration) return;
    if (window.guardianShell?.pipeline()) window.guardianShell.refreshStatus();
    else showStatus(`Discovery ${state.status}: ${state.stage || "finished"}${state.error ? ". " + state.error : ""}`);
    if (!["queued", "running"].includes(state.status)) {
      const report = await getJSON(`/api/scans/${scanId}/report`);
      if (generation !== scanGeneration) return;
      let dependencyGraph = {nodes: [], edges: [], unresolved: [], roots: [], paths: {}};
      if (report.statistics) dependencyGraph = await getJSON(`/api/scans/${scanId}/graph`);
      if (generation !== scanGeneration) return;
      showReport(scanId, report, dependencyGraph);
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

$("scan-form").addEventListener("submit", async event => {
  event.preventDefault(); $("analyze").disabled = true; $("results").hidden = true;
  try {
    showStatus("Submitting repository…");
    const baseline = $("pipeline-baseline").value.trim();
    if (baseline && !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(baseline)) throw new Error("Use a full lowercase commit SHA.");
    const response = await getJSON("/api/pipelines", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({repo_url: $("repo-url").value.trim(), baseline_commit: baseline || null})});
    await window.guardianShell.select(response.scan_id, "pipeline");
  } catch (error) { showStatus(error.message); }
  finally { $("analyze").disabled = false; }
});
$("search").addEventListener("input", drawGraph);
$("classification").addEventListener("change", drawGraph);
$("fit").addEventListener("click", fitGraph);
$("zoom-in").addEventListener("click", () => zoom(.8));
$("zoom-out").addEventListener("click", () => zoom(1.25));
$("graph").addEventListener("wheel", event => { if (event.ctrlKey) { event.preventDefault(); zoom(event.deltaY > 0 ? 1.1 : .9); } }, {passive: false});
$("graph").addEventListener("pointerdown", event => {
  if (event.target.closest(".node")) return;
  drag = {x: event.clientX, y: event.clientY, view: [...view]};
  $("graph").setPointerCapture(event.pointerId);
});
$("graph").addEventListener("pointermove", event => {
  if (!drag) return;
  const bounds = $("graph").getBoundingClientRect();
  const scale = Math.max(view[2] / bounds.width, view[3] / bounds.height);
  view[0] = drag.view[0] - (event.clientX - drag.x) * scale;
  view[1] = drag.view[1] - (event.clientY - drag.y) * scale;
  setView();
});
$("graph").addEventListener("pointerup", () => { drag = null; });
$("graph").addEventListener("pointercancel", () => { drag = null; });

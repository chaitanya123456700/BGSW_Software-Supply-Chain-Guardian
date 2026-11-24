"use strict";
window.guardianDraftPreview = (() => {
  let generation = 0, loadedScan = null, loadedDigest = null, optionCount = 0, currentGuard = () => false;
  function reset() {
    generation++; currentGuard = () => false; loadedScan = loadedDigest = null; optionCount = 0;
    $("remediation-preview").replaceChildren();
  }
  async function load(scan, isCurrent) {
    let token = generation;
    const plan = await getJSON(`/api/scans/${scan}/remediation-preview`);
    if (token !== generation || !isCurrent()) return null;
    currentGuard = isCurrent;
    if (loadedScan === scan && loadedDigest === plan.digest) return optionCount;
    token = ++generation;
    loadedScan = scan; loadedDigest = plan.digest; optionCount = plan.options.length;
    const root = $("remediation-preview"); root.replaceChildren();
    if (!optionCount) {
      addText(root, "p", "No source-backed file edits are available. Findings without a supported file edit remain in manual review below.", "hint");
      return 0;
    }
    addText(root, "h2", "Remediation workspace");
    addText(root, "p", "Inspect proposed edits, choose remedies, and apply selected changes to a downloadable working draft. The scanned checkout stays unchanged.", "hint");
    const toolbar = addText(root, "div", "", "patch-toolbar");
    const allLabel = addText(toolbar, "label", ""), all = document.createElement("input"); all.type = "checkbox";
    allLabel.append(all, " Select all remedies");
    const apply = addText(toolbar, "button", "Apply selected changes", "primary"); apply.type = "button";
    const count = addText(toolbar, "span", "0 selected", "hint"); count.setAttribute("aria-live", "polite");
    const workbench = addText(root, "div", "", "patch-workbench");
    const list = addText(workbench, "section", "", "patch-list");
    addText(list, "h3", `Available remedies (${optionCount})`);
    const panel = addText(workbench, "article", "", "patch-card draft-terminal");
    const title = addText(panel, "h3", "Proposed changes");
    const note = addText(panel, "p", "", "hint");
    const status = addText(panel, "p", "Choose remedies, then apply selected changes.", "draft-status");
    status.id = "draft-status"; status.setAttribute("role", "status");
    const controls = addText(panel, "div", "", "actions draft-file-controls");
    const diffButton = addText(controls, "button", "Unified diff", "secondary"); diffButton.type = "button";
    const fileButton = addText(controls, "button", "Updated file", "secondary"); fileButton.type = "button";
    const fileLabel = addText(controls, "label", "Changed file");
    const fileSelect = document.createElement("select"); fileLabel.append(fileSelect);
    const terminal = addText(panel, "div", "Loading proposed diff…", "patch-diff-lines");
    terminal.id = "draft-terminal"; terminal.tabIndex = 0;
    terminal.setAttribute("role", "region"); terminal.setAttribute("aria-label", "Remediation working draft");
    const downloads = addText(panel, "div", "", "exports draft-downloads"); downloads.hidden = true;
    const verification = addText(panel, "section", "", "draft-validation"); verification.hidden = true;
    const repositoryControls = addText(panel, "section", "", "repository-apply-controls"); repositoryControls.hidden = true;
    addText(repositoryControls, "h3", "Apply to the actual repository");
    addText(repositoryControls, "p", plan.checkout_path || "This scan's local GitHub checkout", "hint");
    addText(repositoryControls, "p", "Regenerates the lockfile, rebuilds dependencies with scripts disabled, writes reviewed files to this checkout, and rescans every dependency. A backup is kept. Unsupported resolution leaves the checkout unchanged.", "hint");
    const reviewLabel = addText(repositoryControls, "label", ""), reviewed = document.createElement("input"); reviewed.type = "checkbox";
    reviewLabel.append(reviewed, " I approve writing selected dependency changes and regenerated lockfiles to this local checkout.");
    const applyRepository = addText(repositoryControls, "button", "Apply to repository and rescan", "primary"); applyRepository.type = "button";
    const checks = new Map(), inspectButtons = new Map();
    let current = null, applied = [], busy = false, requestId = 0, view = "diff", showingApplied = false;
    const selectedIds = () => [...checks].filter(([, check]) => check.checked).map(([id]) => id);
    const same = (left, right) => left.length === right.length && left.every(id => right.includes(id));
    function updateControls(markDirty = true) {
      const selected = selectedIds();
      count.textContent = `${selected.length} selected · ${applied.length} applied to export`;
      apply.disabled = busy || (!selected.length && !applied.length);
      all.disabled = busy; all.checked = selected.length === checks.size;
      all.indeterminate = selected.length > 0 && !all.checked;
      checks.forEach(check => check.disabled = busy);
      inspectButtons.forEach(button => button.disabled = busy);
      downloads.hidden = busy || !showingApplied || !applied.length || !same(selected, applied);
      verification.hidden = downloads.hidden;
      repositoryControls.hidden = downloads.hidden;
      applyRepository.disabled = busy || !reviewed.checked || downloads.hidden || !current?.validation?.receipt_sha256;
      if (markDirty && !busy && !same(selected, applied)) status.textContent = "Selection changed. Apply selected changes to update the working draft and downloads.";
    }
    function renderTerminal() {
      terminal.replaceChildren();
      diffButton.setAttribute("aria-pressed", String(view === "diff"));
      fileButton.setAttribute("aria-pressed", String(view === "file"));
      fileLabel.hidden = view !== "file";
      if (!current) return;
      if (view === "file") {
        const file = current.files.find(item => item.path === fileSelect.value) || current.files[0];
        terminal.textContent = file?.content || "No selected changes. The working draft matches the original files.";
      } else {
        for (const line of (current.diff || "No selected changes. The working draft matches the original files.").split("\n")) {
          addText(terminal, "span", line || " ", "diff-line" + (line.startsWith("---") || line.startsWith("+++") || line.startsWith("@@") ? " file-header" : line.startsWith("+") ? " added" : line.startsWith("-") ? " removed" : ""));
        }
        if (current.diff_truncated) addText(terminal, "span", "Preview truncated. Download the ZIP for the complete diff and files.", "diff-line file-header");
      }
    }
    function renderValidation(report) {
      verification.replaceChildren();
      verification.dataset.state = report?.status || "not_run";
      addText(verification, "h3", "Validation");
      addText(verification, "strong", report?.status === "passed" ? `Export integrity passed · ${report.passed_checks}/${report.checks.length} checks` : "Export validation not run");
      if (!report || report.status !== "passed") return;
      const checks = addText(verification, "ul", "", "draft-checks");
      for (const check of report.checks) addText(checks, "li", `${check.name}: ${displayStatus(check.status)}`);
      addText(verification, "p", `Observed edits = selected edits · ${report.proof.actual_edits} = ${report.proof.expected_edits} · ${report.proof.unexpected_edits} unexpected · ${report.elapsed_ms} ms`, "draft-equation");
      const readiness = addText(verification, "p", report.lockfile.message, "draft-lock-status"); readiness.dataset.state = report.lockfile.status;
      addText(verification, "p", "Build/tests: not run. These checks verify exported changes, not application behavior or vulnerability removal.", "hint");
      const details = addText(verification, "details", "");
      addText(details, "summary", "Mathematical proof and file hashes");
      addText(details, "pre", JSON.stringify(report, null, 2));
    }
    async function showSelection(ids, applying, option) {
      const request = ++requestId; busy = true; updateControls();
      status.textContent = applying ? "Applying selected remedies to the working draft…" : "Loading proposed changes…";
      try {
        const result = await getJSON(`/api/scans/${scan}/remediation-preview`, {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({digest: plan.digest, selected: ids})});
        if (token !== generation || request !== requestId || !currentGuard()) return;
        current = result; showingApplied = applying;
        if (applying) applied = [...ids];
        title.textContent = applying ? `Applied export draft · ${ids.length} ${ids.length === 1 ? "remedy" : "remedies"}` : `Proposed changes · ${option.name}`;
        note.textContent = applying ? plan.note : option.note;
        status.textContent = applying ? (ids.length ? `${result.files.length} changed ${result.files.length === 1 ? "file is" : "files are"} ready to download. Only selected remedies are included.` : "Selections cleared. The working draft matches the original files.") : "Proposed diff only. Select remedies and apply them to create downloadable files.";
        fileSelect.replaceChildren();
        for (const file of result.files) {
          const entry = addText(fileSelect, "option", file.path); entry.value = file.path;
        }
        downloads.replaceChildren();
        renderValidation(applying ? result.validation : null);
        if (applying && ids.length) {
          const query = new URLSearchParams({digest: plan.digest, selected: ids.join(",")});
          const base = `/api/scans/${scan}/remediation-preview/download?${query}`;
          const zip = addText(downloads, "a", "Download selected files (ZIP)"); zip.href = base; zip.download = "guardian-selected-changes.zip";
          for (const file of result.files) {
            const link = addText(downloads, "a", `Download ${file.path}`); link.href = base + "&file=" + encodeURIComponent(file.path); link.download = file.path.split("/").pop();
          }
          const proof = addText(downloads, "a", "Download validation report"); proof.href = base + "&file=guardian-draft-validation.json"; proof.download = "guardian-draft-validation.json";
        }
        view = "diff"; renderTerminal();
      } catch (error) {
        if (token === generation && request === requestId && currentGuard()) {
          showingApplied = false; status.textContent = error.message;
        }
      } finally {
        if (token === generation && request === requestId && currentGuard()) { busy = false; updateControls(false); }
      }
    }
    for (const option of plan.options) {
      const row = addText(list, "div", "", "patch-choice");
      const check = document.createElement("input"); check.type = "checkbox";
      check.setAttribute("aria-label", `Select ${option.name} for export (${option.files.join(", ")})`); row.append(check); checks.set(option.id, check);
      const inspect = addText(row, "button", "", "patch-open"); inspect.type = "button";
      addText(inspect, "strong", option.name);
      addText(inspect, "span", `${option.from_version} → ${option.to_version}`);
      addText(inspect, "small", option.kind === "advisory_draft" ? "Review-only manifest edit" : "Prepared manifest / lockfile patch");
      inspectButtons.set(option.id, inspect);
      inspect.addEventListener("click", () => showSelection([option.id], false, option));
      check.addEventListener("change", updateControls);
    }
    all.addEventListener("change", () => { checks.forEach(check => check.checked = all.checked); updateControls(); });
    apply.addEventListener("click", () => showSelection(selectedIds(), true));
    reviewed.addEventListener("change", updateControls);
    applyRepository.addEventListener("click", async () => {
      if (applyRepository.disabled || !reviewed.checked || !same(selectedIds(), applied)) return;
      busy = true; updateControls();
      await window.guardianRepositoryValidation.start(scan, {digest: plan.digest, selected: [...applied],
        receipt: current.validation.receipt_sha256, reviewed_changes: true, run_tests: !!$("validation-tests")?.checked});
      if (token === generation && currentGuard()) { busy = false; updateControls(false); }
    });
    diffButton.addEventListener("click", () => { view = "diff"; renderTerminal(); });
    fileButton.addEventListener("click", () => { view = "file"; renderTerminal(); });
    fileSelect.addEventListener("change", renderTerminal);
    updateControls();
    await showSelection([plan.options[0].id], false, plan.options[0]);
    return optionCount;
  }
  return {reset, load};
})();

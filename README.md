# BGSW_Software-Supply-Chain-Guardian
AI-assisted software supply chain security platform. Scans a GitHub repo, builds the dependency graph and SBOM, detects vulnerabilities and suspicious packages, prioritizes risk, proposes safe fixes, and validates them with evidence-backed before/after reports.

## Local setup on Windows (Docker Desktop)

Start Docker Desktop with the Linux engine running (resume it if paused). The scan launcher uses Unix resource limits, so use the included Linux container on Windows.

Run these commands in PowerShell from the repository root:

```powershell
# First setup only; leave an existing .env intact.
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up --build -d
```

Open <http://127.0.0.1:8001>. Port 8001 avoids the other local project's service on port 8000. The container includes Python, Git, Node/npm and Syft. No host Python environment or frontend install is required. Source is mounted from this checkout; scan data persists in `data/scans/`.

```powershell
# Start later (after starting/resuming Docker Desktop).
docker compose up -d

# Status and logs.
docker compose ps
docker compose logs -f guardian

# Restart after source or .env changes.
docker compose restart guardian

# Rebuild after changing dependencies or Dockerfile.
docker compose up --build -d

# Run the test suite inside Linux.
docker compose exec guardian python -m pytest -q

# Stop; local scan data is retained.
docker compose down
```

Optional Gemini credentials go in the ignored `.env` file. Without credentials, AI explanations use labeled templates. No model download is needed. The optional scanned-project Docker build/test stage is not configured by this setup and remains `not_run`; it requires a separately configured digest-pinned test image and Docker access inside the execution environment.

## Team Members

| S. No. | Name | Roll Number | Contribution areas |
| --- | --- | --- | --- |
| 1 | Kuppireddy gari chaithanya | AM.AI.U4AID23045 | **Backend development, Architecture Analysis, LLM Integration & pipeline orchestration** |
| 2 | Vatturu Pardheev | CB.SC.U4AIE23344 | **UI/UX, frontend development & SBOM generation** |
| 3 | Sanjushree R | BL.EN.U4AIE23130 | **Vulnerability detection & risk analysis** |
| 4 | Aakash Raj V | CB.AI.U4AID23106 | **AI integration & finding explanations** |
| 5 | Inaganti Rahul Chowdary | CB.SC.U4AIE23232 | **Dependency analysis & remediation validation** |


---

# Guardian · Software Supply Chain Security

## Reading pipeline progress and testing approvals

The live status header follows the latest orchestrator state. A moving violet outline marks only the module currently running; completed and partial outcomes remain still. A review pause highlights Remediate and says **Needs your approval**, while Validate says **Waiting for approval**. Select any stage to see the saved component/SBOM, advisory, priority, patch, or validation results. Selecting a stage changes the inspected results, not the actual running module. Reduced-motion settings remove animation.

A completed plan with zero patches says **No automatic patches** and disables **Validate reviewed patches**. Repeated manual-review recommendations are grouped by reason. Waiting longer does not create an unsupported patch. Each real proposal retains its exact colored diff and shows constraint changes, the exact pin, candidate checks, rollback, and the explicit approve/reject/accepted-risk decision. Validation rebuilds only approved changes in temporary copies.

For the complete approval flow, use **Overview → Run controlled demo**. Testing used the bundled local fixture in `guardian/demo.py`, containing lodash 4.17.20 and an npm lockfile, rather than a separately published GitHub repository. Live verification previously resolved a published fixed candidate and exercised review, temporary rebuild, Syft and OSV rescan. Other GitHub repositories can be scanned, but automatic patches currently require supported direct npm dependencies, package-lock v2/v3, registry constraints, and unchanged dependency topology. The nodejs-goof scan's manual outcomes are preserved; this UI update does not bypass those restrictions.

This progress/approval UI update was checked against saved reports and mocked states only: 46 focused Python checks, six JavaScript state regressions, and seven offline browser scenarios passed. No provider requests, new scans, model generation, or approval mutations were performed. The saved verification screenshots are under `output/verification/stage-feedback/` and depict offline replay, not a fresh live scan.

## AI Model & Provider Configuration

Gemini API keys can be configured in `.env` (copy from `.env.example`). Gemini uses `gemini-2.5-flash` by default. Local fallback can also be enabled with `OLLAMA_MODEL=Qwen/Qwen3-0.6B` and `OLLAMA_BASE_URL=http://127.0.0.1:11434`.

If running a local model server via Transformers, you can serve it with `guardian.local_model`:

```bash
python -m guardian.local_model --model Qwen/Qwen3-0.6B
```

In another terminal, start Guardian:

```bash
python -m uvicorn guardian.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`. Stop either process with Ctrl+C. The local bridge binds only 127.0.0.1, suppresses prompt logging, limits request/context/output sizes, rejects browser-origin POSTs, and allows only one generation at a time. CPU generation is bounded; a small model may fail strict output validation, producing a template instead. No Gemini metadata or generation requests were made during this configuration. The temporary model process was stopped; run the commands yourself when ready. Gemma was not downloaded.

## Milestone 6: six-view workspace and complete demo

All six milestones are implemented. The existing vanilla JavaScript dashboard now has six real-data views with a charcoal theme, violet AI accents, cyan evidence indicators, keyboard focus, deep links, and responsive navigation:

1. **Overview:** public GitHub pipeline intake, optional baseline, local history, original advisory counts, and separate validation outcome.
2. **Live pipeline:** actual five-module states, attempts, event history, errors, cancellation, resume, and the gateway trust-boundary diagram.
3. **Dependencies:** project filters, package search, graph pan/zoom, vulnerable instance markers, trust tiers, and source evidence.
4. **Findings & AI:** search and filters, original severity, deterministic priority/confidence, package reachability, and provider/template provenance.
5. **Remediation:** exact colored diffs, candidate checks, rollback, immutable approve/reject/accepted-risk reviews, and temporary validation results.
6. **Report & settings:** actual artifact downloads, before/after outcomes, usage/cache/fallback counts, four safe key-slot statuses, and on-demand model metadata checks.

Run locally:

```bash
.venv/bin/python -m uvicorn guardian.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`. Select **Run controlled demo** to create an intentionally vulnerable fixture through the ordinary pipeline. It uses live OSV/npm intelligence and Syft, pauses at **awaiting approval**, and never auto-approves. Open Remediation, read the exact diff, check the review acknowledgement, and choose a decision. **Validate reviewed patches** resumes the orchestrator with the requested Docker-test option. Original source stays unchanged. Workflow completion and security verification are displayed separately.

The same controlled demo is available from the CLI:

```bash
.venv/bin/python -m guardian.demo --data data/scans
.venv/bin/python -m guardian.demo --data data/scans --resume SCAN_ID
.venv/bin/python -m guardian.demo --data data/scans --warm-cache SCAN_ID
```

Review through the UI before resuming. `--warm-cache` reuses the actual three task payloads, configured providers, shared budgets, and validated cache. It never creates synthetic provider notes. Without configured credentials it produces labeled templates and no AI cache entries. Saved reports and notes replay in the UI without generation calls; tests separately prove validated provider-cache replay across tasks without requests. No live Gemini generation or billing claim is made.

Additional APIs: `GET /api/scans` returns bounded local scan history; `GET /api/scans/{id}/summary` returns coverage, artifact availability, saved task usage, and validation outcomes with stale-plan checks; `POST /api/demo` queues only the fixed controlled fixture. The regular pipeline endpoint still rejects arbitrary fixture/local-path URLs. `POST /api/scans/{id}/resume` optionally accepts `{ "run_tests": true }`.

Verification: **210 passed, 2 skipped**; all five JavaScript files passed syntax checks and Python dependencies are consistent. The controlled live demo used real OSV, registry metadata, offline lock preparation, script-disabled npm ci, and Syft. An explicitly labeled automated fixture-only UI review approved lodash 4.17.20 → 4.18.1. Four advisory matches resolved, two source script review/policy signals remained, no finding was introduced, and the original source hash stayed unchanged. Docker was unavailable, so tests correctly remained `not_run` and verification `partial`.

Browser verification covered all six views at 1440×1000 and 375×812, landscape at 812×375, reduced motion, the approval checkbox guard, pipeline resume, finding/AI inspection, artifact downloads, and safe key settings with zero JavaScript errors. Initial in-app browser verification worked; subsequent access became unavailable, so isolated Playwright Chromium completed QA. A mobile overflow was fixed. Screenshots and observed results are saved under `output/verification/milestone6/`.

Optional repeatable live browser QA creates and approves **only a new controlled fixture**. It requires a separately installed Playwright test harness, never a production frontend dependency:

```bash
npm install --prefix .tools/browser-qa --ignore-scripts --no-audit --no-fund playwright@1.56.1
node .tools/browser-qa/node_modules/playwright/cli.js install chromium
GUARDIAN_PLAYWRIGHT="$PWD/.tools/browser-qa/node_modules/playwright" GUARDIAN_URL=http://127.0.0.1:8000 node tests/browser_smoke.cjs
```

The command makes live intelligence and registry requests and writes clearly labeled fixture review records. Provider credentials remain optional. No user repository is approved, changed, committed, or pushed.

## Milestone 5: remediation and validation

Guardian now prepares deterministic npm upgrades, exposes exact diffs for human review, and rebuilds approved patches in temporary copies. Pipelines run all five modules and pause at `awaiting_approval` when a patch needs review. Completing the workflow does not imply every security check passed: validation separately reports `passed`, `failed`, `partial`, or `not_run`.

After analysis, select **Prepare fix proposals**, open each diff, and choose approve, reject, or accepted risk. Approval requires the exact proposal digest and an explicit reviewed-diff checkbox; accepted risk requires a reason. Reviews persist in SQLite and cannot be overwritten. Then select **Validate reviewed patches**. For an orchestrated scan, resume the pipeline after reviewing all diffs. Original checkouts are never patched, committed, or pushed.

Automatic patches cover direct npm registry dependencies in independent package-lock v2/v3 projects. Candidates come from advisory fixed events, satisfy a published registry identity check, and require a complete exact-version OSV no-match. Constraint changes and major changes are visible. All direct declarations become exact pins. Candidate runtime dependency declarations must match the existing lock entry; topology changes, workspaces, aliases, unsupported managers, and transitive-only fixes remain explicit manual recommendations. Removal/replacement, trusted pins, base-image changes, blocking, escalation, and risk acceptance never receive invented versions.

Lock preparation runs offline in a temporary directory containing only package.json and package-lock.json. It uses empty user/global npm configuration, a fixed registry, a clean environment, and disabled scripts/audit/funding. Git, URL, local, workspace, tag, and unsupported dependency references are rejected before npm. Approved `npm ci` also requires registry URLs and integrity hashes for every locked package. Repository .npmrc and secret files are never copied. This application-level isolation works on macOS without claiming an OS network sandbox.

Validation regenerates a real Syft SBOM, rescans advisories and static signals, compares components/SBOM/findings, retains raw evidence, and exports rollback instructions and review audit. Each proposal validates independently against the original snapshot; reports do not claim a combined patched checkout. Build/tests run only if requested and Docker plus a preloaded digest-pinned `GUARDIAN_TEST_IMAGE` exist. The container has no network, a read-only root and source mount, dropped capabilities, no-new-privileges, and resource limits. Otherwise tests remain `not_run`; no host build/test scripts run.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/scans/{id}/remediate` | Prepare bounded deterministic proposals and gateway fix notes |
| GET | `/api/scans/{id}/remediation` | Plan status, proposals, immutable reviews, stale-input checks |
| GET | `/api/scans/{id}/remediation/{proposal}/diff` | Exact manifest/lockfile diff download |
| POST | `/api/scans/{id}/remediation/{proposal}/decision` | `{digest, decision, reviewed_diff, reason}`; approve/reject/accepted_risk |
| POST | `/api/scans/{id}/validate` | `{run_tests:false}`; requires review of every proposed diff |
| GET | `/api/scans/{id}/validation` | Validation progress and before/after results |
| GET | `/api/scans/{id}/remediation-report` | Plan and candidate evidence references |
| GET | `/api/scans/{id}/validation-report` | Dependency, SBOM, findings, and test outcomes |
| GET | `/api/scans/{id}/verified-report` | Evidence-backed outcomes, AI usage, review audit; inspect fully_verified |
| GET | `/api/scans/{id}/validation/{result}/{artifact}` | After-scan sbom/components/graph/detection/discovery/evidence/result |
| GET | `/api/scans/{id}/remediation-evidence/{evidence}` | Original candidate query/registry evidence |

Milestone 5 verification: **204 passed, 2 skipped**; four JavaScript syntax checks and dependency consistency checks passed. Live controlled-fixture verification used real OSV, npm metadata, offline npm lock regeneration, script-disabled npm ci, and Syft. lodash 4.17.20 became 4.18.1, four matched advisories disappeared, no new advisory appeared, and the SBOM reflected the upgrade. Repository script review findings remained. Original files stayed byte-identical and the lifecycle sentinel never ran. Approval was explicitly labeled an automated fixture test, not a human approval for a user repository. Docker is unavailable here, so build/tests stayed not_run and overall validation stayed partial. Gemini used labeled templates with zero requests.

Milestone 6 adds the complete six-view interface and demo described above.

## Analysis and AI gateway

Guardian analyzes JS/TS package imports, assigns deterministic review priorities, and optionally explains findings through one budgeted Gemini/Ollama gateway.

Package reachability uses `reachable`, `possibly_reachable`, `unknown`, and `not_reachable`. Literal direct imports can establish an observed package binding; verified transitive dependencies inherit possible reachability. Dynamic loading, aliases, type/test context, absent source, and unsupported ecosystems preserve uncertainty. `not_reachable` means no path was observed in the supported static model, not that runtime loading is impossible. File/line/hash evidence is available separately. No function-level exploitability is claimed.

Priorities combine original severity/CVSS vectors, package reachability, policy context, explicitly advisory-reported exploitation evidence when supplied, verification strength, and signal confidence. Scores retain their factors and never overwrite original advisory severity. They are review heuristics, not CVSS replacements or probabilities. AI cannot add findings, change these scores, or approve a fix.

The gateway supports four Gemini project slots, persistent quota-group cooldowns, credential failover, model-unavailability fallback, schema validation with one bounded repair, validated-result caching, labeled deterministic templates, and optional loopback-only Ollama. Defaults are three attempts per scan, thirty requests per UTC day across scans, and twelve seconds between requests. Failovers and repairs consume budget, so routing may stop before every key is attempted. Keys sharing a quota group never rotate to bypass a 429. Model metadata is checked only on demand, never at startup.

Install updated dependencies with `.venv/bin/python -m pip install -r requirements.lock`, then restart the server using the command below. To configure generation, copy `.env.example` to a local `.env` and fill the four key fields there. Never paste real keys into chat or commit them. Environment variables override file values; new analysis/settings requests reload configuration. Leave Ollama disabled unless you have configured a local model yourself. See [AI_GATEWAY.md](AI_GATEWAY.md) for precise model, budget, payload, caching, and access behavior.

In the existing dashboard, run detection, then select **Analyze reachability and explain findings**. Findings show deterministic priority, source severity, score factors, import evidence, and clearly labeled provider/template notes. **AI gateway settings and usage** exposes safe key status and on-demand metadata checks. Listing a model does not verify generation access, billing, or remaining quota.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/scans/{scan_id}/analyze` | Queue analysis of a usable detection result |
| GET | `/api/scans/{scan_id}/analysis` | Progress/report, including stale detection checks |
| GET | `/api/scans/{scan_id}/analysis-report` | Full analysis report |
| GET | `/api/scans/{scan_id}/reachability` | Package states and source witnesses |
| GET | `/api/scans/{scan_id}/risk-scores` | Deterministic scores and factors |
| GET | `/api/scans/{scan_id}/ai-notes` | Notes, provider/model provenance, usage, cache hits, fallbacks |
| GET | `/api/scans/{scan_id}/analysis-evidence` | Import/source evidence index |
| GET | `/api/scans/{scan_id}/analysis-evidence/{evidence_id}` | Original analysis evidence |
| GET | `/api/ai/status` | Safe slot, cooldown, budget, cache, and usage status |
| POST | `/api/ai/check-models` | Bounded metadata lookup; not a generation test |

Analysis artifacts remain separate from original discovery/detection outputs. SQLite schema 2 adds cache, cooldown, usage, and rate tables while preserving existing jobs and counters. Analysis checkpoints include source evidence and configuration/version hashes. Changing detection makes exposed analysis stale. The first two batched AI tasks explain up to ten findings and review up to five non-vulnerability signals. Remediation runs the third `fix_notes` task with actual deterministic recommendation options, sharing the same scan budget.

Milestone 4 verification: **174 passed, 2 skipped**; all three JavaScript syntax checks and `pip check` passed. The skips remain opt-in GitHub/OSV tests; one upstream TestClient deprecation warning remains. Tests cover routing, shared-project 429s, cooldown persistence, auth/model failover, schema repair, unsafe payloads, score isolation, cache replay, shared limits, local fallback/repair, SQLite upgrade preservation, reachability, CVSS, evidence tampering, and API staleness.

The controlled `fixture://milestone4-controlled` run prioritized twelve findings, observed two directly imported packages, and produced two labeled template batches with zero Gemini requests. Its highest priorities were 64, 63, 57, 56, and 47; overall coverage correctly remained partial. Artifacts are under `data/verification-milestone4/scans/31e950ab509a4133a9d16dcdb1a728e1/`. Browser checks verified score factors, unchanged source severity, template provenance, import evidence, and safe key status. No Gemini keys are configured here, so live Gemini generation, project billing/quota, and live Ollama access remain unverified; provider behavior was tested with synthetic HTTP responses.

## Milestone 3: detection and evidence

Detection now includes current-state repository lifecycle scripts, dependency `hasInstallScript` flags and exact npm registry lifecycle metadata, independent offline name-similarity checks, and local policy enforcement. These checks work without a baseline. Existing OSV matching, baseline change rules, workflow checks, and Dockerfile source inspections remain in use. No scanned package, script, tarball, build, or test command executes.

`policy.yaml` is Guardian's trusted configuration. Its default rules reject Git-based dependency references and unreviewed lifecycle scripts within supported metadata. A repository's own policy file cannot disable them. To record a reviewed script, add either `{file, lifecycle, sha256}` or `{package, version, lifecycle, sha256}` to `reviewed_install_scripts`; the hash covers the exact command text. No reviews are preapproved. Invalid configuration yields `not_run`, and incomplete coverage cannot become a policy pass. `policy_status: failed` means a compliance rule failed; it does not mean the detector crashed or established malware.

Typosquat checks use a runtime-hash-verified 1,000-name snapshot from [`wooorm/npm-high-impact` at a pinned commit](https://github.com/wooorm/npm-high-impact/tree/9e29478332833af97b0e96801a5187cfd3c28382). Collection time, immutable source, upstream hash, and local hash are stored with evidence; its MIT license is retained. One-edit and adjacent-transposition matches produce provisional review signals. Optional deps.dev indexed history and repository-star metadata can adjust review confidence. These are imperfect proxies, not package birth dates, download counts, malware probability, or proof of typosquatting. Missing metadata remains explicit. The historical snapshot is not a trusted-package allowlist or a live global ranking.

The metadata client contacts only `registry.npmjs.org` and `api.deps.dev`. It permits sixty requests and forty-five seconds per scan, bounded responses, no redirects, no automatic retries, and no environment credentials. It checks up to thirty flagged dependency versions, 150 npm metadata files, 2,000 package names, and ten enriched typo candidates. Raw responses, failures, timestamps, source references, and hashes join detection evidence. A lockfile flag without inspectable commands remains unreviewed. Missing flags do not prove absence of scripts, and registry metadata is not tarball-content verification.

OSV `MAL-` matches now have a separate `malicious_package` advisory category, dashboard filter, and verified count. Withdrawn advisories stay excluded. Script, name, and policy findings never create CVEs or MAL matches. Existing advisory severity is preserved.

New output: `artifacts/static_signals.json`, downloadable at `GET /api/scans/{scan_id}/static-signals`. The combined detection report adds `review_signals`, `policy_status`, `policy_violations`, and `verified_malicious_packages`. The dashboard exposes new finding filters, review confidence, policy status, and original evidence. Detection checkpoints include static artifacts, detector version, and the policy hash actually used; changing policy invalidates detection reuse while retaining valid discovery.

Milestone 3 verification: **150 passed, 2 skipped**; both JavaScript syntax checks passed. The skipped tests are opt-in GitHub/OSV integration tests; one upstream TestClient deprecation warning remains. A separate live controlled fixture produced five verified OSV vulnerabilities, zero MAL matches, three policy violations, seven review signals, and 23 evidence records without running scripts. Its results correctly remain partial because baseline and dependency coverage are incomplete. MAL classification and withdrawal behavior were verified with synthetic responses. Browser checks verified filtering, caveats, policy/count display, and raw evidence access.

Live artifacts: `data/verification-milestone3/scans/abdcac65d78b416eabcec04cf2068619/`, labeled `fixture://milestone3-controlled`. This is an intentional test repository, not a claim about a user GitHub project. That milestone 3 fixture predates analysis and remediation; the complete milestone 6 demo is documented above.

## Milestone 2: discovery integration

New scans now expose the five requested trust tiers: `verified_lockfile`, `declared_exact`, `externally_inferred`, `constraint_only`, and `unknown`. Supported npm package-lock v2/v3 projects keep their exact graph and do not contact deps.dev. Unlocked npm and Python projects retain their manifest declarations and can add a separately labeled inferred graph from deps.dev. No package installation or repository code runs.

Python support covers `requirements.txt` and standard `[project]` dependencies and optional dependencies in `pyproject.toml`. Manifests in the same directory share an application. Markers, extras, URL references, and unsupported syntax remain visible as declarations or coverage warnings. Includes, installer options, editable inputs, dynamic metadata, and legacy tool configuration are never executed or followed. Poetry, uv, Yarn, pnpm, and other unsupported locks remain detect-only.

Exact manifest pins use `declared_version`; external resolutions use `inferred_version`. Neither fills `version` or `resolved_version`. Exact pins retain the `declared_exact` tier even when an external graph is attached. Graph JSON separates verified `edges`, manifest `declared` edges, and external `inferred` edges. Inferred paths, cycles, and project filtering work without granting verified reachability. The dashboard adds inferred labels, accessible component descriptions, and a searchable trust/version table. Original Syft SBOM bytes remain unchanged; reconciliation separately identifies declared and inferred observations.

The deps.dev client selects the highest indexed version satisfying a supported constraint. It contacts only the fixed deps.dev host for package versions and dependency graphs, not advisories. It sends package names and selected versions, not source files or credentials. It permits twenty direct declarations, forty requests and thirty seconds per scan, bounded responses and graph sizes, no redirects, and no automatic retries. Unavailable or invalid responses preserve original declarations and partial coverage. External graphs do not establish a joint project resolution or installed/runtime state.

Raw inference evidence lives under `artifacts/discovery/evidence/`, with source URL, retrieval timestamp, commit, and SHA-256. Download its index at `GET /api/scans/{scan_id}/discovery-evidence` and inspect a record at `GET /api/scans/{scan_id}/discovery-evidence/{evidence_id}`. Discovery checkpoints now cover these raw responses. Existing detection evidence stays separate. OSV's existing verified exact npm lockfile checks do not query declared or inferred versions; Python advisory support remains outside this milestone.

Install updated dependencies with `.venv/bin/python -m pip install -r requirements.lock`, then use the server command below. `semantic-version` handles npm ranges; `packaging` handles Python requirements. No Gemini key is needed. Milestone 2 checks: **123 passed, 2 skipped**; JavaScript syntax checks and `pip check` passed. The two skips are opt-in GitHub/OSV integration tests.

Live verification on November 24, 2026 used a controlled, explicitly labeled `fixture://milestone2-unlocked` repository with `express@4.18.2` and `requests==2.31.0`. Four deps.dev requests produced 76 package observations, including 74 transitives, with zero verified edges. Syft completed and the report correctly remained partial/incomplete. Artifacts are under `data/verification-milestone2/scans/e92c69f339ef440caf12bd7406542b55/`. Browser checks verified project filtering, search, trust/version table values, and component evidence. Earlier milestone notes below describe the retained foundation; this section defines current discovery support.

## Revised architecture: milestone 1

The revised five-module architecture now has a persistent central orchestrator. It reuses existing discovery and detection, writes hashed JSON checkpoints, persists job state in SQLite, and supports cancellation and explicit resume. All five modules are implemented. A proposed patch pauses the pipeline at `awaiting_approval`; resume after reviewing every diff. The six-view dashboard starts the full pipeline and retains individual module controls for compatible older scans.

Run the local application with:

```sh
.venv/bin/python -m uvicorn guardian.app:app --host 127.0.0.1 --port 8000
```

Use one server process. Start an orchestrated scan:

```sh
curl -sS http://127.0.0.1:8000/api/pipelines \
  -H 'Content-Type: application/json' \
  -d '{"repo_url":"https://github.com/owner/repository"}'
```

The response contains `scan_id` and `status_url`. An optional `baseline_commit` must be a full trusted commit SHA available in the checkout.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/pipelines` | Latest 100 orchestrated jobs |
| POST | `/api/pipelines` | Queue Discover → Detect; later modules remain blocked |
| GET | `/api/scans/{scan_id}/pipeline` | Full pipeline state, module attempts, events, AI reservations |
| POST | `/api/scans/{scan_id}/cancel` | Request cooperative cancellation |
| POST | `/api/scans/{scan_id}/resume` | Resume a failed, cancelled, interrupted, or blocked job |

Completed stage checkpoints are reused only when their artifact hashes still match. An invalid upstream checkpoint reruns that module and all downstream modules. A discovery retry archives the prior workspace under `workspaces-before-attempt-N`; it does not delete it. Active jobs become `interrupted` after restart and require explicit resume. No automatic unbounded retries occur.

Legacy scan status describes discovery; full pipeline status is separate. Discovery `completed` is not a claim that analysis or security validation succeeded. Existing graph, SBOM, evidence, and detection exports remain available. Original discovery-only and detection-only APIs remain supported.

Four empty Gemini key slots appear in `.env.example`; no API key is needed yet. Environment loading, Gemini routing, AI cache, local fallback, scoring, and remediation are not implemented. SQLite already enforces atomic reservation defaults of three calls per scan and thirty per UTC day across scans for later gateway integration. No AI calls occur in this milestone.

Milestone verification: **90 passed, 2 skipped**; both skips are opt-in network integration tests. Both existing JavaScript files pass `node --check`. One upstream TestClient deprecation warning remains. Live external-service access and the complete remediation demo were not tested. This folder has no `.git` checkout.

See [ARCHITECTURE.md](ARCHITECTURE.md), [AI_GATEWAY.md](AI_GATEWAY.md), [SECURITY_AND_LIMITS.md](SECURITY_AND_LIMITS.md), and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). The earlier implementation notes below describe the retained discovery/detection features; the current milestone scope above takes precedence over historical phase descriptions.

## Day 1 detection and evidence (Phase 2)

The dashboard now foregrounds the slide's expected deliverables: **components, CycloneDX SBOM, dependency graph, risk detection, and inspectable evidence**. After discovering a repository, open **Phase 2 · Detection & evidence** and click **Run Day 1 detection**. An optional trusted baseline must be a full commit SHA already present in the cloned repository. A shallow clone often cannot resolve historical baselines; the application reports `comparison_unavailable` and skips change-dependent rules rather than claiming something was recently added.

Run the existing app:

```sh
python -m pip install -r requirements.lock
python -m uvicorn guardian.app:app --host 127.0.0.1 --port 8000
```

Or run detection on an existing scan from the CLI:

```sh
.venv/bin/python -m guardian.phase2 --scan-dir data/scans/<scan_id>
# Optional comparison, only when this trusted commit is available locally:
.venv/bin/python -m guardian.phase2 --scan-dir data/scans/<scan_id> --baseline <full_commit_sha>
```

Phase 2 adds `vulnerabilities.json`, `suspicious_changes.json`, `detection_report.json`, `detection_status.json`, and `evidence/` under that scan's artifacts. Phase 1 SBOM, inventory, graph, and discovery report are not rewritten. Evidence includes unmodified response/source bytes, content hashes, request context, original retrieval times, commit context, source modification timestamps, and a stable index. The API exposes evidence and findings for inspection. Existing legacy scans can derive application path context from their stored root nodes without rewriting their Phase 1 artifacts.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/scans/{scan_id}/detect` | Start bounded detection; body `{}` or `{"baseline_commit":"<full SHA>"}` |
| GET | `/api/scans/{scan_id}/detection` | Queued/running/completed/partial/failed state and final report |
| GET | `/api/scans/{scan_id}/vulnerabilities` | Exact-version advisory findings and coverage |
| GET | `/api/scans/{scan_id}/suspicious-changes` | Change observations, review signals and source inspections |
| GET | `/api/scans/{scan_id}/findings/{finding_id}` | Canonical finding, affected instances, paths and evidence IDs |
| GET | `/api/scans/{scan_id}/evidence` | Evidence index download |
| GET | `/api/scans/{scan_id}/evidence/{evidence_id}` | Raw source data and provenance metadata |
| GET | `/api/scans/{scan_id}/detection-report` | Detection report download |

**Advisory matching:** only exact npm versions corroborated against original lockfile bytes and valid graph nodes are queried. OSV query batches have at most 100 queries. Full advisory records are retrieved separately. Package/ecosystem agreement, withdrawal, source integrity, affected data, and advisory modification times are checked. OSV's exact-version matching is authoritative; this implementation does not compare semantic version ranges lexicographically or assume a version from a manifest constraint. Batch timestamp microsecond precision is normalized against full-record nanosecond timestamps. CVE/GHSA/OSV aliases are correlated, with one finding supporting multiple installed instances. Shared package instances retain per-application verified paths. Source severity labels, CVSS vectors and fixed-version statements are preserved as advisory data, not converted into risk scores or remediation decisions.

**HTTP bounds:** only `https://api.osv.dev` is contacted by the intelligence client. It does not follow advisory references or HTTP redirects, use environment credentials, or contact GitHub. Requests have timeouts, three attempts for transport/429/5xx failures, bounded backoff, 16 MiB response limits, ten pagination rounds, 2,000 queried logical package/versions, and a 150-second OSV request budget. Query-item failures remain separate from successful items. Successful responses are cached for one hour; cache hits retain original retrieval times. Original evidence files persist. API failure, unknown versions, stale/missing source evidence, incomplete inventory, and unsupported ecosystems never become a claim of no vulnerabilities.

**Change rules:** a valid ancestor baseline enables new dependency declarations, version/constraint changes, lifecycle-script changes, package-source changes, integrity changes, workflow permission changes, and Dockerfile FROM changes. Static workflow inspection flags mutable/unverified action refs even without a baseline. Typosquatting review requires a one-edit match against the versioned npm comparison policy **and** both a newly declared package and changed installation scripts; similarity alone never triggers a finding. Findings are observations or review signals, not malware conclusions. YAML is parsed with SafeLoader after size, alias, depth and event limits. Git comparisons disable external diff/text conversion. No repository scripts, installs, Docker builds, Git writes, or remediation run.

**Limits kept visible:** native vulnerability matching currently covers npm only. Runtime/code reachability and priority remain `not_analyzed` and `not_assessed`. Automated GitHub cross-checking is not enabled. The verification helper can flag supplied conflicting GitHub package metadata, but does not claim range agreement or independent corroboration. OSV may itself contain GitHub-origin data. Docker inspection covers source image references, not image pulls/scans. Non-npm change rules and deleted metadata content analysis remain unsupported; deleted/truncated inspection coverage is reported. Process limits do not provide a full OS sandbox. Evidence/cache retention has no automatic aggregate disk cleanup. A baseline-unavailable result is intentionally partial even when exact-version advisory checks succeed.

Verification commands:

```sh
.venv/bin/python -m pytest -q
GUARDIAN_INTEGRATION=1 GUARDIAN_OSV_INTEGRATION=1 .venv/bin/python -m pytest -q
node --check guardian/static/app.js
node --check guardian/static/phase2.js
```

New deterministic tests use mocked HTTP at the OSV boundary and locally created Git histories. Network is opt-in for separate GitHub/OSV integration tests. The real OSV test checks `lodash@4.17.20` against [GHSA-35jh-r3h4-6jhm / CVE-2021-23337](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm). For the existing public Axios scan at commit `9f0f4ddfe72b4c06afafe1a658e6ee53d35b5760`, an actual OSV run returned 27 verified advisory findings, 969 completed exact package/version queries, and 1,330 evidence records. No trusted baseline was supplied, so it correctly reported partial comparison coverage and made no recent-change claims. These source results are time-dependent and are stored in that scan's detection artifacts.

Implementation files added: `guardian/evidence.py`, `guardian/osv.py`, `guardian/vulnerabilities.py`, `guardian/changes.py`, `guardian/phase2.py`, `guardian/policies/npm_names.json`, `guardian/static/phase2.js`, and corresponding tests. Existing models, API and dashboard were extended. Skills used: lean-build, karpathy-guidelines, surgical-patch, TDD at the supplied interfaces, ponytail, caveman, and verify-and-stop. No plugins, LLMs, agent orchestration, priority scoring, or remediation were added.

Official implementation references: [OSV batch API and pagination](https://google.github.io/osv.dev/post-v1-querybatch/) and [full advisory API](https://google.github.io/osv.dev/get-v1-vulns/).

Phase 1 is a local dependency discovery application. Enter a public GitHub repository URL to clone a pinned commit, detect ecosystems, extract npm lockfile instances and relationships, generate an independent CycloneDX SBOM with Syft, and inspect the graph in a browser.

## Metadata and monorepo upgrade

New scans support npm `package.json` without a lockfile. Constraints are preserved literally, including exact-version declarations, while `resolved_version` stays null. Declared-only nodes and edges appear orange and dashed. No installs, registry guessing, or fabricated transitive dependencies occur.

Completeness distinguishes `verified`, `partial`, `declared_empty`, `verified_empty`, `insufficient_evidence`, `unsupported`, and `failed`. Empty manifests with compatible empty locks are verified empty. Manifest-only empty projects are declared empty. Missing metadata produces a repository root with unknown dependency status. Inconsistent or malformed locks preserve manifest declarations where possible, with explicit warnings or failure status. Orphan lockfile records remain observations with unresolved ownership.

Each discovered application has a stable project ID and root. Explicit npm workspaces can share one v2/v3 lockfile. Valid local links map to canonical targets while retaining installation aliases and link evidence. Workspace containment is separate from actual dependency declarations; being in one lockfile never creates a dependency edge. Independent nested lockfiles retain separate installation instances.

Use **Project / application** to switch between the whole repository and an application. The API supports `GET /api/scans/{scan_id}/graph?project_id=<project_id>`. Per-app traversal follows resolved dependency/workspace edges only; direct declared-only observations remain labeled leaves. Repository containment never grants dependency reachability. Graph JSON keeps `edges` for resolved relationships and adds `declared` and `containment` arrays. Existing `unresolved` declarations remain separate. Source evidence includes stable IDs and exact JSON pointers. Reports include project and repository completeness and counts; node details show shared ownership and version constraints.

Expand **Detected projects and metadata** for manifest/lockfile presence and completeness. Expand **Unresolved dependency declarations** to inspect unresolved records directly. Graph downloads follow the selected project. Rescan after restarting the server to obtain upgraded metadata; old saved scan artifacts are preserved and are not rewritten.

Synthetic upgrade fixtures live in `tests/test_metadata_upgrade.py`. They exercise manifest-only and exact declarations, verified/declared empty projects, missing metadata, inconsistencies, shared workspaces, independent applications, malformed files, literal edge evidence, and API filtering. The original parser, security, graph, Syft, failure, and real GitHub tests remain in place. UI verification uses separately stored, explicitly labeled `fixture://` scans under `data/verification-upgrade`; these are synthetic fixtures, not claimed GitHub scans.

Limits: npm is the only native manifest parser. Python/Cargo manifests without locks are detected but remain unsupported. Complex workspace globs, external/chained links, unverified ownership, semver satisfaction, and installed/runtime verification remain partial or unsupported. Repository-contained SBOM/Dockerfile names are recorded as safe observations when metadata is missing; they do not establish native graph edges. Original Syft SBOMs stay unchanged. Declared-only observations are listed separately in reconciliation and are never upgraded to resolved based on a Syft version.

## Run

Requirements: Python 3.11+, Git, Node.js/npm, and Syft. This workspace already has `.venv` and a checksum-verified Syft 1.57.2 at `.tools/bin/syft`. The application automatically adds that directory to its tool path. Otherwise install Syft from [Anchore's official distribution](https://github.com/anchore/syft/releases).

```sh
python -m uvicorn guardian.app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Use one server process, with no `--workers` or `--reload`: the queue is intentionally local to that process.

For a fresh checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
```

`requirements.lock` records the exact application and test dependency versions used during verification. `pyproject.toml` describes the supported dependency ranges. No tools or packages from a scanned repository are installed.

## Verify

```sh
.venv/bin/python -m pytest -q
node --check guardian/static/app.js
GUARDIAN_INTEGRATION=1 .venv/bin/python -m pytest tests/test_integration.py -q
```

The default suite uses synthetic repositories with known expected versions and edges. Syft and npm run as real tools in the fixture/API tests. The opt-in integration test clones public Axios and exercises the actual pipeline; it requires GitHub network access. An unavailable tool is an actual failure in the tests that require it, not a simulated success. One upstream Starlette/httpx deprecation warning is currently emitted by TestClient.

## Outputs and API

Artifacts are stored under `data/scans/<scan_id>/artifacts/`:

- `sbom.json`: original, unmodified Syft CycloneDX 1.6 JSON. It is downloadable only after offline schema and reference validation succeed.
- `components.json`: normalized component instances, all declarations, application roots, and adapter warnings.
- `dependency_graph.json`: valid resolved edges, separately listed unresolved declarations, statistics, shortest paths, and predecessor references.
- `discovery_report.json`: commit, ecosystem support, tool execution results, reconciliation, warnings, and completeness status.
- `npm-check-*.json`, `npm-check-*.stderr.log`, and `syft.stderr.log`: independent tool evidence and diagnostics.

| Method | Endpoint | Result |
| --- | --- | --- |
| GET | `/health` | API liveness |
| POST | `/api/scans` | `{"repo_url":"https://github.com/owner/repository"}`; returns HTTP 202 and scan ID |
| GET | `/api/scans/{scan_id}` | Queued/running/completed/incomplete/failed status |
| GET | `/api/scans/{scan_id}/graph` | Graph JSON download |
| GET | `/api/scans/{scan_id}/sbom` | Validated original SBOM download, or HTTP 409 |
| GET | `/api/scans/{scan_id}/components` | Inventory JSON download |
| GET | `/api/scans/{scan_id}/report` | Discovery report download |

One worker runs scans outside API request handling. Two more scans can queue; subsequent submissions return HTTP 429. Status files are replaced atomically. On restart, interrupted scans become failed. Results remain available by opening `/?scan=<scan_id>`. Failed ingestion produces a failure report. Syft failure preserves graph findings and marks the analysis incomplete.

## Accuracy and support

Only npm `package.json` and `package-lock.json` v2/v3 have native dependency adapters. The detector recognizes npm, pnpm, Yarn, pip, Poetry, uv, Maven, Go, Cargo, and NuGet markers, including nested projects. Missing npm locks use manifest-only observations; unsupported adapters, old npm locks, and conflicting manager evidence are reported explicitly. Syft can inventory other ecosystems independently; this does not imply native graph support.

The npm adapter models installation instances separately from logical package/version identities. It resolves dependencies from the nearest available lockfile location, including scoped packages, hoisted dependencies, nested versions, aliases with lockfile names, optional overrides, and parent-context peer dependencies. Production, development, optional, and peer declarations retain their source JSON pointer and SHA-256 digest. A missing version stays unknown. A missing target stays unresolved with a null child; it never becomes a fabricated node.

Local lockfile links are supported when the target is another non-link record inside the same lockfile. Their outgoing dependencies resolve from the target's real path. Root workspace membership supports simple per-segment glob patterns such as `packages/*`. Complex globs and external or chained links are explicitly incomplete. In the discovery pipeline, repository containment and declared workspace dependencies have distinct edge types. The low-level lockfile extractor retains its original workspace membership interface for compatibility. Workspace manifests covered by an ancestor lockfile are not extracted twice. Filesystem symlinks are never followed.

`resolved` means the lockfile contains a target at the npm lookup location. It does **not** assert that the installed tree exists, that a version satisfies a constraint, that a package is active on the current OS, or that source code imports it. Every edge records `version_satisfaction: not_checked` unless that check is inapplicable. npm's offline, script-disabled `ls --package-lock-only` provides an independent name/version cross-check; aliases and workspaces may have different native representations. It is not proof of every edge. Manifest/lock discrepancies remain visible in native tool diagnostics.

NetworkX computes reachability from each project's application root. A hoisted package can be transitive. Direct classification means minimum graph distance one, including root peer/development/optional/workspace declarations. Component count excludes application roots; unreachable lockfile records remain in the inventory. The graph retains cycles and repeated references. One shortest witness is exported per reachable instance, capped at depth 100; predecessors retain deeper routes. It does not enumerate exponentially many paths.

Syft runs with development dependencies included and remote enrichment disabled. Original SBOM relationships remain untouched. Reconciliation maps normalized npm names and versions to Syft identities; an identity match does not prove an instance-level SBOM relationship. Missing matches, unresolved declarations (including optional peers), unsupported projects, and tool failures produce `incomplete`, never `completed`.

The dashboard uses local HTML/CSS/JavaScript and an SVG graph renderer. Search, direct/transitive filters, keyboard-selectable node evidence, pan/zoom, and artifact downloads operate on real scan artifacts. The view is capped at 500 matching nodes and 3,000 edges for browser responsiveness. Search covers the entire inventory; JSON exports retain all findings. No CDN or frontend package installation is required.

## Security and limits

- Only strict public `https://github.com/owner/repository` URLs are accepted. Credentials, ports, query strings, fragments, other protocols, and Git redirects are rejected. Private or inaccessible repositories fail without credential prompts.
- Git uses a shallow clone, empty template, disabled hooks, no global/system configuration, no credential helper, no submodules, and argument arrays without a shell. Repositories are isolated under unique scan workspaces. Checkout does not run package scripts or custom repository filters.
- Tools receive a minimal environment with an isolated HOME/TMPDIR. Repository `.npmrc` and Syft configuration are never loaded. npm sees only copied lockfile/manifest data. Syft sees a snapshot of regular files, excluding `.git`, `node_modules`, and symlink entries. Remote enrichment, local module-cache license lookup, and Go package-tool execution are disabled.
- Limits: 20 MiB per parsed source file, 30,000 repository files, 300 MiB repository size, 30 detected project entries, 20,000 combined component records, 100,000 combined declarations, 30 MiB stdout, and 4 MiB stderr. Large files are omitted from the Syft snapshot with warnings. Clone monitoring includes `.git` data. Resource monitoring is periodic rather than a hard filesystem quota.
- Clone timeout is 90 seconds; checkout 45 seconds; npm 30 seconds per project; Syft 120 seconds. Tools share a 300-second scan deadline. Bounded file parsing and graph work can add time after that deadline. Child process groups are killed on timeout. Unix subprocess limits bound CPU, file size, open files, and core dumps; Linux additionally bounds address space. macOS has no reliable equivalent memory limit here.
- Bind to loopback only. Host and browser-origin checks block ordinary cross-origin scan submissions and DNS rebinding. There is no authentication, multi-user isolation, or production deployment support. Do not expose this server publicly.
- **This MVP is not an OS security sandbox.** A malicious input that exploits Git, npm, Syft, or a parser could exceed application-level protections. Use a disposable container or VM with restricted egress, filesystem quotas, and no secrets for adversarial inputs. No unrelated local files are intentionally scanned, and no repository scripts run.
- Artifacts and cloned source persist locally. There is no automatic retention cleanup or aggregate disk quota. Stop the server before removing old scan directories. Do not edit stored repositories during analysis.

## Implementation checklist

- [x] Typed models and local JSON artifacts
- [x] npm v2/v3 extraction and ground-truth fixtures
- [x] NetworkX graph integrity, classification, cycles, and paths
- [x] Restricted ingestion and ecosystem detection
- [x] Real Syft SBOM and offline CycloneDX validation
- [x] Bounded FastAPI scan queue and exports
- [x] Interactive dashboard and real-repository verification

Modules expose ordinary typed Python functions so later phases can call them as tools. Phase 1 contains no LLM integration, vulnerability scanner, remediation, remote PR creation, database, or hosted service.

Design: an engineering inspection workspace, with a large graph and adjacent evidence panel. Navy `#073b55`, teal `#007e87`, red `#c63845`, pale gray `#f5f8fa`, and white separate evidence, actions, and warnings. System Avenir/Segoe fonts keep the interface fully local. The graph carries the visual focus; no decorative imagery is needed.

Skills used: ponytail (full), lean-build, karpathy-guidelines, TDD at the interfaces supplied in the task, caveman reporting, frontend-design for the simple dashboard, and verify-and-stop for acceptance checks. No skills or plugins were installed and no subagents were used.

References: [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/), [Node.js lookup rules](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), [Syft CLI](https://oss.anchore.com/docs/reference/syft/cli/), [Syft configuration](https://oss.anchore.com/docs/reference/syft/configuration/). Vendored CycloneDX 1.6 schemas come from the [official specification](https://github.com/CycloneDX/specification/tree/1.6/schema); its license is included in `guardian/schemas/LICENSE`.

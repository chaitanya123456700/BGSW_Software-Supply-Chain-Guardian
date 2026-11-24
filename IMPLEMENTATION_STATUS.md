# Implementation status

## Follow-up: clear stage progress and approval feedback

- Replaced the stale post-discovery status with the latest pipeline state. Only the running stage has a moving outline; partial/completed stages, review pauses, cancellation, and failures have distinct text. Reduced motion disables movement.
- Made stage markers selectable and added one compact result panel covering saved discoveries, advisory signals, priorities, patch counts/decisions, and validation outcomes. Selection never changes the actual active module.
- Added summary counts for prioritized findings and pending/approved/manual patch decisions. Kept exact-diff approval intact; labeled its constraint change, exact pin, candidate check and rollback.
- Disabled validation when there are zero proposals, explained why nothing can be approved, grouped repeated manual reasons, and removed the false claim that patches were checked when no approved patch was rebuilt.

Verification used saved evidence and intercepted/mock responses only: 46 focused Python checks, six JavaScript state checks, and seven offline UI checks passed. No external requests, generation, scans, or review mutations occurred; no application server was started. Screenshots under output/verification/stage-feedback are labeled offline replay in result.json. Automated patch support was not broadened; nodejs-goof's unsupported dependency-spec outcomes remain manual review. The built-in lodash fixture remains the supported full approval-flow demonstration.

## Milestone 6: six-view UI and complete demonstration

Completed after explicit milestone 6 approval:

- Rebuilt the vanilla JavaScript interface around six deep-linked views, persistent navigation, charcoal surfaces, violet AI accents, cyan evidence, consistent controls, responsive layouts, keyboard focus, and reduced-motion support.
- Connected new scans to the real orchestrator. Added real local history, module states/attempts/errors/events, cancellation/resume controls, and deterministic gateway architecture visualization.
- Preserved graph/project/search/evidence functionality; added vulnerable instance markers and selected finding state. Split findings/AI, remediation, and exports/settings into dedicated views.
- Added colored exact diffs, explicit pending/reviewed counts, manual review recommendations, immutable approvals, validation summaries, downloads, and four safe key statuses with actual saved usage.
- Added a fixed local controlled-fixture endpoint and CLI using live intelligence, ordinary checkpointed orchestration, and the existing approval gate. No arbitrary local paths or fixture URLs were enabled on repository intake.
- Added genuine provider-cache warming through actual task payloads and shared budgets. Synthetic tests prove replay with zero requests; live runs without keys use three labeled templates and never fake AI cache entries.
- Added summary/history APIs with stale-plan handling and optional Docker-test selection on pipeline resume. Scan changes reset client evidence and in-flight work uses generation guards.

Verification: **210 tests passed, 2 opt-in network tests skipped**, five JavaScript syntax checks passed, and pip check found no broken requirements. One upstream TestClient deprecation warning remains. New integration tests cover controlled demo intake, no automatic approval, exact review/resume, immutable source, actual after-scan outcome, history, corrupt status handling, stale summaries, template honesty, validated cache warming/replay, CSP and preserved controls.

The complete live fixture is `d84f71502ba74838a7aa97e340071e27` under `data/verification-milestone6/scans/`. Browser testing created it through the real UI. It reached awaiting_approval, rejected an unchecked approval attempt, then used an explicitly labeled AUTOMATED CONTROLLED FIXTURE TEST ONLY review. Validation resumed through the orchestrator and preserved upstream checkpoints. lodash 4.17.20 became 4.18.1; four advisories resolved, two script/policy review signals remained, and no finding was introduced. Source snapshot digest stayed unchanged and SCRIPT_EXECUTED never appeared. Syft SBOM identities reflected the change. No real user patch or human review is claimed.

All six views were verified at desktop 1440×1000, mobile 375×812 with reduced motion, and landscape 812×375. Exports and key settings worked with no JavaScript errors. In-app browser access later became unavailable; isolated headless Playwright Chromium completed testing. The mobile table overflow and diff-panel layout were fixed. Deliberate evidence screenshots and browser-result.json live under `output/verification/milestone6/`. `tests/browser_smoke.cjs` repeats the controlled live workflow; the Python suite stays offline by default.

Visual QA directly compared generated overview/remediation concepts with browser screenshots using view_image. Checked navigation geometry, charcoal/violet/cyan tokens, heading/control typography, component spacing, diff/inspector hierarchy, responsive collapse, and primary copy. Intentional differences: actual source/commit provenance, manual review signals, real recorded dates/statuses, accessible native controls, and truthful deterministic-versus-AI wording replace illustrative mockup data. No decorative metrics or fabricated charts were shipped.

All six milestones are implemented; none remain pending. Live Gemini/Ollama generation and live Docker execution remain unverified here. The demo accurately shows templates and tests not_run, with overall partial verification. Those external capabilities are not replaced by fabricated success.

## Milestone 5: remediation and validation

Implemented after explicit milestone 5 approval:

- Added bounded fixed-version selection from advisory events, semver constraint checks, published registry identity/integrity checks, complete exact-version OSV candidate checks, and additional advisory fixed-event exploration.
- Added deterministic manifest/lock patches, offline script-disabled npm regeneration, fixed registry, empty configuration, clean environment, reference preflight, five-proposal limits, explicit unsupported/manual recommendations and rollback instructions.
- Added source/patch/evidence digests and immutable SQLite schema 3 approve/reject/accepted-risk reviews. Reviewed-diff acknowledgement is required for approval; accepted risk requires a reason. No original checkout changes.
- Added approved temporary npm ci rebuilds, optional restricted Docker build/tests, real Syft regeneration, OSV/static rescan, component/SBOM/finding comparisons, retained after-scan evidence, audit reports and accurate outcome labels.
- Connected both modules to orchestration, checkpoints, cancellation and worker ownership. Pipelines pause at awaiting_approval. Added preparation, review, validation, raw-evidence/report APIs and usable dashboard controls.
- Connected the third fix_notes gateway task to real deterministic recommendation options; included analysis/fix provenance and shared request totals in reports.

Verification: **204 tests passed, 2 opt-in network tests skipped**; four JS syntax checks and pip dependency checks passed. One upstream TestClient deprecation warning remains. New tests cover unsafe references, lock URLs/links, incomplete locks, candidate outages/deprecation/identity/topology/new advisories, exact approval and tamper rejection, source staleness, persisted decisions, accepted risk/rejection, unapproved rebuild refusal, newly introduced vulnerabilities, Docker command restrictions, API exports, and orchestration review/resume.

Real controlled fixture used OSV, npm metadata, offline lock regeneration, npm ci with scripts disabled, and Syft. lodash 4.17.20 became 4.18.1. Four advisory matches disappeared; source installation-script policy/review signals remained. SBOM identities changed accordingly. Original bytes stayed unchanged and the lifecycle sentinel never executed. Review was explicitly marked AUTOMATED CONTROLLED FIXTURE TEST ONLY. Docker was unavailable, so tests stayed not_run and validation partial. Three template tasks used zero Gemini requests. Live Docker and Gemini generation remain unverified.

Automatic patches currently require unchanged runtime dependency declarations in an independent direct npm project. Other changes have explicit manual recommendations. Each proposal validates independently; no combined patched checkout is claimed. Milestone 6, documented above, completes the interface and demo.

## Milestone 4: analysis and AI gateway

Implemented following explicit milestone 4 approval:

- Added bounded JS/TS lexical package-import extraction with file/line/hash evidence, direct bindings, inherited possible dependency paths, dynamic/alias/type/test uncertainty, and all four reachability states.
- Added deterministic priority scores and evidence confidence with auditable factors, CVSS v2/v3/v4 parsing, original severity preservation, policy context, and explicit advisory-reported exploitation evidence only when supplied.
- Added one four-slot Gemini gateway with operator-defined quota groups, persistent 429 cooldowns, authentication failover, model-unavailability fallback, shared daily/scan/rate limits, and one schema repair within those limits.
- Added literal server-side environment configuration, compact allowlisted payloads, Pydantic output/reference validation, actual/requested model provenance, persistent validated-result caching, labeled templates, and optional loopback-only Ollama.
- Added safe key/usage settings and on-demand model metadata checks. Startup never calls a provider. Metadata listing does not prove generation permission or quota.
- Added analysis/report/evidence APIs and dashboard controls, priorities, score factors, note provenance, import evidence, usage, and safe settings. Detection changes mark analysis stale.
- Integrated analysis into checkpointed orchestration. At that milestone boundary pipelines stopped at remediation. SQLite schema 2 preserves old jobs/counters and adds AI state tables.
- Added the CVSS runtime dependency. No repository packages, scripts, builds, tests, or local model downloads run.

At the milestone 4 boundary, fix notes awaited a deterministic plan. Milestone 5 now invokes that task after remediation recommendations exist, sharing the same budget.

Verification: 174 tests passed, 2 opt-in GitHub/OSV tests skipped, all three JavaScript syntax checks passed, and `pip check` found no broken requirements. One upstream TestClient deprecation warning remains. Tests cover provider routing, shared quota 429s, cooldown persistence, model fallback/deprecation, schema repair, invalid IDs and added scores, secret-free payload boundaries, cache replay, shared limits, SQLite upgrade preservation, import uncertainty, transitive paths, CVSS, evidence tampering, API staleness, and zero startup provider traffic.

Controlled fixture `fixture://milestone4-controlled`, saved under `data/verification-milestone4/scans/31e950ab509a4133a9d16dcdb1a728e1/`, produced twelve prioritized findings, two observed direct package imports, one package with no observed static import path, and one unknown package. Its five highest priorities were 64, 63, 57, 56, and 47. Two tasks used labeled templates and zero Gemini requests because no Gemini keys are configured. Source analysis stayed partial. Browser checks verified unchanged source severity, deterministic scores, template labels, import evidence, and four unconfigured key slots. Live generation, billing, and quota remain unverified; synthetic HTTP tests verify provider behavior.

## Milestone 3: detection and evidence

Implemented following explicit milestone 3 approval:

- Added current-state repository lifecycle checks and exact dependency `hasInstallScript` inspection using bounded npm registry metadata. Regex findings retain raw command evidence without executing anything.
- Added offline typo checks with a named 1,000-package snapshot, immutable upstream commit, collection timestamp, SHA-256 verification, and retained MIT license. Optional deps.dev age/history and project-star evidence adjusts review confidence without creating malware claims.
- Added trusted local `policy.yaml` enforcing no Git-based dependencies and no unreviewed lifecycle scripts in supported metadata. Reviews require exact command hashes and exact source or dependency version context. Repository-owned policies are ignored.
- Added separate MAL advisory labels and counts while preserving OSV exact-version matching, alias correlation, withdrawn-record checks, and source severity.
- Added `static_signals.json`, API export, finding types, filters, confidence descriptions, policy outcomes, and raw evidence links to the existing dashboard.
- Extended detection checkpoints with static artifacts, detector version, and the actual policy hash used. Policy changes invalidate detection reuse.
- Preserved workflow/Dockerfile checks and baseline-dependent change rules. Current-state static signals need no baseline.

Verification: 150 tests passed, 2 opt-in GitHub/OSV tests skipped, and both JavaScript syntax checks passed. One upstream TestClient deprecation warning remains. Focused detector/API tests cover exact command/version reviews, ignored repository policy, Git references, implicit/missing scripts, bad metadata, source tampering, snapshot provenance, scope boundaries, outages, redirects, limits, MAL classification, and withdrawn records. An orchestration test verifies policy changes invalidate only detection checkpoints. Browser checks verified filtering, policy/count display, heuristic caveats, and raw source evidence.

Live verification on November 24, 2026 used an explicitly labeled `fixture://milestone3-controlled` repository under `data/verification-milestone3/scans/abdcac65d78b416eabcec04cf2068619/`. It found five verified OSV vulnerabilities, zero verified MAL advisories, three policy violations, seven review signals, and 23 evidence records. Three metadata requests completed without errors. No scripts, tarballs, package installs, builds, or AI calls ran. Missing baseline and incomplete dependency metadata correctly left overall coverage partial. Synthetic tests separately verify MAL behavior.

## Milestone 2: discovery integration

Implemented following explicit milestone 2 approval:

- Added the five requested trust tiers and separate `declared_version` and `inferred_version` fields. Exact manifest pins never become installed versions.
- Added safe Python requirement and standard pyproject dependency parsing, preserving extras, markers, groups, raw source pointers, and hashes. Supported manifests in one directory share an application.
- Added bounded deps.dev package-version selection and dependency-graph inference for unlocked supported npm/Python declarations. Existing npm lockfile discovery never uses inference.
- Kept inferred nodes, edges, graph paths, per-project observations, and raw discovery evidence separate from verified topology and detection evidence.
- Preserved directed cycles, project filtering, original Syft SBOM bytes, and OSV's existing verified-lockfile-only matching boundary.
- Extended API exports and the existing vanilla dashboard with inferred labels, accessible descriptions, and a trust/version table. Milestone 6 now supplies the full six-view redesign.
- Added `semantic-version` for npm constraint matching and declared the already-installed `packaging` dependency explicitly. No repository packages or scripts were installed or executed.

Verification: 123 tests passed, 2 opt-in GitHub/OSV tests skipped, and both JavaScript syntax checks passed. `pip check` reported no broken requirements. One upstream TestClient deprecation warning remains. New tests cover Python exact/range declarations, dynamic/legacy metadata, unsupported locks, safe source handling, PEP 440/semver selection, inferred cycles, source hashes, bad provider data, outages, redirects, request/response limits, API exports, and full orchestrated discovery/detection with checkpoint tamper detection. Live deps.dev verification on November 24, 2026 made four requests for a controlled fixture containing `express@4.18.2` and `requests==2.31.0`; it yielded 76 package observations, 74 transitive observations, zero verified edges, a validated Syft SBOM, and no errors. The result correctly remained `incomplete` with partial coverage.

The live fixture is explicitly labeled `fixture://milestone2-unlocked` under `data/verification-milestone2/`. Browser checks verified Python project filtering, package search, declared versus inferred table values, and component evidence. Unsupported locks, unsupported requirement forms, and external inference limits remain visible. No Gemini keys were needed.

## Milestone 1: audit and orchestration

Implemented against the revised architecture supplied November 24, 2026:

- Reused existing npm discovery, directed graphs, Syft, OSV detection, evidence, change rules, and vanilla JavaScript dashboard.
- Added a five-module orchestrator over existing discovery and detection functions, with explicit unimplemented later stages.
- Added SQLite schema versioning, persistent jobs, module outcomes and attempts, event history, and request reservations.
- Added JSON checkpoints with artifact hashes, including detection raw evidence, and downstream invalidation when rerunning an upstream module.
- Added explicit resume, restart recovery, cooperative cancellation, process-group termination, and OSV cancellation boundaries.
- Added pipeline start/history/status/cancel/resume APIs while retaining discovery-only and detection-only routes.
- Added atomic per-scan and cross-scan daily AI request reservations. No provider is connected yet.
- Added four empty Gemini key slots, ignored local secret files, and architecture/gateway/security documentation.

The pipeline runs Discover → Detect → evidence persistence, then reports `blocked` at Analyze. It does not claim a completed five-module scan or verified remediation. The current dashboard remains the existing discovery/detection interface; orchestration is available through the API until the later UI milestone.

## Audit findings

The folder is not a Git checkout, so a Git diff, commit, or push is unavailable. No source files were replaced wholesale.

The milestone 1 audit found native npm adapters only. Milestones 2–4 added Python declaration parsing, external inference, independent typo checks, package-level source analysis, deterministic priorities, and the explanation gateway. Milestone 5 added deterministic remediation and validation.

Baseline: 82 tests passed, 2 opt-in network tests skipped. Added orchestration tests cover real detection with mocked OSV transport, checkpoint reuse/tampering, failure/resume, restart recovery, queued cancellation, running process cancellation, atomic budgets, API compatibility, duplicate submission, and schema rejection. See the final milestone test result in README.

## Remaining milestones

| Milestone | Status | Work |
| --- | --- | --- |
| 1. Audit and orchestration | Implemented | Validate and review the persistent orchestration foundation |
| 2. Discovery integration | Implemented | Trust tiers, separate inferred graphs, deps.dev routing, safe Python declaration parsing |
| 3. Detection and evidence | Implemented | Lifecycle metadata, pinned typo corpus, policy enforcement, separate MAL labels, evidence/API/dashboard integration |
| 4. Analysis and AI gateway | Implemented | Package imports/reachability, deterministic scores, four-slot routing, cache, schema repair, templates, optional local provider |
| 5. Remediation and validation | Implemented | Candidate OSV/registry checks, offline lock preparation, exact diff reviews, temporary rebuild, rescan/SBOM/findings comparison |
| 6. UI and demo | Implemented | Six real-data views, architecture visualization, controlled fixture, browser approval/rebuild/rescan demo |

The supplied master prompt requests review after each milestone. All six milestones are complete. No milestones remain pending. No real credentials, commits, pushes, or external messages were used.

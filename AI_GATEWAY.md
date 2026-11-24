# AI gateway

Milestone 4 implements `guardian/ai.py`: one gateway shared by finding explanations, non-CVE signal review, and remediation notes. Deterministic analysis remains authoritative. Provider notes are interpretations and cannot add findings, change scores, or approve actions.

## Configure four project keys

Copy `.env.example` to `.env` in Guardian's project root and fill the four `GEMINI_API_KEY_1` through `GEMINI_API_KEY_4` fields locally. Keep real keys out of chat, source, scanned repositories, and browser forms. `.env` files are ignored. Environment variables override file values. The loader supports literal values with optional surrounding quotes; it does not execute shell syntax, expand variables, or follow a symlinked environment file. New jobs and settings requests reload configuration without restarting the server. Invalid configuration disables provider calls and exposes a generic error.

Use distinct `GEMINI_KEY_n_PROJECT` labels only for genuinely independent quota groups. Repeated or blank labels share one group. Duplicate credential values are deduplicated even when labels differ. Labels are operator-supplied; the gateway cannot verify project ownership or provider eligibility.

The preferred model remains `gemini-2.5-flash` as requested. Fallback order is `gemini-3.8-flash`, then `gemini-3.5-flash-lite`. Google's documentation checked November 24, 2026 lists those fallbacks and restricts 2.5 Flash access to existing users. It also documents automatic routing of 2.5 Flash to 3.5 Flash-Lite from December 1, 2026. Listing does not establish generation access, billing eligibility, or remaining quota. [Official model documentation](https://aistudio.google.com/docs/models).

## Routing and limits

The flow is compact validated JSON → compatible cache lookup → atomic budget/rate reservation → eligible Gemini project/model → optional loopback Ollama → schema validation → validated cache entry or labeled deterministic template.

Defaults are three provider attempts per scan, thirty API requests per UTC day shared across scans, and twelve seconds between requests. Failed requests, credential/model failover, and repair attempts consume budget. Cache hits and templates consume none. SQLite counters, rate reservations, quota-group cooldowns, and cached explanations persist across restarts. Legacy job budgets survive the additive schema 1 to 2 upgrade. Existing job caps remain binding if configuration later increases its per-scan allowance.

On 429, the gateway honors Retry-After seconds or dates and supplied RetryInfo delays, then persists a cooldown for the entire configured group. It never changes models or rotates credentials within that group to bypass a 429. Another eligible independent project can be tried only within remaining budgets. Authentication failures may use another credential in the same group. Model fallback occurs for 404/410/503 unavailability responses or an explicit model-deprecation/unavailability error; other bad requests use templates. There are no uncontrolled retries.

The three-attempt default can end before all four key slots or local fallback are attempted. This is budget enforcement, not evidence that every key failed. Each explanation task has a forty-five-second total window, twenty-second maximum HTTP request duration, and 256 KiB response limit. Shared rate limiting may leave later tasks using templates. Actual model metadata reported by Gemini is retained; when absent, the requested model is recorded with `model_reported: false`.

## Payload and output boundaries

Each task sends only validated finding IDs, evidence IDs, recognized advisory IDs, finding type, deterministic score/confidence, severity category, package reachability, and optional deterministic option codes. It sends no source files, package commands, titles, URLs, repository contents, credentials, or arbitrary user text. Import evidence enters the payload as IDs only. Credentials appear only in the `x-goog-api-key` header to the fixed Gemini host.

Pydantic schemas reject extra fields, unknown/duplicate finding IDs, invalid evidence references, unexpected advisory IDs, credential-shaped text, links, code fences, and unprovided semantic versions. One repair is allowed within the same budgets; invalid generated text is never reflected into the repair request. A second invalid result becomes a template. This checks structure and references, not the semantic truth of all prose. Every provider note remains labeled and untrusted.

Validated provider results are cached by prompt/schema version, task, compact payload, and model policy. Entries preserve actual/requested model, provider, usage when supplied, and prompt version. Cache hits retain original provenance. Templates are not cached, allowing later credential setup to produce provider notes. Compatible cached notes can replay without keys or network calls, including when generation is disabled. Changed discovery/detection/import evidence changes payload IDs and invalidates the relevant cache entry.

## Optional Ollama

Ollama is disabled by default. Enable `AI_LOCAL_ENABLED=true` and set `OLLAMA_MODEL` only after configuring it yourself. `OLLAMA_BASE_URL` must be an explicit HTTP loopback host and port, defaulting to `http://127.0.0.1:11434`. No model is downloaded automatically. Local generation runs only after eligible Gemini attempts fail or are unavailable and only if budget remains. Local attempts and their possible single repair share the same counters and validation. Local failure also produces a template.

## Tasks and app controls

Analysis batches up to ten highest-priority findings into `explain` and five non-vulnerability signals into `review`. Analysis does not create patches. Remediation invokes `fix_notes` after deterministic recommendations exist, supplying only allowlisted option categories alongside finding facts. AI never selects versions or edits files. Notes and usage live in remediation_report.json and the final audit report; all three tasks share existing scan/daily limits. No candidates are invented to fill an AI call.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/ai/status` | Safe configured-slot/group status, cooldowns, budgets, cache count, sanitized events |
| POST | `/api/ai/check-models` | On-demand metadata GETs; never a generation-access or quota test |
| POST | `/api/scans/{id}/analyze` | Queue source analysis, priorities, and optional explanations |
| GET | `/api/scans/{id}/analysis` | Progress/report; marks results stale after detection changes |
| GET | `/api/scans/{id}/ai-notes` | Task provenance, calls, cache hits, templates, and persistent usage |

The dashboard exposes these controls inside Detection & evidence. Startup performs no provider metadata or generation request. Metadata checks share the daily counter and limiter, have a bounded request window, and can report unchecked/unavailable models when limits prevent completion. Metadata attempts have a separate daily settings cap and do not consume a scan's generation allowance. Settings never return keys, key suffixes, or credential hashes.

## Verification and current access

Tests cover shared/distinct quota groups, missing labels, duplicate credentials, auth failover, model fallback/deprecation, malformed JSON, one repair, unknown references, unsafe payloads, cache replay, daily/scan/rate caps, four-key-to-local ordering, host/response limits, and SQLite upgrade preservation.

No Gemini keys are configured in this workspace. The controlled end-to-end fixture used real source/OSV evidence and labeled templates with zero Gemini requests. Generation access, actual Google billing/quota behavior, and a live Ollama server have not been verified. Routing and response handling are verified with synthetic HTTP transports. [GenerateContent reference](https://aistudio.google.com/api-reference/generate-content), [structured-output reference](https://aistudio.google.com/docs/structured-output).

Milestone 5 adds no credential requirement. The controlled live fixture used three labeled template tasks and zero generation requests. SQLite schema 3 preserves all existing gateway tables and counters while adding immutable patch reviews.

## Demo cache and report replay

Milestone 6 adds `python -m guardian.demo --data data/scans --warm-cache SCAN_ID`. The command validates the current plan, reconstructs the exact explain/review/fix_notes payloads, and calls the ordinary gateway. It shares existing rate, scan and daily budgets. Actual validated Gemini/Ollama results can warm the cache; cache hits replay across matching task inputs. Empty tasks remain not_needed. Missing credentials use templates, which are never cached as AI. The command saves its observed tasks and usage in the scan's demo_cache.json without overwriting approvals or patch bytes.

The six-view UI displays saved provider/model/cache/template provenance, saved task request/cache/fallback counters, safe four-slot configuration, and daily limits. Opening history, reports, or a saved demo does not trigger generation or model checks. Metadata checks remain explicit on-demand actions. Synthetic tests prove warming and replay with zero subsequent HTTP requests. Live milestone 6 used three templates, zero provider requests and zero AI cache hits because real credentials are not configured; no synthetic notes are presented as real generation.

## Cached Qwen without Ollama

The current machine has complete Qwen/Qwen3-0.6B Transformers weights, while the Qwen2.5-1.5B cache is incomplete. `guardian.local_model` provides the existing Ollama-compatible `/api/chat` protocol using cached weights only, with `local_files_only=True` and `trust_remote_code=False`. It does not install Ollama, download Gemma, or contact Hugging Face. Launch it manually using the Torch/Transformers interpreter documented in README. The legacy provider label `ollama` identifies the compatible protocol; the actual model remains Qwen/Qwen3-0.6B and the local response records backend transformers_cached. Gemini 2.5 Flash remains primary, and local calls still obey shared gateway budgets and schema checks. No live Gemini or Qwen generation was tested during key configuration at the user's request.

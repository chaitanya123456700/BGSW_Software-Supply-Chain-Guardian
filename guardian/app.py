import json
import re
import threading
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .files import write_json
from .ingestion import validate_repository_url
from .models import DetectionRequest, Inventory, PipelineRequest, ScanRequest, PatchReviewRequest, ValidationRequest, RemediationSelectionRequest, RepositoryValidationRequest
from .graph import build_graph
from .pipeline import now, scan_repository
from .process import WORKSPACE
from .phase2 import run_detection
from .orchestrator import ACTIVE, JobConflict, JobStore, Orchestrator
from .ai import AIConfig, AIGateway
from .analysis import run_analysis
from .remediation import checkout_target, digest, run_remediation, reviews, review_plan, snapshot, source, verify_plan
from .validation import run_validation
from .demo import DEMO_URL
from .remediation_preview import apply_selection, draft_plan, export_zip
from .repository_validation import run_repository_validation


def create_app(data_directory: Path | None = None, *, osv_transport=None, deps_transport=None, metadata_transport=None, ai_config=None, ai_transport=None) -> FastAPI:
    data = data_directory or WORKSPACE / "data/scans"
    slots = threading.BoundedSemaphore(3)
    detection_jobs = set()
    analysis_jobs = set()
    remediation_jobs = set()
    detection_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        data.mkdir(parents=True, exist_ok=True)
        app.state.jobs = JobStore(data / "guardian.sqlite3")
        app.state.jobs.recover()
        app.state.orchestrator = Orchestrator(app.state.jobs, data, osv_transport=osv_transport,
                                            deps_transport=deps_transport, metadata_transport=metadata_transport,
                                            ai_config=ai_config, ai_transport=ai_transport)
        for status_path in data.glob("*/status.json"):
            try:
                status = json.loads(status_path.read_text())
                if status["status"] in {"queued", "running"}:
                    status.update(status="failed", stage="Interrupted by application restart", finished_at=now())
                    write_json(status_path, status)
            except (ValueError, KeyError):
                continue
        for status_path in data.glob("*/artifacts/detection_status.json"):
            state = json.loads(status_path.read_text())
            if state.get("status") in {"queued", "running"}:
                state.update(status="failed", stage="Detection interrupted by application restart")
                write_json(status_path, state)
        for status_path in [*data.glob("*/artifacts/analysis_status.json"), *data.glob("*/artifacts/remediation_status.json"), *data.glob("*/artifacts/validation_status.json"), *data.glob("*/artifacts/repository_validation_status.json")]:
            state = json.loads(status_path.read_text())
            if state.get("status") in {"queued", "running"}:
                state.update(status="failed", stage="Analysis interrupted by application restart")
                write_json(status_path, state)
        app.state.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guardian-scan")
        yield
        app.state.executor.shutdown(wait=True, cancel_futures=False)

    app = FastAPI(title="Bosch Software Supply Chain Guardian", version="0.1.0", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])
    static = Path(__file__).with_name("static")
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.middleware("http")
    async def local_browser_guard(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method == "POST" and origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Cross-origin scan requests are blocked"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        return response

    def directory(scan_id):
        if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
            raise HTTPException(404, "Scan not found")
        path = data / scan_id
        if not (path / "status.json").is_file():
            raise HTTPException(404, "Scan not found")
        return path

    def execute(scan_id, repo_url):
        path = data / scan_id
        status = {"scan_id": scan_id, "repo_url": repo_url, "status": "running", "started_at": now()}

        def update(stage):
            status["stage"] = stage
            write_json(path / "status.json", status)

        try:
            update("Starting scan")
            report = scan_repository(repo_url, path, update, **({"deps_transport": deps_transport} if deps_transport is not None else {}))
            status.update(status=report["status"], stage="Discovery finished", finished_at=now(), commit=report.get("repository", {}).get("commit"))
        except Exception as exc:
            status.update(status="failed", stage="Scan failed", error=str(exc)[:3000], finished_at=now())
            write_json(path / "artifacts/discovery_report.json", {
                "status": "failed", "errors": [status["error"]], "repository": {"url": repo_url}, "finished_at": now()})
        finally:
            try:
                write_json(path / "status.json", status)
            finally:
                slots.release()

    @app.get("/")
    def dashboard():
        return FileResponse(static / "index.html")

    @app.get("/health")
    def health():
        return {"status": "ok", "phase": 1}

    def ai_gateway():
        return AIGateway(app.state.jobs, ai_config or AIConfig.load(), transport=ai_transport)

    @app.get("/api/ai/status")
    def ai_status():
        result = ai_gateway().status()
        with app.state.jobs.connection() as db:
            result["recent_events"] = [json.loads(row[0]) for row in db.execute("SELECT event FROM ai_events ORDER BY id DESC LIMIT 30")]
        return result

    @app.post("/api/ai/check-models")
    def check_ai_models():
        return {"models": ai_gateway().check_models(), "note": "Metadata listing only; generation access and quota remain unchecked"}

    def pipeline_job(scan_id):
        directory(scan_id)
        try:
            return app.state.jobs.get(scan_id)
        except KeyError as exc:
            raise HTTPException(404, "No orchestrated pipeline exists for this scan") from exc

    def submit_pipeline(scan_id):
        def execute_pipeline():
            try:
                app.state.orchestrator.run(scan_id)
            finally:
                slots.release()
        try:
            app.state.executor.submit(execute_pipeline)
        except Exception:
            slots.release()
            app.state.jobs.change(scan_id, lambda state: state.update(status="failed", stage="Worker submission failed"))
            raise

    @app.get("/api/pipelines")
    def list_pipelines():
        return {"pipelines": app.state.jobs.list()}

    @app.post("/api/demo", status_code=202)
    def start_demo():
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "Scan/pipeline capacity reached")
        scan_id = uuid.uuid4().hex
        try:
            (data / scan_id / "artifacts").mkdir(parents=True)
            state = app.state.jobs.create(scan_id, DEMO_URL, max_ai_calls=(ai_config or AIConfig.load()).max_calls)
            write_json(data / scan_id / "status.json", {"scan_id": scan_id, "repo_url": DEMO_URL,
                       "status": "queued", "stage": "Waiting for controlled demo"})
        except Exception:
            slots.release()
            raise
        submit_pipeline(scan_id)
        return {**state, "controlled_fixture": True, "providers": "live", "approval": "required"}

    @app.get("/api/scans")
    def scan_history():
        rows = []
        for path in data.glob("*/status.json"):
            if not re.fullmatch(r"[0-9a-f]{32}", path.parent.name):
                continue
            try:
                state = json.loads(path.read_text())
                rows.append({"scan_id": path.parent.name, "repo_url": state.get("repo_url", "Repository scan"),
                    "status": state.get("pipeline_status", state.get("status", "unknown")), "commit": state.get("commit"),
                    "updated_at": state.get("updated_at", state.get("finished_at", state.get("created_at"))),
                    "modified": path.stat().st_mtime, "controlled_fixture": state.get("repo_url") == DEMO_URL})
            except (OSError, ValueError):
                continue
        return {"scans": sorted(rows, key=lambda row: row["modified"], reverse=True)[:100]}

    @app.get("/api/scans/{scan_id}/summary")
    def scan_summary(scan_id: str):
        path = directory(scan_id)
        result = {"scan_id": scan_id, "available_artifacts": [], "warnings": [], "controlled_fixture": (path / "demo.json").is_file()}
        for key, filename in [("discovery", "discovery_report.json"), ("detection", "detection_report.json"),
                              ("analysis", "analysis_report.json"), ("remediation", "remediation_report.json"), ("validation", "validation_report.json")]:
            report_file = path / "artifacts" / filename
            if report_file.exists():
                try:
                    report = json.loads(report_file.read_text())
                    result[key] = {"status": report.get("status"), "finished_at": report.get("finished_at")}
                    result[key]["warnings_count"] = len(report.get("warnings", []))
                    result["warnings"].extend(report.get("errors", []))
                    if key == "discovery":
                        result.update(repository=report.get("repository"), statistics=report.get("statistics"), coverage=report.get("coverage_status"), sbom=report.get("sbom", {}).get("status"))
                    if key == "detection":
                        result.update(advisories=(report.get("verified_vulnerabilities", 0) + report.get("verified_malicious_packages", 0)), signals=report.get("review_signals", 0), policy=report.get("policy_status"), evidence_count=report.get("evidence_count", 0))
                    if key == "analysis":
                        result["analysis_ai"] = report.get("ai")
                        result[key].update(findings_count=len(report.get("findings", [])), reachability=report.get("reachability_summary", {}))
                    if key == "remediation":
                        result["remediation_ai"] = {"task": report.get("ai"), "usage": report.get("ai_usage")}
                        proposals = report.get("proposals", [])
                        decisions = reviews(app.state.jobs, scan_id)
                        result[key].update(proposals_count=len(proposals),
                            manual_review_count=sum(item.get("status") == "manual_review" for item in report.get("recommendations", [])),
                            pending_review_count=sum(item["id"] not in decisions for item in proposals),
                            approved_count=sum(decisions.get(item["id"], {}).get("decision") == "approve" for item in proposals))
                    if key == "validation": result["validation"]["results"] = report.get("results", [])
                except (ValueError, OSError):
                    result["warnings"].append(f"Unreadable {key} report")
        for artifact, filename in artifacts.items():
            if (path / "artifacts" / filename).is_file() and (artifact != "sbom" or result.get("sbom") == "completed"):
                result["available_artifacts"].append(artifact)
        if result.get("analysis") and analysis_state(path).get("status") == "stale":
            result["analysis"]["status"] = "stale"
        if result.get("remediation"):
            try:
                verify_plan(path)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                result["remediation"]["status"] = "stale"
                if result.get("validation"):
                    result["validation"] = {"status": "stale", "results": []}
                result["warnings"].append(str(exc))
        if (path / "artifacts/repository_validation_status.json").is_file():
            applied = repository_validation_state(scan_id)
            if applied.get("report"):
                result["repository_validation"] = {**applied["report"], "status": applied["status"]}
        return result

    @app.post("/api/pipelines", status_code=202)
    def start_pipeline(body: PipelineRequest):
        try:
            url = validate_repository_url(body.repo_url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "Scan/pipeline capacity reached")
        scan_id = uuid.uuid4().hex
        try:
            (data / scan_id / "artifacts").mkdir(parents=True)
            state = app.state.jobs.create(scan_id, url, body.baseline_commit, max_ai_calls=(ai_config or AIConfig.load()).max_calls)
            write_json(data / scan_id / "status.json", {"scan_id": scan_id, "repo_url": url,
                       "status": "queued", "stage": "Waiting for pipeline worker"})
        except Exception:
            slots.release()
            raise
        submit_pipeline(scan_id)
        return {**state, "status_url": f"/api/scans/{scan_id}/pipeline"}

    @app.get("/api/scans/{scan_id}/pipeline")
    def get_pipeline(scan_id: str):
        return pipeline_job(scan_id)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_pipeline(scan_id: str):
        pipeline_job(scan_id)
        try:
            return app.state.jobs.cancel(scan_id)
        except JobConflict as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/scans/{scan_id}/resume", status_code=202)
    def resume_pipeline(scan_id: str, body: ValidationRequest | None = None):
        pipeline_job(scan_id)
        with detection_lock:
            if scan_id in detection_jobs or scan_id in analysis_jobs or scan_id in remediation_jobs:
                raise HTTPException(409, "Detection is already active for this scan")
            if not slots.acquire(blocking=False):
                raise HTTPException(429, "Scan/pipeline capacity reached")
            try:
                state = app.state.jobs.resume(scan_id, run_tests=body.run_tests if body else False)
            except JobConflict as exc:
                slots.release()
                raise HTTPException(409, str(exc)) from exc
            except Exception:
                slots.release()
                raise
        submit_pipeline(scan_id)
        return state

    @app.post("/api/scans", status_code=202)
    def start_scan(body: ScanRequest):
        try:
            url = validate_repository_url(body.repo_url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "Scan capacity reached: one running and two queued scans. Try again later.")
        scan_id = uuid.uuid4().hex
        path = data / scan_id
        try:
            (path / "artifacts").mkdir(parents=True)
            write_json(path / "status.json", {"scan_id": scan_id, "repo_url": url, "status": "queued",
                                              "stage": "Waiting for scan worker", "created_at": now()})
            app.state.executor.submit(execute, scan_id, url)
        except Exception:
            slots.release()
            raise
        return {"scan_id": scan_id, "status": "queued", "status_url": f"/api/scans/{scan_id}"}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        return json.loads((directory(scan_id) / "status.json").read_text())

    artifacts = {"graph": "dependency_graph.json", "sbom": "sbom.json", "report": "discovery_report.json",
                 "components": "components.json", "vulnerabilities": "vulnerabilities.json",
                 "suspicious-changes": "suspicious_changes.json", "detection-report": "detection_report.json", "evidence": "evidence/index.json",
                 "discovery-evidence": "discovery/evidence/index.json", "static-signals": "static_signals.json",
                 "analysis-report": "analysis_report.json", "reachability": "reachability.json", "risk-scores": "risk_scores.json",
                 "ai-notes": "ai_notes.json", "analysis-evidence": "analysis/evidence/index.json",
                 "remediation-report": "remediation_report.json", "remediation-evidence": "remediation/evidence/index.json",
                 "validation-report": "validation_report.json", "verified-report": "verified_report.json"}

    @app.get("/api/scans/{scan_id}/discovery-evidence/{evidence_id}")
    def get_discovery_evidence(scan_id: str, evidence_id: str):
        path = directory(scan_id) / "artifacts/discovery/evidence"
        index_path = path / "index.json"
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
        record = index.get(evidence_id)
        if not record or not re.fullmatch(r"evidence:[0-9a-f]{24}", evidence_id):
            raise HTTPException(404, "Discovery evidence not found")
        raw = (path / Path(record["raw_artifact"]).name).read_text()
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        return {"metadata": record, "raw_data": body}

    @app.post("/api/scans/{scan_id}/detect", status_code=202)
    def start_detection(scan_id: str, body: DetectionRequest):
        path = directory(scan_id)
        if json.loads((path / "status.json").read_text())["status"] in {"queued", "running", "failed"}:
            raise HTTPException(409, "Finish a usable Phase 1 scan before detection")
        if not all((path / "artifacts" / name).is_file() for name in ["components.json", "dependency_graph.json", "discovery_report.json"]):
            raise HTTPException(409, "Phase 1 artifacts are unavailable")
        with detection_lock:
            try:
                pipeline = app.state.jobs.get(scan_id)
            except KeyError:
                pipeline = None
            if pipeline and pipeline["status"] in ACTIVE:
                raise HTTPException(409, "The orchestrator owns detection while this pipeline is active")
            if scan_id in detection_jobs or scan_id in analysis_jobs or scan_id in remediation_jobs:
                raise HTTPException(409, "Detection is already queued or running for this scan")
            if not slots.acquire(blocking=False):
                raise HTTPException(429, "Scan/detection capacity reached")
            detection_jobs.add(scan_id)
        state_path = path / "artifacts/detection_status.json"
        state = {"scan_id": scan_id, "status": "queued", "stage": "Waiting for detection worker"}
        write_json(state_path, state)

        def execute_detection():
            def update(stage):
                state.update(status="running", stage=stage)
                write_json(state_path, state)
            try:
                report = run_detection(path, body.baseline_commit, transport=osv_transport,
                                       metadata_transport=metadata_transport, update=update)
                state.update(status=report["status"], stage="Detection finished", finished_at=report["finished_at"])
            except Exception as exc:
                state.update(status="failed", stage="Detection failed", error=str(exc)[:2000])
            finally:
                try:
                    write_json(state_path, state)
                finally:
                    with detection_lock:
                        detection_jobs.discard(scan_id)
                    slots.release()
        try:
            app.state.executor.submit(execute_detection)
        except Exception:
            with detection_lock:
                detection_jobs.discard(scan_id)
            slots.release()
            raise
        return state

    @app.get("/api/scans/{scan_id}/detection")
    def get_detection(scan_id: str):
        path = directory(scan_id) / "artifacts"
        state_path = path / "detection_status.json"
        if not state_path.exists():
            return {"status": "not_started", "stage": "Phase 2 detection has not run"}
        state = json.loads(state_path.read_text())
        report_path = path / "detection_report.json"
        if state["status"] not in {"queued", "running"} and report_path.exists():
            state["report"] = json.loads(report_path.read_text())
        return state

    def analysis_state(path):
        artifacts_path = path / "artifacts"
        state_file = artifacts_path / "analysis_status.json"
        if not state_file.exists():
            return {"status": "not_started", "stage": "Analysis has not run"}
        state = json.loads(state_file.read_text())
        report_file = artifacts_path / "analysis_report.json"
        detection_file = artifacts_path / "detection_report.json"
        detection_state_file = artifacts_path / "detection_status.json"
        detecting = json.loads(detection_state_file.read_text()).get("status") in {"queued", "running"} if detection_state_file.exists() else False
        if detecting:
            return {"status": "stale", "stage": "Detection is changing; rerun analysis after detection"}
        if state["status"] not in {"queued", "running"} and report_file.exists():
            report = json.loads(report_file.read_text())
            if report.get("detection_sha256") and (not detection_file.exists() or report["detection_sha256"] != hashlib.sha256(detection_file.read_bytes()).hexdigest()):
                return {"status": "stale", "stage": "Detection changed; rerun analysis"}
            state["report"] = report
        return state

    @app.get("/api/scans/{scan_id}/analysis")
    def get_analysis(scan_id: str):
        return analysis_state(directory(scan_id))

    @app.post("/api/scans/{scan_id}/analyze", status_code=202)
    def start_analysis(scan_id: str):
        path = directory(scan_id)
        report_file = path / "artifacts/detection_report.json"
        if not report_file.exists() or json.loads(report_file.read_text()).get("status") not in {"completed", "partial"}:
            raise HTTPException(409, "Finish a usable detection scan before analysis")
        with detection_lock:
            try:
                pipeline = app.state.jobs.get(scan_id)
            except KeyError:
                pipeline = None
            if pipeline and pipeline["status"] in ACTIVE or scan_id in detection_jobs or scan_id in analysis_jobs or scan_id in remediation_jobs:
                raise HTTPException(409, "A pipeline, detection, or analysis job already owns this scan")
            if not slots.acquire(blocking=False):
                raise HTTPException(429, "Scan/analysis capacity reached")
            analysis_jobs.add(scan_id)
        state_path = path / "artifacts/analysis_status.json"
        state = {"scan_id": scan_id, "status": "queued", "stage": "Waiting for analysis worker"}
        try:
            write_json(state_path, state)
            def execute_analysis():
                def update(stage):
                    state.update(status="running", stage=stage)
                    write_json(state_path, state)
                try:
                    report = run_analysis(path, app.state.jobs, config=ai_config or AIConfig.load(), ai_transport=ai_transport, update=update)
                    state.update(status=report["status"], stage="Analysis finished", finished_at=report["finished_at"])
                except Exception:
                    state.update(status="failed", stage="Analysis failed")
                finally:
                    try:
                        write_json(state_path, state)
                    finally:
                        with detection_lock:
                            analysis_jobs.discard(scan_id)
                        slots.release()
            app.state.executor.submit(execute_analysis)
        except Exception:
            with detection_lock:
                analysis_jobs.discard(scan_id)
            slots.release()
            raise
        return state

    def remediation_busy(scan_id):
        try:
            active = app.state.jobs.get(scan_id)["status"] in ACTIVE
        except KeyError:
            active = False
        return active or scan_id in detection_jobs or scan_id in analysis_jobs or scan_id in remediation_jobs

    def remediation_state(scan_id, name):
        path = directory(scan_id) / "artifacts"
        state_path = path / f"{name}_status.json"
        if not state_path.exists():
            return {"status": "not_started", "stage": f"{name} has not run"}
        state = json.loads(state_path.read_text())
        if state["status"] not in {"queued", "running", "failed"}:
            try:
                plan = verify_plan(directory(scan_id))
                state["report"] = plan if name == "remediation" else json.loads((path / "validation_report.json").read_text())
                state["reviews"] = reviews(app.state.jobs, scan_id)
                if name == "validation" and state["report"].get("plan_sha256") != hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest():
                    return {"status": "stale", "stage": "Remediation changed; rerun validation"}
            except (ValueError, OSError, KeyError) as exc:
                return {"status": "stale", "stage": str(exc)}
        return state

    @app.get("/api/scans/{scan_id}/remediation")
    def get_remediation(scan_id: str):
        return remediation_state(scan_id, "remediation")

    @app.get("/api/scans/{scan_id}/validation")
    def get_validation(scan_id: str):
        return remediation_state(scan_id, "validation")

    def submit_remediation(scan_id, name, run_tests=False):
        path = directory(scan_id)
        with detection_lock:
            if remediation_busy(scan_id):
                raise HTTPException(409, "Another stage owns this scan")
            if name == "validation":
                try:
                    plan = verify_plan(path)
                    decisions = reviews(app.state.jobs, scan_id)
                    if any(p["id"] not in decisions for p in plan["proposals"]):
                        raise ValueError("Review every exact diff before validation")
                except (ValueError, OSError, KeyError) as exc:
                    raise HTTPException(409, str(exc)) from exc
            elif analysis_state(path).get("report", {}).get("status") not in {"completed", "partial"}:
                raise HTTPException(409, "Fresh usable analysis is required")
            if not slots.acquire(blocking=False):
                raise HTTPException(429, "Worker capacity reached")
            remediation_jobs.add(scan_id)
        state = {"status": "queued", "stage": f"Waiting for {name} worker"}
        state_path = path / f"artifacts/{name}_status.json"
        def execute_remediation():
            def update(stage):
                state.update(status="running", stage=stage)
                write_json(state_path, state)
            try:
                if name == "remediation":
                    report = run_remediation(path, app.state.jobs, osv_transport=osv_transport, metadata_transport=metadata_transport,
                                             config=ai_config or AIConfig.load(), ai_transport=ai_transport, update=update)
                else:
                    report = run_validation(path, app.state.jobs, osv_transport=osv_transport, metadata_transport=metadata_transport,
                                            run_tests=run_tests, update=update)
                state.update(status=report["status"], stage=f"{name} finished")
            except Exception as exc:
                state.update(status="failed", stage=f"{name} failed", error=str(exc)[:1000])
            finally:
                try:
                    write_json(state_path, state)
                finally:
                    with detection_lock:
                        remediation_jobs.discard(scan_id)
                    slots.release()
        try:
            write_json(state_path, state)
            app.state.executor.submit(execute_remediation)
        except Exception:
            with detection_lock:
                remediation_jobs.discard(scan_id)
            slots.release()
            raise
        return state

    @app.post("/api/scans/{scan_id}/remediate", status_code=202)
    def start_remediation(scan_id: str):
        return submit_remediation(scan_id, "remediation")

    @app.get("/api/scans/{scan_id}/remediation-preview")
    def get_remediation_preview(scan_id: str):
        try:
            return draft_plan(directory(scan_id))[0]
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/scans/{scan_id}/remediation-preview")
    def select_remediation_preview(scan_id: str, body: RemediationSelectionRequest):
        try:
            return apply_selection(directory(scan_id), body.digest, body.selected)[0]
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/scans/{scan_id}/repository-validation")
    def repository_validation_state(scan_id: str):
        state_path = directory(scan_id) / "artifacts/repository_validation_status.json"
        if not state_path.exists():
            return {"status": "not_started", "stage": "Repository changes have not been applied"}
        state = json.loads(state_path.read_text())
        report = state.get("report", {})
        if report.get("applied"):
            try:
                if digest(snapshot(checkout_target(directory(report["scan_id"]))[1])) != report["after_sha256"]:
                    state.update(status="stale", stage="The local repository changed after this validation; run a fresh scan")
            except (ValueError, OSError, KeyError):
                state.update(status="stale", stage="The applied checkout is no longer available for verification")
        return state

    @app.get("/api/scans/{scan_id}/repository-validation/report")
    def repository_validation_report(scan_id: str):
        path = directory(scan_id) / "artifacts/repository_validation_report.json"
        if not path.is_file():
            raise HTTPException(404, "Repository validation report is not available")
        return FileResponse(path, media_type="application/json", filename="repository-validation.json")

    @app.post("/api/scans/{scan_id}/repository-validation", status_code=202)
    def start_repository_validation(scan_id: str, body: RepositoryValidationRequest):
        path = directory(scan_id)
        if not body.reviewed_changes or not body.selected:
            raise HTTPException(409, "Explicit review of the selected changes is required before updating the local checkout")
        with detection_lock:
            if remediation_busy(scan_id):
                raise HTTPException(409, "Another stage owns this scan")
            try:
                selection, _ = apply_selection(path, body.digest, body.selected)
                if selection["validation"].get("receipt_sha256") != body.receipt:
                    raise ValueError("The reviewed draft changed; preview and review it again")
            except (ValueError, OSError, KeyError) as exc:
                raise HTTPException(409, str(exc)) from exc
            if not slots.acquire(blocking=False):
                raise HTTPException(429, "Worker capacity reached")
            remediation_jobs.add(scan_id)
        state = {"status": "queued", "stage": "Waiting to apply reviewed changes and rescan the local repository"}
        status_path = path / "artifacts/repository_validation_status.json"
        write_json(status_path, state)

        def execute_repository_validation():
            def update(stage):
                state.update(status="running", stage=stage)
                write_json(status_path, state)
            try:
                report = run_repository_validation(path, body.digest, body.selected, body.receipt, run_tests=body.run_tests,
                    osv_transport=osv_transport, metadata_transport=metadata_transport, update=update)
                state.update(status=report["status"], stage="Repository remediation and rescan finished", report=report)
            except Exception as exc:
                state.update(status="failed", stage="Repository validation failed", error=str(exc)[:2000])
            finally:
                try:
                    write_json(status_path, state)
                finally:
                    with detection_lock:
                        remediation_jobs.discard(scan_id)
                    slots.release()
        try:
            app.state.executor.submit(execute_repository_validation)
        except Exception:
            with detection_lock:
                remediation_jobs.discard(scan_id)
            slots.release()
            state.update(status="failed", stage="Worker submission failed")
            write_json(status_path, state)
            raise
        return state

    @app.get("/api/scans/{scan_id}/remediation-preview/download")
    def download_remediation_preview(scan_id: str, digest: str = Query(pattern=r"^[0-9a-f]{64}$"),
                                     selected: str = Query(default="", max_length=7000), file: str | None = Query(default=None, max_length=1000)):
        try:
            identifiers = selected.split(",") if selected else []
            if not identifiers or len(identifiers) > 100:
                raise ValueError("Apply at least one remedy before downloading")
            selection, full_diff = apply_selection(directory(scan_id), digest, identifiers)
            if file == "guardian-draft-validation.json":
                return JSONResponse(selection["validation"], headers={
                    "Content-Disposition": 'attachment; filename="guardian-draft-validation.json"', "Cache-Control": "no-store"})
            if file is not None:
                item = next((item for item in selection["files"] if item["path"] == file), None)
                if item is None:
                    raise ValueError("File is not part of the selected changes")
                return Response(item["content"].encode(), media_type="application/json",
                                headers={"Content-Disposition": f'attachment; filename="{Path(file).name}"', "Cache-Control": "no-store"})
            return Response(export_zip(selection, full_diff), media_type="application/zip",
                            headers={"Content-Disposition": 'attachment; filename="guardian-selected-changes.zip"', "Cache-Control": "no-store"})
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/scans/{scan_id}/validate", status_code=202)
    def start_validation(scan_id: str, body: ValidationRequest):
        return submit_remediation(scan_id, "validation", body.run_tests)

    @app.get("/api/scans/{scan_id}/remediation/{proposal_id}/diff")
    def proposal_diff(scan_id: str, proposal_id: str):
        try:
            plan = verify_plan(directory(scan_id))
            if not any(p["id"] == proposal_id for p in plan["proposals"]):
                raise ValueError("Proposal not found")
            return FileResponse(directory(scan_id) / f"artifacts/remediation/proposals/{proposal_id}/patch.diff", media_type="text/plain", filename="patch.diff")
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/scans/{scan_id}/remediation/{proposal_id}/decision")
    def patch_decision(scan_id: str, proposal_id: str, body: PatchReviewRequest):
        path = directory(scan_id)
        with detection_lock:
            if remediation_busy(scan_id):
                raise HTTPException(409, "Another stage owns this scan")
            try:
                return review_plan(path, app.state.jobs, proposal_id, proposal_digest=body.digest, decision=body.decision,
                                   reviewed_diff=body.reviewed_diff, reason=body.reason)
            except (ValueError, OSError, KeyError) as exc:
                raise HTTPException(409, str(exc)) from exc

    @app.get("/api/scans/{scan_id}/remediation-evidence/{evidence_id}")
    def get_remediation_evidence(scan_id: str, evidence_id: str):
        path = directory(scan_id) / "artifacts/remediation/evidence"
        try:
            records = json.loads((path / "index.json").read_text())
            if not re.fullmatch(r"evidence:[0-9a-f]{24}", evidence_id):
                raise KeyError(evidence_id)
            record = records[evidence_id]
            return {"metadata": record, "raw_data": json.loads((path / Path(record["raw_artifact"]).name).read_text())}
        except (OSError, KeyError, ValueError) as exc:
            raise HTTPException(404, "Remediation evidence not found") from exc

    @app.get("/api/scans/{scan_id}/validation/{result_id}/{artifact}")
    def validation_artifact(scan_id: str, result_id: str, artifact: str):
        allowed = {"sbom": "sbom.json", "components": "components.json", "graph": "dependency_graph.json",
                   "detection": "detection_report.json", "discovery": "discovery_report.json", "evidence": "evidence/index.json", "result": "validation_result.json"}
        if not re.fullmatch(r"[0-9a-f]{32}", result_id) or artifact not in allowed:
            raise HTTPException(404, "Validation artifact not found")
        path = directory(scan_id) / "artifacts/validation" / result_id / allowed[artifact]
        if not path.is_file():
            raise HTTPException(404, "Validation artifact not found")
        return FileResponse(path, media_type="application/json", filename=path.name)

    @app.get("/api/scans/{scan_id}/analysis-evidence/{evidence_id}")
    def get_analysis_evidence(scan_id: str, evidence_id: str):
        path = directory(scan_id) / "artifacts/analysis/evidence"
        index_file = path / "index.json"
        records = json.loads(index_file.read_text()) if index_file.exists() else {}
        if not re.fullmatch(r"evidence:[0-9a-f]{24}", evidence_id) or evidence_id not in records:
            raise HTTPException(404, "Analysis evidence not found")
        record = records[evidence_id]
        raw = (path / Path(record["raw_artifact"]).name).read_text(errors="replace")
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        return {"metadata": record, "raw_data": body}

    @app.get("/api/scans/{scan_id}/findings/{finding_id}")
    def get_finding(scan_id: str, finding_id: str):
        report_path = directory(scan_id) / "artifacts/detection_report.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        analysis = analysis_state(directory(scan_id)).get("report", {})
        if analysis.get("status") in {"completed", "partial"}:
            report = analysis
        finding = next((finding for finding in report.get("findings", []) if finding["finding_id"] == finding_id), None)
        if finding is None:
            raise HTTPException(404, "Finding not found")
        return finding

    @app.get("/api/scans/{scan_id}/evidence/{evidence_id}")
    def get_evidence(scan_id: str, evidence_id: str):
        path = directory(scan_id) / "artifacts/evidence"
        index_path = path / "index.json"
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
        record = index.get(evidence_id)
        if not record or not re.fullmatch(r"evidence:[0-9a-f]{24}", evidence_id):
            raise HTTPException(404, "Evidence not found")
        raw = (path / Path(record["raw_artifact"]).name).read_text()
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        return {"metadata": record, "raw_data": body}

    @app.get("/api/scans/{scan_id}/{artifact}")
    def get_artifact(scan_id: str, artifact: str, project_id: str | None = None):
        path = directory(scan_id)
        if artifact not in artifacts:
            raise HTTPException(404, "Artifact not found")
        if artifact == "sbom":
            report_file = path / "artifacts/discovery_report.json"
            report = json.loads(report_file.read_text()) if report_file.exists() else {}
            if report.get("sbom", {}).get("status") != "completed":
                raise HTTPException(409, "A validated Syft SBOM is unavailable; inspect scan report")
        filename = path / "artifacts" / artifacts[artifact]
        if not filename.is_file():
            raise HTTPException(409, "Artifact is not available yet")
        if artifact == "graph" and project_id:
            inventory_path = path / "artifacts/components.json"
            try:
                inventory = Inventory.model_validate_json(inventory_path.read_bytes())
                graph = build_graph(inventory, project_id=project_id)
            except ValueError as exc:
                raise HTTPException(404, str(exc)) from exc
            return JSONResponse(graph, headers={"Content-Disposition": 'attachment; filename="project_dependency_graph.json"'})
        return FileResponse(filename, media_type="application/json", filename=filename.name)

    return app


app = create_app()

"""Persistent five-module orchestration over the existing discovery/detection tools."""
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .files import safe_file, write_json
from .pipeline import now, scan_repository, analyze_repository
from .demo import DEMO_URL, create_fixture
from .phase2 import DETECTION_VERSION, run_detection
from .process import SCAN_CANCEL_CHECK, ScanCancelled, WORKSPACE
from .analysis import ANALYSIS_VERSION, run_analysis
from .ai import AIConfig
from .remediation import run_remediation, reviews, verify_plan
from .validation import run_validation

STAGES = ("discover", "detect", "analyze", "remediate", "validate")
ACTIVE = {"queued", "running", "cancelling"}
IMPLEMENTED = set(STAGES)
ARTIFACTS = {
    "discover": ("components.json", "dependency_graph.json", "discovery_report.json"),
    "detect": ("vulnerabilities.json", "suspicious_changes.json", "static_signals.json", "detection_report.json", "evidence/index.json"),
    "analyze": ("analysis_report.json", "reachability.json", "risk_scores.json", "ai_notes.json", "analysis/evidence/index.json"),
    "remediate": ("remediation_report.json", "remediation/evidence/index.json"),
    "validate": ("validation_report.json", "verified_report.json"),
}


class JobConflict(ValueError):
    pass


class JobStore:
    """SQLite is authoritative; JSON files are immutable stage checkpoints."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1, 2, 3}:
                raise RuntimeError(f"Unsupported Guardian database schema: {version}")
            db.execute("CREATE TABLE IF NOT EXISTS jobs (scan_id TEXT PRIMARY KEY, state TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_daily (day TEXT PRIMARY KEY, requests INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_scan (scan_id TEXT PRIMARY KEY, requests INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_cache (cache_key TEXT PRIMARY KEY, result TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_cooldowns (quota_group TEXT PRIMARY KEY, until REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_rate (id INTEGER PRIMARY KEY CHECK(id=1), next_at REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS ai_events (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, event TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS remediation_reviews (scan_id TEXT NOT NULL, proposal_id TEXT NOT NULL, review TEXT NOT NULL, PRIMARY KEY(scan_id, proposal_id))")
            db.execute("PRAGMA user_version = 3")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, scan_id):
        with self.connection() as db:
            row = db.execute("SELECT state FROM jobs WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(scan_id)
        return json.loads(row[0])

    def list(self, limit=100):
        with self.connection() as db:
            rows = db.execute("SELECT state FROM jobs ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create(self, scan_id, repo_url, baseline_commit=None, max_ai_calls=3):
        state = {"schema_version": 1, "scan_id": scan_id, "repo_url": repo_url,
                 "baseline_commit": baseline_commit, "status": "queued", "stage": "Waiting for pipeline worker",
                 "created_at": now(), "updated_at": now(), "cancel_requested": False,
                 "ai_budget": {"max_calls": max_ai_calls, "calls": 0},
                 "modules": {name: {"status": "not_started", "attempts": 0} for name in STAGES}, "events": []}
        with self.connection() as db:
            db.execute("INSERT INTO jobs VALUES (?, ?)", (scan_id, json.dumps(state)))
        return state

    def change(self, scan_id, mutate):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM jobs WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None:
                raise KeyError(scan_id)
            state = json.loads(row[0])
            mutate(state)
            state["updated_at"] = now()
            db.execute("UPDATE jobs SET state = ? WHERE scan_id = ?", (json.dumps(state), scan_id))
        return state

    def recover(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for scan_id, raw in db.execute("SELECT scan_id, state FROM jobs").fetchall():
                state = json.loads(raw)
                if state["status"] in ACTIVE:
                    state.update(status="interrupted", stage="Application restarted; resume explicitly", updated_at=now())
                    state["events"].append({"at": now(), "event": "interrupted"})
                    for module in state["modules"].values():
                        if module["status"] == "running":
                            module["status"] = "interrupted"
                    db.execute("UPDATE jobs SET state = ? WHERE scan_id = ?", (json.dumps(state), scan_id))

    def cancel(self, scan_id):
        def mutate(state):
            if state["status"] not in ACTIVE:
                raise JobConflict("Only queued or running pipelines can be cancelled")
            state["cancel_requested"] = True
            state["status"] = "cancelled" if state["status"] == "queued" else "cancelling"
            state["stage"] = "Cancellation requested"
            state["events"].append({"at": now(), "event": "cancel_requested"})
        return self.change(scan_id, mutate)

    def resume(self, scan_id, *, run_tests=False):
        def mutate(state):
            if state["status"] not in {"failed", "interrupted", "cancelled", "blocked", "awaiting_approval", "completed"}:
                raise JobConflict("Pipeline is active or already completed")
            state.update(status="queued", cancel_requested=False, stage="Waiting to resume")
            state["validation_run_tests"] = run_tests
            state["events"].append({"at": now(), "event": "resume_requested"})
        return self.change(scan_id, mutate)

    def reserve_ai_call(self, scan_id, *, daily_limit=30, scan_limit=3):
        """Reserve before each provider attempt; unsuccessful requests still count."""
        return self.reserve_ai_attempt(scan_id, daily_limit=daily_limit, scan_limit=scan_limit)["allowed"]

    def reserve_ai_attempt(self, scan_id, *, daily_limit=30, scan_limit=3, interval=0):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM jobs WHERE scan_id = ?", (scan_id,)).fetchone()
            state = json.loads(row[0]) if row else None
            day = now()[:10]  # Provider usage accounting uses UTC calendar days.
            row = db.execute("SELECT requests FROM ai_daily WHERE day = ?", (day,)).fetchone()
            requests = row[0] if row else 0
            row = db.execute("SELECT requests FROM ai_scan WHERE scan_id = ?", (scan_id,)).fetchone()
            used = max(row[0] if row else 0, state["ai_budget"]["calls"] if state else 0)
            limit = min(scan_limit, state["ai_budget"]["max_calls"]) if state else scan_limit
            if state and state["cancel_requested"]:
                return {"allowed": False, "reason": "cancelled"}
            if used >= limit or requests >= daily_limit:
                return {"allowed": False, "reason": "budget_exhausted"}
            row = db.execute("SELECT next_at FROM ai_rate WHERE id=1").fetchone()
            if interval and row and row[0] > time.time():
                return {"allowed": False, "reason": "rate_limited", "retry_at": row[0]}
            db.execute("INSERT INTO ai_scan VALUES (?, ?) ON CONFLICT(scan_id) DO UPDATE SET requests=excluded.requests", (scan_id, used + 1))
            db.execute("INSERT INTO ai_rate VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET next_at=excluded.next_at", (time.time() + interval,))
            db.execute("INSERT INTO ai_daily VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET requests = requests + 1", (day,))
            if state:
                state["ai_budget"]["calls"] = used + 1
                state["updated_at"] = now()
                db.execute("UPDATE jobs SET state = ? WHERE scan_id = ?", (json.dumps(state), scan_id))
        return {"allowed": True}


class Orchestrator:
    def __init__(self, store: JobStore, data: Path, *, osv_transport=None, deps_transport=None, metadata_transport=None, ai_config=None, ai_transport=None):
        self.store, self.data, self.osv_transport = store, data, osv_transport
        self.deps_transport = deps_transport
        self.metadata_transport = metadata_transport
        self.ai_config, self.ai_transport = ai_config, ai_transport

    def check_cancel(self, scan_id):
        if self.store.get(scan_id)["cancel_requested"]:
            raise ScanCancelled("Pipeline cancelled")

    def checkpoint(self, scan_id, stage, report):
        artifacts = self.data / scan_id / "artifacts"
        names = list(ARTIFACTS[stage])
        if stage == "discover" and (artifacts / "sbom.json").is_file():
            names.append("sbom.json")
        if stage == "discover":
            names.extend(p.relative_to(artifacts).as_posix() for p in (artifacts / "discovery/evidence").glob("*.json"))
        if stage == "detect":
            names.extend(p.relative_to(artifacts).as_posix() for p in (artifacts / "evidence").glob("*.json")
                         if p.name != "index.json")
        if stage == "analyze":
            names.extend(p.relative_to(artifacts).as_posix() for p in (artifacts / "analysis/evidence").glob("*.json") if p.name != "index.json")
        if stage in {"remediate", "validate"}:
            folder = artifacts / ("remediation" if stage == "remediate" else "validation")
            names.extend(p.relative_to(artifacts).as_posix() for p in folder.rglob("*") if p.is_file() and "osv-cache" not in p.parts)
        files = {name: hashlib.sha256(safe_file(artifacts, name).read_bytes()).hexdigest() for name in names}
        checkpoint = {"schema_version": 1, "stage": stage, "status": report["status"], "finished_at": now(),
                      "repository_commit": report.get("repository_commit") or report.get("repository", {}).get("commit"),
                      "artifacts": files}
        if stage == "detect":
            checkpoint["policy_sha256"] = report.get("static_signals", {}).get("policy_sha256")
            checkpoint["detector_version"] = DETECTION_VERSION
        if stage == "analyze":
            checkpoint.update(analysis_version=ANALYSIS_VERSION, ai_policy_hash=report["ai_policy_hash"])
        if stage in {"remediate", "validate"}:
            checkpoint["reviews"] = reviews(self.store, scan_id) if stage == "validate" else None
        if stage == "validate":
            checkpoint["run_tests"] = self.store.get(scan_id).get("validation_run_tests", False)
        directory = self.data / scan_id / "checkpoints"
        directory.mkdir(exist_ok=True)
        write_json(directory / (stage + ".json"), checkpoint)

    def valid_checkpoint(self, scan_id, stage):
        root = self.data / scan_id
        try:
            checkpoint = json.loads(safe_file(root, f"checkpoints/{stage}.json").read_bytes())
            files = checkpoint["artifacts"]
            if stage == "detect" and (checkpoint.get("detector_version") != DETECTION_VERSION or
                    checkpoint.get("policy_sha256") != hashlib.sha256((WORKSPACE / "policy.yaml").read_bytes()).hexdigest()):
                return False
            if stage == "analyze" and (checkpoint.get("analysis_version") != ANALYSIS_VERSION or
                    checkpoint.get("ai_policy_hash") != (self.ai_config or AIConfig.load()).policy_hash):
                return False
            if stage in {"remediate", "validate"}:
                verify_plan(root)
                if stage == "validate" and checkpoint.get("reviews") != reviews(self.store, scan_id):
                    return False
                if stage == "validate" and checkpoint.get("run_tests", False) != self.store.get(scan_id).get("validation_run_tests", False):
                    return False
            return (checkpoint["schema_version"] == 1 and checkpoint["stage"] == stage
                    and checkpoint["status"] in {"completed", "incomplete", "partial", "passed", "not_run"}
                    and set(ARTIFACTS[stage]) <= files.keys()
                    and all(hashlib.sha256(safe_file(root / "artifacts", name).read_bytes()).hexdigest() == digest
                            for name, digest in files.items()))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def run(self, scan_id):
        path = self.data / scan_id
        current_stage = None
        token = SCAN_CANCEL_CHECK.set(lambda: self.check_cancel(scan_id))
        try:
            def claim(state):
                if state["cancel_requested"]:
                    raise ScanCancelled("Pipeline cancelled before execution")
                if state["status"] != "queued":
                    raise JobConflict("Pipeline is not queued")
                state.update(status="running", stage="Starting pipeline")
            self.store.change(scan_id, claim)
            reuse = True
            for stage in STAGES:
                self.check_cancel(scan_id)
                current_stage = stage
                if stage not in IMPLEMENTED:
                    def block(state):
                        if state["cancel_requested"]:
                            raise ScanCancelled("Pipeline cancelled")
                        state.update(status="blocked", stage=f"{stage} awaits implementation in a later milestone")
                        state["modules"][stage]["status"] = "not_implemented"
                    self.store.change(scan_id, block)
                    return
                state = self.store.get(scan_id)
                module = state["modules"][stage]
                if reuse and module["status"] in {"completed", "incomplete", "partial", "passed", "not_run"} and self.valid_checkpoint(scan_id, stage):
                    continue
                if stage == "validate":
                    plan = verify_plan(path)
                    decisions = reviews(self.store, scan_id)
                    if any(p["id"] not in decisions for p in plan["proposals"]):
                        def await_review(state):
                            state.update(status="awaiting_approval", stage="Review each exact diff before validation")
                            state["modules"]["validate"]["status"] = "awaiting_approval"
                        self.store.change(scan_id, await_review)
                        return
                reuse = False

                def begin(state):
                    state["stage"] = stage
                    state["modules"][stage].update(status="running", attempts=state["modules"][stage]["attempts"] + 1)
                    state["modules"][stage].pop("error", None)
                    # Rerunning an upstream module invalidates all dependent checkpoints.
                    for downstream in STAGES[STAGES.index(stage) + 1:]:
                        state["modules"][downstream]["status"] = "not_started"
                    state["events"].append({"at": now(), "event": "module_started", "module": stage})
                self.store.change(scan_id, begin)

                def update(message):
                    self.check_cancel(scan_id)
                    self.store.change(scan_id, lambda state: state.update(stage=message))

                if stage == "discover":
                    workspace = path / "workspaces"
                    if workspace.exists() or workspace.is_symlink():
                        attempt = self.store.get(scan_id)["modules"][stage]["attempts"]
                        workspace.rename(path / f"workspaces-before-attempt-{attempt}")
                    if state["repo_url"] == DEMO_URL:
                        report = analyze_repository(create_fixture(path), path / "artifacts", update)
                    else:
                        report = scan_repository(state["repo_url"], path, update, **(
                            {"deps_transport": self.deps_transport} if self.deps_transport is not None else {}))
                elif stage == "detect":
                    report = run_detection(path, state["baseline_commit"], transport=self.osv_transport,
                                           metadata_transport=self.metadata_transport, update=update)
                elif stage == "analyze":
                    report = run_analysis(path, self.store, config=self.ai_config or AIConfig.load(), ai_transport=self.ai_transport, update=update)
                elif stage == "remediate":
                    report = run_remediation(path, self.store, osv_transport=self.osv_transport, metadata_transport=self.metadata_transport,
                                             config=self.ai_config or AIConfig.load(), ai_transport=self.ai_transport, update=update)
                else:
                    report = run_validation(path, self.store, osv_transport=self.osv_transport, metadata_transport=self.metadata_transport,
                                            run_tests=state.get("validation_run_tests", False), update=update)
                self.check_cancel(scan_id)
                if report["status"] not in {"completed", "incomplete", "partial", "passed", "not_run"}:
                    raise RuntimeError("; ".join(report.get("errors", [])) or f"{stage} failed")
                self.checkpoint(scan_id, stage, report)

                def finish(state):
                    state["modules"][stage].update(status=report["status"], finished_at=now())
                    state["events"].append({"at": now(), "event": "module_finished", "module": stage, "status": report["status"]})
                self.store.change(scan_id, finish)
                if stage == "discover":
                    self.publish_discovery_status(scan_id)
            self.store.change(scan_id, lambda state: state.update(status="completed", stage="Pipeline finished"))
        except JobConflict:
            raise
        except Exception as exc:
            def fail(state):
                cancelled = state["cancel_requested"] or isinstance(exc, ScanCancelled)
                status = "cancelled" if cancelled else "failed"
                state.update(status=status, stage="Pipeline cancelled" if cancelled else "Pipeline failed")
                if current_stage and state["modules"][current_stage]["status"] == "running":
                    state["modules"][current_stage].update(status=status, error=str(exc)[:2000])
                state["events"].append({"at": now(), "event": status, "module": current_stage, "error": str(exc)[:2000]})
            self.store.change(scan_id, fail)
        finally:
            SCAN_CANCEL_CHECK.reset(token)
            self.publish_discovery_status(scan_id)

    def publish_discovery_status(self, scan_id):
        """Keep legacy graph/detection APIs usable without claiming full pipeline success."""
        state = self.store.get(scan_id)
        discovery = state["modules"]["discover"]["status"]
        status = discovery if discovery in {"completed", "incomplete"} else "failed"
        write_json(self.data / scan_id / "status.json", {
            "scan_id": scan_id, "repo_url": state["repo_url"], "status": status,
            "stage": state["stage"], "pipeline_status": state["status"], "updated_at": now(),
            "commit": self.discovery_commit(scan_id)})

    def discovery_commit(self, scan_id):
        try:
            return json.loads((self.data / scan_id / "checkpoints/discover.json").read_text())["repository_commit"]
        except (OSError, KeyError, ValueError):
            return None

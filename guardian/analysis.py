"""Deterministic finding prioritization followed by optional gateway explanations."""
import hashlib
import json
from collections import Counter
from pathlib import Path

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from .ai import ADVISORY, AIGateway, AIConfig
from .evidence import EvidenceStore, timestamp
from .files import read_json, write_json
from .models import Finding, Inventory
from .process import SCAN_CANCEL_CHECK
from .reachability import package_reachability

ANALYSIS_VERSION = "guardian-analysis/0.4.0"
SEVERITY = {"critical": 10, "high": 8, "medium": 5, "moderate": 5, "low": 2}


def severity(finding):
    values, supplied = [], []
    for source in finding.source_metadata:
        label = source.get("database_specific", {}).get("severity") if isinstance(source.get("database_specific", {}), dict) else None
        if isinstance(label, str) and label.lower() in SEVERITY:
            values.append(SEVERITY[label.lower()])
            supplied.append({"source": "advisory_label", "value": label})
        entries = source.get("severity", [])
        if not isinstance(entries, list):
            continue
        for entry in entries[:20]:
            if not isinstance(entry, dict) or not isinstance(entry.get("score"), str) or len(entry["score"]) > 500:
                continue
            try:
                kind = entry.get("type")
                parser = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(kind)
                if parser:
                    score = float(parser(entry["score"]).scores()[0])
                    values.append(score)
                    supplied.append({"source": kind, "value": entry["score"], "base_score": score})
            except (ValueError, TypeError, ArithmeticError, CVSSError):
                continue
    score = max(values) if values else None
    label = "unknown" if score is None else "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return score, label, supplied


def prioritize(findings, reachability):
    policy_components = {identifier for f in findings if f.finding_type == "policy_violation" for identifier in f.component_instance_ids}
    output = []
    for finding in findings:
        data = finding.model_dump()
        states = [reachability[identifier]["status"] for identifier in finding.component_instance_ids if identifier in reachability]
        state = next((s for s in ("reachable", "possibly_reachable", "unknown", "not_reachable") if s in states), "unknown")
        number, label, supplied = severity(finding)
        base = (70 if finding.advisory_category == "malicious_package" else number * 6 if number is not None else 30) if finding.finding_type == "vulnerability" else {
            "policy_violation": 30, "typosquat": 20, "install_script": 15, "suspicious_change": 15}[finding.finding_type]
        exploitation = finding.finding_type == "vulnerability" and any(isinstance(s.get("database_specific"), dict) and s["database_specific"].get("known_exploited") is True for s in finding.source_metadata)
        reach_points = {"reachable": 15, "possibly_reachable": 8, "unknown": 0, "not_reachable": -5}[state]
        policy_points = 10 if finding.finding_type != "policy_violation" and policy_components.intersection(finding.component_instance_ids) else 0
        verification = {"verified_match": 1, "provisional": .7, "undetermined": .4, "conflicting_evidence": .3, "not_applicable": 0}[finding.verification_status]
        signal_confidence = finding.confidence if finding.finding_type != "vulnerability" and finding.confidence is not None else 1
        multiplier = verification * signal_confidence
        score = max(0, min(100, round((base + reach_points + policy_points + (15 if exploitation else 0)) * multiplier)))
        confidence = min(multiplier, .6 if finding.finding_type == "vulnerability" and number is None and finding.advisory_category != "malicious_package" else 1)
        if state == "unknown": confidence *= .8
        data.update(risk_score=score, risk_confidence=round(confidence, 2), reachability_status=state,
            priority_status="critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low",
            score_factors={"base": base, "severity": label, "original_severity": supplied, "reachability_points": reach_points,
                "policy_points": policy_points, "exploitation_points": 15 if exploitation else 0,
                "exploitation_evidence": "advisory_reported_known_exploited" if exploitation else "not_supplied",
                "verification_multiplier": verification, "heuristic_confidence_multiplier": signal_confidence,
                "formula": "clamp(round((base + reachability + policy + exploitation) * verification * heuristic_confidence), 0, 100)"})
        output.append(data)
    return sorted(output, key=lambda f: (-f["risk_score"], f["finding_id"]))


def ai_fact(finding, reachability=None):
    proofs = list(finding["evidence_ids"])
    for identifier in finding["component_instance_ids"]:
        for witness in (reachability or {}).get(identifier, {}).get("witnesses", []):
            proofs.extend(witness["evidence_ids"])
    return {"finding_id": finding["finding_id"], "finding_type": finding["finding_type"],
        "evidence_ids": list(dict.fromkeys(proofs))[:40], "advisory_ids": [a for a in finding["advisory_ids"] if ADVISORY.fullmatch(a)][:20],
        "risk_score": finding["risk_score"], "risk_confidence": float(finding["risk_confidence"]),
        "reachability": finding["reachability_status"], "severity": finding["score_factors"]["severity"]}


def run_analysis(scan_directory: Path, store, *, config=None, ai_transport=None, update=lambda stage: None):
    artifacts = scan_directory / "artifacts"
    report = {"scan_id": scan_directory.name, "status": "running", "started_at": timestamp(),
              "tool_version": ANALYSIS_VERSION, "errors": [], "warnings": [], "findings": []}
    try:
        update("Validating detection evidence")
        inventory = Inventory.model_validate(read_json(artifacts, "components.json")[0])
        graph = read_json(artifacts, "dependency_graph.json")[0]
        detection = read_json(artifacts, "detection_report.json")[0]
        report["detection_sha256"] = hashlib.sha256((artifacts / "detection_report.json").read_bytes()).hexdigest()
        if detection["status"] not in {"completed", "partial"}:
            raise ValueError("A usable detection report is required")
        if {c.id for c in inventory.components} != {n["id"] for n in graph["nodes"]}:
            raise ValueError("Inventory and graph disagree")
        node_ids = {c.id for c in inventory.components}
        if any(e.parent not in node_ids or e.child and e.child not in node_ids for e in inventory.edges):
            raise ValueError("Inventory contains invalid dependency edges")
        findings = [Finding.model_validate(f) for f in detection["findings"]]
        evidence = EvidenceStore(artifacts / "evidence", detection["repository_commit"])
        evidence.records = read_json(artifacts, "evidence/index.json")[0]
        evidence.validate(findings)
        sources = list((scan_directory / "workspaces").glob("repo-*/source"))
        repo = sources[0] if len(sources) == 1 and not sources[0].is_symlink() else None
        source_store = EvidenceStore(artifacts / "analysis/evidence", detection["repository_commit"])
        update("Extracting package imports and dependency paths")
        reach = package_reachability(repo, inventory, graph, source_store)
        source_store.save()
        write_json(artifacts / "reachability.json", reach)
        update("Calculating deterministic priorities")
        scored = prioritize(findings, reach["components"])
        write_json(artifacts / "risk_scores.json", {"version": ANALYSIS_VERSION, "findings": scored})
        immutable_scores = hashlib.sha256(json.dumps(scored, sort_keys=True).encode()).hexdigest()
        config = config or AIConfig.load()
        gateway = AIGateway(store, config, transport=ai_transport)
        update("Explaining top findings through the AI gateway")
        notes = [gateway.explain(scan_directory.name, "explain", [ai_fact(f, reach["components"]) for f in scored[:10]])]
        SCAN_CANCEL_CHECK.get()()
        update("Reviewing non-CVE signals through the AI gateway")
        notes.append(gateway.explain(scan_directory.name, "review", [ai_fact(f, reach["components"]) for f in scored if f["finding_type"] != "vulnerability"][:5]))
        if hashlib.sha256(json.dumps(scored, sort_keys=True).encode()).hexdigest() != immutable_scores:
            raise RuntimeError("AI gateway modified deterministic findings")
        with store.connection() as db:
            row = db.execute("SELECT requests FROM ai_scan WHERE scan_id=?", (scan_directory.name,)).fetchone()
        usage = {**gateway.stats, "scan_requests_total": row[0] if row else 0, "max_calls_per_scan": config.max_calls,
                 "daily_requests": gateway.status()["daily_requests"], "daily_limit": config.daily_limit}
        write_json(artifacts / "ai_notes.json", {"tasks": notes, "usage": usage,
            "fix_notes": "not_run_in_analysis: prepare remediation to produce deterministic options and fix notes"})
        report.update(repository_commit=detection["repository_commit"], findings=scored,
            reachability_summary=dict(Counter(value["status"] for value in reach["components"].values())),
            ai={"tasks": notes, "usage": usage}, ai_policy_hash=config.policy_hash,
            coverage_status="partial" if detection.get("coverage_status") != "verified_scoped" or reach["status"] != "completed" else "verified_scoped")
        report["warnings"].extend(reach["warnings"])
        report["status"] = "completed" if report["coverage_status"] == "verified_scoped" else "partial"
        report["limitations"] = ["Reachability is a lexical package-level source model, not function-level exploitability.",
            "Absence of an observed import path is not proof a package cannot load at runtime.",
            "Source severity is preserved; priority is a deterministic review heuristic, not CVSS or malware probability.",
            "AI interpretations may be wrong; they cannot add findings, change scores, approve fixes, or replace original evidence.",
            "Fix notes run separately after deterministic remediation options exist; see remediation_report.json."]
    except Exception as exc:
        report.update(status="failed", coverage_status="unknown")
        report["errors"].append(str(exc)[:1000])
    report["finished_at"] = timestamp()
    write_json(artifacts / "analysis_report.json", report)
    write_json(artifacts / "analysis_status.json", {"scan_id": scan_directory.name, "status": report["status"],
               "stage": "Analysis finished", "finished_at": report["finished_at"]})
    return report

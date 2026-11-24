"""Controlled local fixture; live providers, ordinary orchestration, no auto-approval."""
import argparse
import json
import uuid
from pathlib import Path

from .files import write_json
from .models import Repository

DEMO_URL = "fixture://guardian-controlled-demo"


def create_fixture(scan: Path):
    repo = scan / "workspaces/repo-controlled/source"
    repo.mkdir(parents=True)
    manifest = {"name": "guardian-controlled-demo", "version": "1.0.0", "private": True,
                "dependencies": {"lodash": "4.17.20"}, "scripts": {"postinstall": "node sentinel.js"}}
    write_json(repo / "package.json", manifest)
    write_json(repo / "package-lock.json", {"name": manifest["name"], "version": "1.0.0", "lockfileVersion": 3,
        "requires": True, "packages": {"": manifest, "node_modules/lodash": {"version": "4.17.20",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}})
    (repo / "index.js").write_text("const lodash = require('lodash'); console.log(lodash.VERSION);\n")
    (repo / "sentinel.js").write_text("require('fs').writeFileSync('SCRIPT_EXECUTED', 'Installation scripts must never run');\n")
    (repo / ".npmrc").write_text("registry=https://must-never-contact.invalid\n")
    write_json(scan / "demo.json", {"kind": "controlled_fixture", "providers": "live", "approval": "required",
        "description": "Intentionally vulnerable lodash fixture. Not a user repository. Never execute sentinel.js."})
    return Repository(url=DEMO_URL, commit="6" * 40, path=str(repo))


def warm_cache(scan, store, *, config=None, transport=None):
    """Warm only real configured providers; templates never masquerade as cached AI."""
    from .ai import AIGateway, AIConfig
    from .analysis import ai_fact
    from .files import read_json
    from .remediation import remediation_facts, verify_plan
    plan = verify_plan(scan)
    analysis = read_json(scan / "artifacts", "analysis_report.json")[0]
    reach = read_json(scan / "artifacts", "reachability.json")[0]
    gateway = AIGateway(store, config or AIConfig.load(), transport=transport)
    tasks = [("explain", [ai_fact(f, reach["components"]) for f in analysis["findings"][:10]]),
             ("review", [ai_fact(f, reach["components"]) for f in analysis["findings"] if f["finding_type"] != "vulnerability"][:5]),
             ("fix_notes", remediation_facts(analysis, plan["recommendations"]))]
    results = [gateway.explain(scan.name, task, facts) for task, facts in tasks]
    result = {"scan_id": scan.name, "tasks": results, "usage": gateway.stats,
              "note": "Provider results are cached only after validation. Templates are labeled and never cached as AI."}
    write_json(scan / "artifacts/demo_cache.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Run the controlled Guardian demo with live intelligence; stop before approval.")
    parser.add_argument("--data", type=Path, default=Path("data/scans"))
    parser.add_argument("--resume", metavar="SCAN_ID", help="Resume only after reviewing exact diffs through the UI")
    parser.add_argument("--warm-cache", metavar="SCAN_ID", help="Pre-warm the three task caches using configured providers and existing shared budgets")
    args = parser.parse_args()
    from .orchestrator import JobStore, Orchestrator
    store = JobStore(args.data / "guardian.sqlite3")
    if args.resume and args.warm_cache:
        parser.error("Choose either resume or cache warming")
    requested = args.resume or args.warm_cache
    if requested and (len(requested) != 32 or any(c not in "0123456789abcdef" for c in requested)):
        parser.error("Use a 32-character scan ID")
    if args.warm_cache:
        print(json.dumps(warm_cache(args.data / args.warm_cache, store), indent=2))
        return
    if args.resume:
        scan_id = args.resume
        store.resume(scan_id)
    else:
        scan_id = uuid.uuid4().hex
        (args.data / scan_id / "artifacts").mkdir(parents=True)
        store.create(scan_id, DEMO_URL)
    Orchestrator(store, args.data).run(scan_id)
    print(json.dumps(store.get(scan_id), indent=2))
    print(f"Open /?scan={scan_id}#remediation to review. No patch was auto-approved.")


if __name__ == "__main__":
    main()

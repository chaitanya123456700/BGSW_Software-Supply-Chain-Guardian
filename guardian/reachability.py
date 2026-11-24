"""Conservative package-level JS/TS import observations, not exploitability analysis."""
import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path

import networkx as nx

from .files import safe_file, walk_files
from .process import SCAN_CANCEL_CHECK

TOKEN = re.compile(r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|(?P<template>`(?:\\.|[^`\\])*`)|(?P<word>[A-Za-z_$][\w$]*)|(?P<punct>[^\s])")
EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
EXCLUDED = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "coverage", "vendor"}
BUILTINS = {"assert", "async_hooks", "buffer", "child_process", "cluster", "console", "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"}


def imports(text):
    tokens = [(m.lastgroup, m.group(), m.start()) for m in TOKEN.finditer(text) if m.lastgroup != "comment"]
    found, uncertain = [], False
    for index, (kind, value, offset) in enumerate(tokens):
        if kind != "word":
            continue
        if value in {"eval", "Function", "createRequire"}:
            uncertain = True
        if value not in {"import", "require", "export"}:
            continue
        if index and tokens[index - 1][1] == ".":
            if value == "require": uncertain = True
            continue
        following = tokens[index + 1:index + 66]
        target, type_only = None, bool(following and following[0][1] == "type")
        if value == "require" or following and following[0][1] == "(":
            if len(following) >= 3 and following[0][1] == "(" and following[1][0] == "string" and following[2][1] == ")":
                target = following[1][1][1:-1]
            else:
                uncertain = True
        elif value == "import" and following and following[0][0] == "string":
            target = following[0][1][1:-1]
        else:
            for position, token in enumerate(following[:-1]):
                if token[1] == ";":
                    break
                if token[1] == "from" and following[position + 1][0] == "string":
                    target = following[position + 1][1][1:-1]
                    break
        if target is None and (value == "import" or value == "export" and following and following[0][1] in {"*", "{"}):
            uncertain = True
        if target is not None:
            if "\\" in target or target.startswith("#"):
                uncertain = True
            elif not target.startswith((".", "/", "#", "node:")):
                parts = target.split("/")
                name = "/".join(parts[:2]) if target.startswith("@") else parts[0]
                if name in BUILTINS:
                    continue
                if re.fullmatch(r"(?:@[A-Za-z0-9_.~-]+/)?[A-Za-z0-9_.~-]+", name):
                    found.append({"package": name, "line": text.count("\n", 0, offset) + 1, "type_only": type_only})
                else:
                    uncertain = True
    return found, uncertain


def package_reachability(repo, inventory, graph, store):
    report = {"scope": "Lexical JS/TS package imports and verified dependency paths; not function-level or runtime exploitability",
              "status": "completed", "files": [], "components": {}, "warnings": []}
    packages = [c for c in inventory.components if c.kind == "package"]
    projects = [p for p in inventory.projects if p.ecosystem == "npm"]
    network = nx.DiGraph()
    network.add_nodes_from(c.id for c in inventory.components)
    network.add_edges_from((e.parent, e.child) for e in inventory.edges if e.status == "resolved" and e.dependency_type != "containment" and e.child)
    observations, counts, uncertain_projects = defaultdict(list), defaultdict(int), set()
    project_members = {p.id: nx.descendants(network, p.root_id) for p in projects}
    direct = defaultdict(list)
    for edge in inventory.edges:
        if edge.child and edge.dependency_type != "containment" and edge.status in {"resolved", "declared_only"}:
            direct[(edge.parent, edge.dependency)].append(edge)
    if repo is None:
        report["warnings"].append("Source workspace unavailable; reachability remains unknown")
    else:
        total = total_imports = 0
        for path in walk_files(repo):
            SCAN_CANCEL_CHECK.get()()
            relative = path.relative_to(repo)
            if any(part in EXCLUDED for part in relative.parts):
                continue
            if path.name in {"tsconfig.json", "jsconfig.json"} or re.match(r"(?:vite|webpack|rollup)\.config\.", path.name):
                ambiguous = True
                try:
                    raw = safe_file(repo, relative.as_posix()).read_bytes()
                    if path.name in {"tsconfig.json", "jsconfig.json"} and len(raw) <= 256 * 1024:
                        config = json.loads(raw)
                        options = config.get("compilerOptions", {})
                        ambiguous = bool(config.get("extends") or options.get("paths") or options.get("baseUrl"))
                    store.add("module_resolution_configuration", relative.as_posix(), None, raw=raw, reliability="source_observation")
                except (ValueError, AttributeError, OSError):
                    ambiguous = True
                if ambiguous:
                    uncertain_projects.update(p.id for p in projects if p.path == "." or relative.as_posix().startswith(p.path + "/"))
            if path.suffix not in EXTENSIONS:
                continue
            matches = [p for p in projects if p.path == "." or relative.as_posix().startswith(p.path + "/")]
            if not matches:
                continue
            project = max(matches, key=lambda p: len(p.path) if p.path != "." else 0)
            if len(report["files"]) >= 2000 or total + path.stat().st_size > 10 * 1024 * 1024:
                report["warnings"].append("Import inspection reached file/byte limit; negative reachability is unknown")
                uncertain_projects.update(p.id for p in projects)
                break
            if path.stat().st_size > 512 * 1024:
                uncertain_projects.add(project.id)
                report["warnings"].append("Oversized source file skipped during import inspection")
                continue
            try:
                raw = safe_file(repo, relative.as_posix()).read_bytes()
                found, dynamic = imports(raw.decode("utf-8"))
            except (ValueError, UnicodeError, OSError):
                uncertain_projects.add(project.id)
                report["warnings"].append("Unreadable source file skipped during import inspection")
                continue
            total += len(raw)
            if total_imports + len(found) > 20000:
                found = found[:max(0, 20000 - total_imports)]
                uncertain_projects.add(project.id)
                report["warnings"].append("Import observation limit reached; remaining imports are unknown")
            total_imports += len(found)
            counts[project.id] += 1
            if dynamic:
                uncertain_projects.add(project.id)
            source_id = store.add("javascript_source", relative.as_posix(), None, raw=raw, reliability="source_observation")
            detail = {"file": relative.as_posix(), "project_id": project.id, "sha256": hashlib.sha256(raw).hexdigest(),
                      "imports": found[:2000], "dynamic_or_unsupported_loading": dynamic, "source_evidence_id": source_id}
            observation = store.add("package_import_observation", relative.as_posix(), detail, reliability="lexical_static_observation")
            report["files"].append(detail)
            test_context = any(part in {"test", "tests", "__tests__", "scripts"} for part in relative.parts) or bool(re.search(r"\.(?:test|spec)\.", path.name))
            for item in found[:2000]:
                for edge in direct[(project.root_id, item["package"])]:
                    if len(observations[edge.child]) >= 20:
                        continue
                    observations[edge.child].append({"file": relative.as_posix(), "line": item["line"],
                        "project_id": project.id, "evidence_ids": [source_id, observation],
                        "strong": edge.status == "resolved" and not item["type_only"] and not test_context})
            if len(found) > 2000:
                uncertain_projects.add(project.id)
    queue, visited = deque(observations), set(observations)
    while queue:
        parent = queue.popleft()
        for descendant in network.successors(parent):
            if descendant not in visited:
                witness = observations[parent][0]
                observations[descendant].append({**witness, "strong": False, "inherited_from": witness.get("inherited_from", parent), "dependency_parent": parent})
                visited.add(descendant)
                queue.append(descendant)
    for component in packages:
        witnesses = observations.get(component.id, [])
        owning = [p for p in projects if component.id in project_members[p.id] or component.project == p.path]
        if witnesses:
            strong = any(w["strong"] and w["project_id"] not in uncertain_projects for w in witnesses)
            status = "reachable" if strong else "possibly_reachable"
            reason = "Literal package import observed" if strong else "Possible import/ancestor path; binding or loading context remains uncertain"
        elif component.ecosystem != "npm" or component.resolution_status != "resolved" or not owning or any(not counts[p.id] or p.id in uncertain_projects for p in owning):
            status, reason = "unknown", "No complete supported import model establishes reachability or absence"
        else:
            status, reason = "not_reachable", "No import path observed within the scanned static package model; not proof of runtime absence"
        report["components"][component.id] = {"status": status, "reason": reason, "witnesses": witnesses[:20]}
    if report["warnings"] or uncertain_projects or any(v["status"] == "unknown" for v in report["components"].values()):
        report["status"] = "partial"
    report["uncertain_project_ids"] = sorted(uncertain_projects)
    return report

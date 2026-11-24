"""Bounded, cached OSV REST client. Only api.osv.dev is contacted."""
import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

import httpx

from .evidence import EvidenceStore, timestamp
from .files import write_json
from .process import SCAN_CANCEL_CHECK

ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,199}\Z")


class OSVError(RuntimeError):
    pass


class OSVClient:
    def __init__(self, cache: Path, evidence: EvidenceStore, *, transport=None, sleep=time.sleep, budget=150):
        self.cache, self.evidence, self.sleep = cache, evidence, sleep
        cache.mkdir(parents=True, exist_ok=True)
        self.deadline = time.monotonic() + budget
        self.client = httpx.Client(base_url="https://api.osv.dev", follow_redirects=False, trust_env=False,
            timeout=httpx.Timeout(15, connect=5), transport=transport, headers={"User-Agent": "guardian-phase2/0.2.0"})
        self.request_count = 0
        self.cache_hits = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def request(self, method, path, payload=None):
        SCAN_CANCEL_CHECK.get()()
        if path != "/v1/querybatch" and not (path.startswith("/v1/vulns/") and ADVISORY_ID.fullmatch(path[len("/v1/vulns/"):])):
            raise OSVError("Unsupported OSV endpoint")
        context = {"method": method, "payload": payload}
        key = hashlib.sha256(json.dumps([method, path, payload], sort_keys=True).encode()).hexdigest()
        cached = self.cache / (key + ".json")
        raw = retrieved = None
        if cached.is_file() and cached.stat().st_size < 20 * 1024 * 1024 and time.time() - cached.stat().st_mtime < 3600:
            try:
                saved = json.loads(cached.read_text())
                raw, retrieved = saved["raw"].encode(), saved["retrieved_at"]
                self.cache_hits += 1
            except (ValueError, KeyError, AttributeError):
                raw = None
        if raw is None:
            for attempt in range(3):
                SCAN_CANCEL_CHECK.get()()
                remaining = self.deadline - time.monotonic()
                if remaining <= 0 or self.request_count >= 1000:
                    raise OSVError("OSV request/time budget exhausted")
                self.request_count += 1
                try:
                    with self.client.stream(method, path, json=payload, timeout=min(15, remaining)) as response:
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            SCAN_CANCEL_CHECK.get()()
                            if time.monotonic() > self.deadline:
                                raise OSVError("OSV response exceeded total time budget")
                            size += len(chunk)
                            if size > 16 * 1024 * 1024:
                                raise OSVError("OSV response size limit exceeded")
                            chunks.append(chunk)
                        raw = b"".join(chunks)
                        retrieved = timestamp()
                        if response.status_code != 200:
                            self.evidence.add("osv_http_error", str(response.url), None, raw=raw,
                                retrieved_at=retrieved, reliability="source_error", context={**context, "http_status": response.status_code})
                            if response.status_code == 429 or response.status_code >= 500:
                                if attempt < 2:
                                    delay = .2 * 2**attempt
                                    try:
                                        delay = min(2, max(delay, float(response.headers.get("retry-after", 0))))
                                    except ValueError:
                                        pass
                                    self.sleep(delay)
                                    continue
                            raise OSVError(f"OSV HTTP {response.status_code}")
                        break
                except httpx.TransportError as exc:
                    self.evidence.add("osv_transport_error", "https://api.osv.dev" + path,
                        {"error": type(exc).__name__, "message": str(exc)}, reliability="source_error", context=context)
                    if attempt == 2:
                        raise OSVError(f"OSV transport failure: {type(exc).__name__}") from exc
                    self.sleep(.2 * 2**attempt)
            try:
                json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                self.evidence.add("osv_invalid_response", "https://api.osv.dev" + path, None, raw=raw, context=context)
                raise OSVError("OSV returned invalid JSON") from exc
            write_json(cached, {"raw": raw.decode(), "retrieved_at": retrieved})
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise OSVError("Invalid cached OSV response") from exc
        if not isinstance(data, dict):
            raise OSVError("OSV response must be an object")
        evidence = self.evidence.add("osv_advisory" if method == "GET" else "osv_exact_version_query",
            "https://api.osv.dev" + path, data, raw=raw, retrieved_at=retrieved,
            modified=data.get("modified"), reliability="authoritative_advisory_source", context=context)
        return data, evidence

    def query_batch(self, queries: list[dict]) -> list[dict]:
        if not 1 <= len(queries) <= 100:
            raise OSVError("OSV batches must contain 1 to 100 exact-version queries")
        output = [{"advisories": [], "modified": {}, "evidence_ids": [], "complete": False, "error": None} for _ in queries]
        pending = [(index, dict(query)) for index, query in enumerate(queries)]
        seen_tokens = set()
        for _ in range(10):
            if not pending:
                break
            try:
                data, evidence = self.request("POST", "/v1/querybatch", {"queries": [query for _, query in pending]})
                results = data.get("results")
                if not isinstance(results, list) or len(results) != len(pending):
                    raise OSVError("OSV batch response length mismatch")
            except OSVError as exc:
                for index, _ in pending:
                    output[index]["error"] = str(exc)
                break
            following = []
            for (index, query), result in zip(pending, results):
                item = output[index]
                item["evidence_ids"].append(evidence)
                if not isinstance(result, dict) or result.get("error"):
                    item["error"] = "OSV query item failed or was malformed"
                    continue
                vulnerabilities = result.get("vulns", [])
                if not isinstance(vulnerabilities, list) or any(not isinstance(v, dict) or not isinstance(v.get("id"), str)
                        or not ADVISORY_ID.fullmatch(v["id"]) for v in vulnerabilities):
                    item["error"] = "Malformed OSV vulnerability identifiers"
                    continue
                item["advisories"] = sorted(set(item["advisories"]) | {v["id"] for v in vulnerabilities})
                item["modified"].update({v["id"]: v.get("modified") for v in vulnerabilities})
                token = result.get("next_page_token")
                if token:
                    if not isinstance(token, str) or len(token) > 4096 or (index, token) in seen_tokens:
                        item["error"] = "Invalid/repeated OSV pagination token"
                        continue
                    seen_tokens.add((index, token))
                    following.append((index, {**query, "page_token": token}))
                else:
                    item["complete"] = True
            pending = following
        for index, _ in pending:
            if not output[index]["complete"] and not output[index]["error"]:
                output[index]["error"] = "OSV pagination budget exhausted"
        return output

    def advisory(self, identifier: str):
        if not ADVISORY_ID.fullmatch(identifier):
            raise OSVError("Invalid advisory identifier")
        data, evidence = self.request("GET", "/v1/vulns/" + identifier)
        if data.get("id") != identifier or not isinstance(data.get("modified"), str) or not isinstance(data.get("affected"), list):
            raise OSVError("Malformed/mismatched OSV advisory record")
        try:
            for field in ["modified", "published", "withdrawn"]:
                if data.get(field) and datetime.fromisoformat(data[field].replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError("Missing source timestamp timezone")
        except (ValueError, TypeError, AttributeError) as exc:
            raise OSVError("Invalid advisory timestamps") from exc
        return data, evidence

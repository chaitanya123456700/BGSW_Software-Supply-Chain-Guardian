"""Read bounded registry/deps.dev metadata; never fetch tarballs or run packages."""
import json
import re
import time
from urllib.parse import quote

import httpx
from semantic_version import Version

from .depsdev import valid_name
from .evidence import EvidenceStore
from .process import SCAN_CANCEL_CHECK, SCAN_DEADLINE

DEFAULT_TRANSPORT = None


class MetadataError(ValueError):
    pass


class MetadataClient:
    def __init__(self, store: EvidenceStore, *, transport=None, max_requests=60, budget=45):
        self.store, self.max_requests = store, max_requests
        self.requests = self.cache_hits = self.received = 0
        self.cache, self.unavailable = {}, set()
        self.deadline = min(time.monotonic() + budget, SCAN_DEADLINE.get() or float("inf"))
        self.client = httpx.Client(trust_env=False, follow_redirects=False, transport=transport or DEFAULT_TRANSPORT,
                                  timeout=httpx.Timeout(8, connect=3), headers={"User-Agent": "guardian-detection/0.3.0"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def _get(self, host, path, source_type):
        SCAN_CANCEL_CHECK.get()()
        if host not in {"registry.npmjs.org", "api.deps.dev"} or not path.startswith("/"):
            raise MetadataError("Unsupported metadata host or path")
        url = "https://" + host + path
        if url in self.cache:
            self.cache_hits += 1
            return self.cache[url]
        remaining = self.deadline - time.monotonic()
        if host in self.unavailable or remaining <= 0 or self.requests >= self.max_requests:
            raise MetadataError("Metadata service unavailable or request/time budget exhausted")
        self.requests += 1
        try:
            with self.client.stream("GET", url, timeout=min(8, remaining)) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    SCAN_CANCEL_CHECK.get()()
                    size += len(chunk)
                    self.received += len(chunk)
                    if size > 2 * 1024 * 1024 or self.received > 10 * 1024 * 1024 or time.monotonic() > self.deadline:
                        self.unavailable.add(host)
                        self.store.add("metadata_response_limit", url, {"bytes_received": size}, reliability="source_error")
                        raise MetadataError("Metadata response size/time limit exceeded")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                evidence = self.store.add(source_type, url, None, raw=raw,
                    reliability="source_error" if response.status_code != 200 else "registry_statement" if host == "registry.npmjs.org" else "external_metadata",
                    context={"http_status": response.status_code})
                if response.status_code != 200:
                    if response.status_code == 429 or response.status_code >= 500:
                        self.unavailable.add(host)
                    raise MetadataError(f"Metadata HTTP {response.status_code}; redirects/retries are disabled")
        except httpx.TransportError as exc:
            self.unavailable.add(host)
            self.store.add("metadata_transport_error", url, {"error": type(exc).__name__}, reliability="source_error")
            raise MetadataError("Metadata transport unavailable") from exc
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise MetadataError("Metadata response is not valid JSON") from exc
        if not isinstance(data, dict):
            raise MetadataError("Metadata response must be an object")
        self.cache[url] = data, evidence
        return data, evidence

    def version(self, host, name, version):
        if not valid_name("NPM", name) or not isinstance(version, str) or len(version) > 200:
            raise MetadataError("Unsupported exact npm identity")
        try:
            Version(version)
        except ValueError as exc:
            raise MetadataError("Unsupported exact npm version") from exc
        encoded_name, encoded_version = quote(name, safe=""), quote(version, safe="")
        if host == "registry.npmjs.org":
            path, source = f"/{encoded_name}/{encoded_version}", "npm_version_metadata"
        elif host == "api.deps.dev":
            path, source = f"/v3/systems/npm/packages/{encoded_name}/versions/{encoded_version}", "depsdev_version_metadata"
        else:
            raise MetadataError("Unsupported metadata host")
        data, evidence = self._get(host, path, source)
        key = data if host == "registry.npmjs.org" else data.get("versionKey", {})
        if (not isinstance(key, dict) or key.get("name") != name or key.get("version") != version
                or host == "api.deps.dev" and key.get("system") != "NPM"):
            raise MetadataError("Metadata package identity/version mismatch")
        return data, evidence

    def package(self, name):
        if not valid_name("NPM", name):
            raise MetadataError("Unsupported npm package name")
        data, evidence = self._get("api.deps.dev", "/v3/systems/npm/packages/" + quote(name, safe=""), "depsdev_package_metadata")
        if data.get("packageKey") != {"system": "NPM", "name": name}:
            raise MetadataError("Metadata package identity mismatch")
        return data, evidence

    def project(self, identifier):
        if not isinstance(identifier, str) or len(identifier) > 300 or not re.fullmatch(r"(?:github.com|gitlab.com|bitbucket.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identifier):
            raise MetadataError("Unsupported deps.dev project identifier")
        data, evidence = self._get("api.deps.dev", "/v3/projects/" + quote(identifier, safe=""), "depsdev_project_metadata")
        if data.get("projectKey") != {"id": identifier}:
            raise MetadataError("Project metadata identity mismatch")
        return data, evidence

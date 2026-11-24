from typing import Literal

import hashlib

from pydantic import BaseModel, Field, computed_field, model_validator

Resolution = Literal["resolved", "declared_only", "inferred", "unresolved", "unknown"]
TrustTier = Literal["verified_lockfile", "declared_exact", "externally_inferred", "constraint_only", "unknown"]
Completeness = Literal["verified", "partial", "declared_empty", "verified_empty", "insufficient_evidence", "unsupported", "failed"]


def stable_id(kind: str, *parts: str) -> str:
    return kind + ":" + hashlib.sha256("\0".join(parts).encode()).hexdigest()[:24]


class Evidence(BaseModel):
    file: str
    pointer: str
    sha256: str

    @computed_field
    @property
    def id(self) -> str:
        return stable_id("evidence", self.file, self.pointer, self.sha256)


class Project(BaseModel):
    id: str
    repository_id: str
    name: str
    path: str
    ecosystem: str
    root_id: str
    manifest_path: str | None = None
    manifest_paths: list[str] = Field(default_factory=list)
    lockfile_path: str | None = None
    workspace_id: str | None = None
    workspace_membership: str | None = None
    completeness_status: Completeness = "insufficient_evidence"
    dependency_status: str = "unknown"
    coverage_status: str = "insufficient_evidence"
    warnings: list[str] = Field(default_factory=list)


class Component(BaseModel):
    id: str
    identity: str | None = None
    name: str
    version: str | None = None
    ecosystem: str = "npm"
    path: str
    project: str
    kind: Literal["repository", "application", "package", "workspace"] = "package"
    classification: Literal["root", "direct", "transitive", "unreachable"] = "unreachable"
    dev: bool = False
    optional: bool = False
    link_target: str | None = None
    evidence: list[Evidence]
    requested_constraint: str | None = None
    declared_version: str | None = None
    inferred_version: str | None = None
    inference_evidence: list[Evidence] = Field(default_factory=list)
    environment_marker: str | None = None
    extras: list[str] = Field(default_factory=list)
    declaration_group: str | None = None
    resolution_status: Resolution = "resolved"
    version_source: str = "lockfile"
    installation_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def keep_inference_separate(self):
        if (self.resolution_status == "inferred" or self.version_source == "deps.dev") and self.version is not None:
            raise ValueError("Inferred versions must not populate the verified version field")
        return self

    @computed_field
    @property
    def trust_tier(self) -> TrustTier:
        if self.kind != "package":
            return "unknown"
        if self.resolution_status == "resolved" and self.version_source == "lockfile" and self.version:
            return "verified_lockfile"
        if self.declared_version:
            return "declared_exact"
        if self.inferred_version:
            return "externally_inferred"
        return "constraint_only" if self.requested_constraint is not None else "unknown"

    @computed_field
    @property
    def instance_id(self) -> str:
        return self.id

    @computed_field
    @property
    def package_identity(self) -> str | None:
        return self.identity

    @computed_field
    @property
    def resolved_version(self) -> str | None:
        return self.version if self.resolution_status == "resolved" else None

    @computed_field
    @property
    def evidence_ids(self) -> list[str]:
        return [item.id for item in self.evidence]

    @computed_field
    @property
    def node_type(self) -> str:
        if self.kind == "repository":
            return "repository"
        if self.kind in {"application", "workspace"}:
            return "application"
        if self.resolution_status == "inferred":
            return "inferred_component"
        return "resolved_component" if self.resolution_status == "resolved" else "declared_only_component" if self.resolution_status == "declared_only" else "unknown_component"


class Edge(BaseModel):
    parent: str
    child: str | None = None
    dependency: str
    dependency_type: Literal["production", "development", "optional", "peer", "workspace", "containment"]
    constraint: str | None = None
    optional: bool = False
    status: Resolution
    reason: str | None = None
    evidence: Evidence
    workspace: bool = False
    # Lockfile topology proves placement, not semver satisfaction or runtime installation.
    version_satisfaction: str = "not_checked"

    @computed_field
    @property
    def source_id(self) -> str:
        return self.parent

    @computed_field
    @property
    def target_id(self) -> str | None:
        return self.child

    @computed_field
    @property
    def relationship_type(self) -> str:
        if self.dependency_type == "containment":
            return "contains_project"
        if self.dependency_type == "workspace" or self.workspace:
            return "workspace_dependency"
        if self.status == "inferred":
            return "inferred_dependency"
        return "declares_dependency" if self.status != "resolved" else "resolved_dependency"

    @computed_field
    @property
    def requested_constraint(self) -> str | None:
        return self.constraint

    @computed_field
    @property
    def resolution_status(self) -> str:
        return self.status

    @computed_field
    @property
    def evidence_ids(self) -> list[str]:
        return [self.evidence.id]


class Inventory(BaseModel):
    components: list[Component] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    roots: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    repository_id: str | None = None
    projects: list[Project] = Field(default_factory=list)


class Ecosystem(BaseModel):
    ecosystem: str
    package_manager: str
    project_root: str
    manifest_path: str | None = None
    manifest_paths: list[str] = Field(default_factory=list)
    lockfile_path: str | None = None
    supported: bool = False
    reason: str | None = None
    covered_by: str | None = None
    metadata_errors: list[str] = Field(default_factory=list)


class Repository(BaseModel):
    url: str
    commit: str
    path: str


class ScanRequest(BaseModel):
    repo_url: str = Field(min_length=1, max_length=300)


class DetectionRequest(BaseModel):
    baseline_commit: str | None = Field(default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class PipelineRequest(ScanRequest, DetectionRequest):
    pass


class PatchReviewRequest(BaseModel):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approve", "reject", "accepted_risk"]
    reviewed_diff: bool = False
    reason: str = Field(default="", max_length=2000)


class ValidationRequest(BaseModel):
    run_tests: bool = False


class RemediationSelectionRequest(BaseModel):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected: list[str] = Field(default_factory=list, max_length=100)


class RepositoryValidationRequest(RemediationSelectionRequest):
    receipt: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed_changes: bool = False
    run_tests: bool = False


class Finding(BaseModel):
    finding_id: str
    scan_id: str
    finding_type: Literal["vulnerability", "suspicious_change", "install_script", "typosquat", "policy_violation"]
    title: str
    explanation: str
    component_instance_ids: list[str] = Field(default_factory=list)
    repository_commit: str
    baseline_commit: str | None = None
    advisory_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    verification_status: Literal["verified_match", "provisional", "conflicting_evidence", "undetermined", "not_applicable"]
    classification: str = "source_statement"
    advisory_category: Literal["vulnerability", "malicious_package"] | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    version_applicability: str = "undetermined"
    source_consistency: str = "single_source"
    evidence_ids: list[str] = Field(min_length=1)
    affected_application_ids: list[str] = Field(default_factory=list)
    dependency_paths: list[dict] = Field(default_factory=list)
    graph_coverage_warnings: list[str] = Field(default_factory=list)
    reachability_status: str = "not_analyzed"
    priority_status: str = "not_assessed"
    created_at: str
    source_metadata: list[dict] = Field(default_factory=list)

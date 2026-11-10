"""Strict contracts for model-assisted repository and Terraform workflows.

The model is never the authority for source-derived facts, Azure prices, plan
approval, Terraform validation, or execution. These contracts deliberately
bound model input and output so downstream code can enforce those boundaries.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$"
TERRAFORM_ADDRESS_PATTERN = r"^[a-z0-9_]+\.[a-zA-Z0-9_-]+(?:\[[^\]]+\])?$"
TERRAFORM_RESOURCE_TYPE_PATTERN = r"^azurerm_[a-z0-9_]+$"

_SENSITIVE_PATH_MARKERS = (
    ".env",
    "credential",
    "secret",
    "private-key",
    "id_rsa",
    ".pem",
    ".pfx",
    ".key",
)
_CURRENCY_AMOUNT_PATTERN = re.compile(
    r"(?i)(?:[$\u20ac\u00a3\u20b9]\s*\d|\b(?:usd|eur|gbp|inr)\s*\d)"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bauthorization\b\s*[:=]\s*bearer\s+\S+"),
    re.compile(r"(?i)\baccountkey\s*=\s*[^;\s]+"),
    re.compile(
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b"
        r"\s*[:=]\s*(?!<redacted>|<secret>|null\b|none\b)[^\s,;]+"
    ),
    re.compile(r"(?i)\b(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_-]+"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"://[^\s/@:]+:[^\s/@]+@"),
)
_SECRET_PROPERTY_NAME = re.compile(
    r"(?i)(?:password|passwd|secret_value|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|connection[_-]?string|sas[_-]?token)"
)


def _contains_secret_value(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)


class StrictContract(BaseModel):
    """Shared contract policy: reject unknown fields and normalize strings."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class AIWorkload(StrEnum):
    REPOSITORY_ANALYSIS = "repository_analysis"
    TERRAFORM_GENERATION = "terraform_generation"


class ConfidenceLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RecommendationPriority(StrEnum):
    REQUIRED = "required"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QualitativeImpact(StrEnum):
    DECREASE = "decrease"
    NEUTRAL = "neutral"
    INCREASE = "increase"
    UNKNOWN = "unknown"


class SourceFact(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    category: Literal[
        "framework",
        "runtime",
        "dependency",
        "build",
        "start",
        "port",
        "database",
        "environment-variable",
        "repository",
        "other",
    ]
    value: str = Field(min_length=1, max_length=1_200)
    source_path: str | None = Field(default=None, max_length=300)
    source_line: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def enforce_non_secret_fact(self) -> "SourceFact":
        if self.category == "environment-variable" and not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,254}",
            self.value,
        ):
            raise ValueError(
                "Environment-variable facts may contain names only, never values."
            )
        if _contains_secret_value(self.value):
            raise ValueError("Source facts cannot contain a secret-like value.")
        return self


class SafeFileExcerpt(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=4_000)
    sha256: str = Field(pattern=SHA256_PATTERN)
    truncated: bool = False

    @field_validator("path")
    @classmethod
    def reject_sensitive_paths(cls, value: str) -> str:
        normalized = value.replace("\\", "/").lower()
        if (
            normalized.startswith("/")
            or normalized.startswith("../")
            or "/../" in normalized
            or any(marker in normalized for marker in _SENSITIVE_PATH_MARKERS)
        ):
            raise ValueError("Safe model context cannot contain a sensitive or unsafe path.")
        return value.replace("\\", "/")

    @field_validator("content")
    @classmethod
    def reject_secret_values(cls, value: str) -> str:
        if _contains_secret_value(value):
            raise ValueError("Safe model context cannot contain a secret-like value.")
        return value


class RepositoryAnalysisRequest(StrictContract):
    schema_version: Literal["repository-analysis-request.v1"]
    tenant_id: UUID
    project_id: UUID
    repository: str = Field(min_length=3, max_length=250)
    branch: str = Field(min_length=1, max_length=250)
    commit_sha: str = Field(pattern=GIT_COMMIT_PATTERN)
    source_facts: list[SourceFact] = Field(default_factory=list, max_length=200)
    safe_files: list[SafeFileExcerpt] = Field(default_factory=list, max_length=20)
    repository_tree: str = Field(default="", max_length=8_000)
    constraints: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def enforce_context_budget(self) -> "RepositoryAnalysisRequest":
        total = len(self.repository_tree)
        total += sum(len(fact.value) + len(fact.source_path or "") for fact in self.source_facts)
        total += sum(len(item.path) + len(item.content) for item in self.safe_files)
        total += sum(len(item) for item in self.constraints)
        if total > 60_000:
            raise ValueError("Repository model context exceeds the 60,000 character safety budget.")
        if any(_contains_secret_value(item) for item in self.constraints):
            raise ValueError("Repository constraints cannot contain a secret-like value.")
        return self


class AnalysisRecommendation(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    priority: RecommendationPriority
    category: Literal["security", "reliability", "operations", "performance", "cost", "delivery"]
    action: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=700)
    evidence_refs: list[str] = Field(min_length=1, max_length=8)
    cost_impact: QualitativeImpact
    security_impact: QualitativeImpact
    reliability_impact: QualitativeImpact
    tradeoffs: list[str] = Field(max_length=4)


class CostOptimizationCandidate(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    title: str = Field(min_length=1, max_length=180)
    rationale: str = Field(min_length=1, max_length=600)
    evidence_refs: list[str] = Field(min_length=1, max_length=8)
    expected_impact: Literal["low", "medium", "high", "unknown"]
    tradeoffs: list[str] = Field(max_length=4)
    validation_needed: str = Field(min_length=1, max_length=400)

    @field_validator("rationale", "validation_needed")
    @classmethod
    def reject_unverified_currency_amounts(cls, value: str) -> str:
        if _CURRENCY_AMOUNT_PATTERN.search(value):
            raise ValueError("Repository analysis cannot invent numerical cost amounts.")
        return value


class RepositoryAssessment(StrictContract):
    schema_version: Literal["repository-assessment.v1"]
    summary: str = Field(min_length=1, max_length=1_200)
    deployment_risk: str = Field(min_length=1, max_length=1_200)
    recommendations: list[AnalysisRecommendation] = Field(max_length=8)
    cost_optimizations: list[CostOptimizationCandidate] = Field(max_length=6)
    unresolved_questions: list[str] = Field(max_length=8)
    confidence: ConfidenceLevel
    limitations: list[str] = Field(max_length=8)

    @field_validator("unresolved_questions", "limitations")
    @classmethod
    def bound_list_items(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 400:
                raise ValueError("Assessment list items must contain 1 to 400 characters.")
        return values

    @model_validator(mode="after")
    def unique_assessment_identifiers(self) -> "RepositoryAssessment":
        identifiers = [
            *(item.id for item in self.recommendations),
            *(item.id for item in self.cost_optimizations),
        ]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Assessment recommendation identifiers must be unique.")
        return self


class ApprovedComponent(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    service: str = Field(min_length=1, max_length=180)
    tier: str | None = Field(default=None, max_length=120)
    properties: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_secret_properties(self) -> "ApprovedComponent":
        for key, value in self.properties.items():
            if (
                _SECRET_PROPERTY_NAME.search(str(key))
                and not (
                    value is None
                    or value == ""
                    or isinstance(value, bool)
                )
            ):
                raise ValueError(
                    "Approved component properties cannot contain secret values."
                )
        serialized = json.dumps(self.properties, sort_keys=True, default=str)
        if _contains_secret_value(serialized):
            raise ValueError(
                "Approved component properties cannot contain a secret-like value."
            )
        return self


class VerifiedPricingContext(StrictContract):
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    captured_at: str = Field(min_length=10, max_length=40)
    source: str = Field(min_length=1, max_length=300)
    monthly_budget: float | None = Field(default=None, ge=0)
    price_snapshot_ref: str | None = Field(default=None, max_length=500)


class TerraformGenerationRequest(StrictContract):
    schema_version: Literal["terraform-generation-request.v1"]
    tenant_id: UUID
    project_id: UUID
    plan_id: UUID
    plan_revision: int = Field(ge=1)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)
    plan_status: Literal["approved"]
    target_cloud: Literal["azure"] = "azure"
    region: str = Field(min_length=2, max_length=80)
    components: list[ApprovedComponent] = Field(min_length=1, max_length=80)
    allowed_resource_types: list[str] = Field(min_length=1, max_length=120)
    module_catalog_version: str = Field(min_length=1, max_length=80)
    policy_version: str = Field(min_length=1, max_length=80)
    constraints: list[str] = Field(default_factory=list, max_length=30)
    pricing: VerifiedPricingContext | None = None

    @field_validator("allowed_resource_types")
    @classmethod
    def validate_resource_allowlist(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("Terraform resource allowlist cannot contain duplicates.")
        for value in values:
            if not re.fullmatch(TERRAFORM_RESOURCE_TYPE_PATTERN, value):
                raise ValueError("Terraform generation is restricted to AzureRM resource types.")
        return values

    @model_validator(mode="after")
    def unique_components(self) -> "TerraformGenerationRequest":
        identifiers = [component.id for component in self.components]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Approved component identifiers must be unique.")
        return self


class TerraformFile(StrictContract):
    path: str = Field(min_length=3, max_length=180)
    content: str = Field(min_length=1, max_length=30_000)


class TerraformVariable(StrictContract):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    type: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=400)
    sensitive: bool
    # Keep the model-facing shape compatible with strict structured-output
    # schemas. Complex object defaults belong in deterministic renderers, not
    # in model-authored metadata.
    default: str | int | float | bool | list[str] | None


class TerraformResourceMapping(StrictContract):
    address: str = Field(pattern=TERRAFORM_ADDRESS_PATTERN)
    resource_type: str = Field(pattern=TERRAFORM_RESOURCE_TYPE_PATTERN)
    component_id: str = Field(pattern=IDENTIFIER_PATTERN)
    rationale: str = Field(min_length=1, max_length=500)
    cost_driver: bool


class TerraformOutput(StrictContract):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=300)
    sensitive: bool


class TerraformCostOptimization(StrictContract):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    component_id: str = Field(pattern=IDENTIFIER_PATTERN)
    mechanism: str = Field(min_length=1, max_length=300)
    expected_impact: Literal["low", "medium", "high", "unknown"]
    tradeoff: str = Field(min_length=1, max_length=400)
    requires_verified_pricing: bool


class TerraformBundle(StrictContract):
    schema_version: Literal["terraform-bundle.v1"]
    status: Literal["generated", "blocked"]
    plan_revision: int = Field(ge=1)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)
    files: list[TerraformFile] = Field(max_length=12)
    variables: list[TerraformVariable] = Field(max_length=64)
    resources: list[TerraformResourceMapping] = Field(max_length=120)
    outputs: list[TerraformOutput] = Field(max_length=32)
    assumptions: list[str] = Field(max_length=12)
    warnings: list[str] = Field(max_length=12)
    cost_optimizations: list[TerraformCostOptimization] = Field(max_length=12)
    validation_requirements: list[str] = Field(max_length=20)
    blocked_reasons: list[str] = Field(max_length=12)

    @model_validator(mode="after")
    def validate_bundle_shape(self) -> "TerraformBundle":
        file_paths = [item.path for item in self.files]
        if len(file_paths) != len(set(file_paths)):
            raise ValueError("Terraform bundle file paths must be unique.")
        if sum(len(item.content) for item in self.files) > 120_000:
            raise ValueError("Terraform bundle exceeds the 120,000 character output budget.")

        variable_names = [item.name for item in self.variables]
        if len(variable_names) != len(set(variable_names)):
            raise ValueError("Terraform variable names must be unique.")

        output_names = [item.name for item in self.outputs]
        if len(output_names) != len(set(output_names)):
            raise ValueError("Terraform output names must be unique.")

        resource_addresses = [item.address for item in self.resources]
        if len(resource_addresses) != len(set(resource_addresses)):
            raise ValueError("Terraform resource mappings must be unique.")

        if self.status == "generated" and (not self.files or self.blocked_reasons):
            raise ValueError("Generated Terraform bundles require files and cannot contain blocking reasons.")
        if self.status == "blocked" and (self.files or not self.blocked_reasons):
            raise ValueError("Blocked Terraform bundles require reasons and cannot contain files.")
        return self


class ModelProvenance(StrictContract):
    workload: AIWorkload
    provider: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=160)
    prompt_version: str = Field(min_length=1, max_length=100)
    schema_version: str = Field(min_length=1, max_length=100)
    execution_mode: Literal["model", "deterministic_only"]
    correlation_id: UUID
    request_hash: str = Field(pattern=SHA256_PATTERN)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    repair_attempted: bool = False
    cached: bool = False
    selected_route: Literal["primary", "fallback", "none"] = "primary"
    fallback_attempted: bool = False
    primary_failure_code: str | None = Field(default=None, max_length=80)
    primary_input_tokens: int = Field(default=0, ge=0)
    primary_output_tokens: int = Field(default=0, ge=0)
    primary_latency_ms: int = Field(default=0, ge=0)
    primary_repair_attempted: bool = False

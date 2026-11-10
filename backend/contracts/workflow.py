"""Strict backend-owned contracts for Azure workflow queue messages.

Only opaque identifiers, immutable artifact references, non-secret Terraform
inputs, and validation digests cross the Service Bus boundary.  These models
mirror the Function and VMSS consumer contracts so producers fail before an
invalid message can enter the durable outbox.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TENANT_CONTAINER = re.compile(r"^t-[0-9a-f]{40}$")
_VARIABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESOURCE_TYPE = re.compile(r"^azurerm_[a-z0-9_]{1,96}$")
_RESOURCE_GROUP = re.compile(r"^[A-Za-z0-9._()\-]{1,90}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
_USER_ARTIFACT_PATH = re.compile(
    r"^objects/(?P<artifact_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})/v(?P<version>[1-9][0-9]*)/"
    r"(?P<sha256>[0-9a-f]{64})$"
)
_SECRET_NAME = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|api[_-]?key|"
    r"connection[_-]?string|private[_-]?key|sas|client[_-]?secret)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]+PRIVATE KEY-----|"
    r"(?:AccountKey|SharedAccessSignature|client_secret|password)\s*=|"
    r"(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{8,}|[?&](?:sig|se|sp|sv)=|"
    r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_-]+|"
    r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@)"
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    import hashlib

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _canonical_uuid(value: str, *, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError(f"{field} must be a canonical UUID") from error
    canonical = str(parsed)
    if value != canonical:
        raise ValueError(f"{field} must use lowercase canonical UUID form")
    return canonical


class ArtifactReferenceV1(StrictContract):
    schema_version: Literal["artifact-reference.v1"] = "artifact-reference.v1"
    artifact_id: str
    account_url: str
    container: str
    blob_name: str
    version_id: str | None = None
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0, le=268_435_456)
    media_type: str = Field(min_length=1, max_length=128)
    classification: Literal[
        "tenant-source",
        "tenant-analysis",
        "tenant-terraform",
        "tenant-plan-sanitized",
        "tenant-cost",
        "tenant-evidence",
        "executor-plan-raw",
        "executor-state",
        "workflow-event",
    ]

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("artifact_id is invalid")
        return value

    @field_validator("account_url")
    @classmethod
    def validate_account_url(cls, value: str) -> str:
        normalized = value.rstrip("/")
        if (
            not normalized.startswith("https://")
            or "/" in normalized.removeprefix("https://")
            or not normalized.endswith(".blob.core.windows.net")
        ):
            raise ValueError("account_url must be an Azure Blob HTTPS account origin")
        return normalized

    @field_validator("container")
    @classmethod
    def validate_container(cls, value: str) -> str:
        if not _TENANT_CONTAINER.fullmatch(value):
            raise ValueError("container must be an opaque tenant container")
        return value

    @field_validator("blob_name")
    @classmethod
    def validate_blob_name(cls, value: str) -> str:
        normalized = value.replace("\\", "/").strip("/")
        if not normalized or ".." in normalized.split("/") or len(normalized) > 1_024:
            raise ValueError("blob_name is invalid")
        return normalized

    @model_validator(mode="after")
    def validate_immutable_user_artifact(self) -> "ArtifactReferenceV1":
        match = _USER_ARTIFACT_PATH.fullmatch(self.blob_name)
        if match is None:
            raise ValueError("blob_name must use the immutable user-artifact path")
        if match.group("artifact_id") != self.artifact_id:
            raise ValueError("artifact_id does not match blob_name")
        if match.group("sha256") != self.sha256:
            raise ValueError("artifact digest does not match blob_name")
        return self


class JobIdentityV1(StrictContract):
    job_id: str
    tenant_id: str
    project_id: str
    run_id: str
    correlation_id: str
    attempt: int = Field(default=1, ge=1, le=10)
    enqueued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("job_id", "tenant_id", "project_id", "run_id", "correlation_id")
    @classmethod
    def validate_safe_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("identifier contains unsupported characters")
        return value


class RepositoryAnalysisJobV1(JobIdentityV1):
    schema_version: Literal["repository-analysis-job.v1"] = "repository-analysis-job.v1"
    source_artifact: ArtifactReferenceV1
    scanner_facts_artifact: ArtifactReferenceV1
    output_artifact_id: str
    output_container: str
    source_commit: str = Field(min_length=7, max_length=64)
    scanner_version: str = Field(min_length=1, max_length=64)

    @field_validator("output_artifact_id")
    @classmethod
    def validate_output_artifact_id(cls, value: str) -> str:
        return _canonical_uuid(value, field="output_artifact_id")

    @field_validator("output_container")
    @classmethod
    def validate_output_container(cls, value: str) -> str:
        if not _TENANT_CONTAINER.fullmatch(value):
            raise ValueError("output_container must be an opaque tenant container")
        return value


class TerraformInputVariableV1(StrictContract):
    name: str
    type: Literal["string", "number", "bool", "list(string)"]
    value: str | int | float | bool | list[str]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _VARIABLE_NAME.fullmatch(value) or _SECRET_NAME.search(value):
            raise ValueError("Terraform input variable name is unsafe")
        return value

    @model_validator(mode="after")
    def validate_typed_value(self) -> "TerraformInputVariableV1":
        value = self.value
        valid = (
            (self.type == "string" and isinstance(value, str))
            or (
                self.type == "number"
                and not isinstance(value, bool)
                and isinstance(value, (int, float))
                and (isinstance(value, int) or math.isfinite(value))
            )
            or (self.type == "bool" and isinstance(value, bool))
            or (
                self.type == "list(string)"
                and isinstance(value, list)
                and all(isinstance(item, str) for item in value)
            )
        )
        if not valid:
            raise ValueError("Terraform input variable value does not match its declared type")
        string_values = [value] if self.type == "string" else (value if self.type == "list(string)" else [])
        if len(string_values) > 64:
            raise ValueError("Terraform string lists may contain at most 64 items")
        for item in string_values:
            if len(item) > 1_024 or any(ord(character) < 32 for character in item):
                raise ValueError("Terraform input strings must be bounded printable text")
            if _SECRET_VALUE.search(item):
                raise ValueError("Terraform input variable contains unsafe data")
        return self


class TerraformGenerationJobV1(JobIdentityV1):
    schema_version: Literal["terraform-generation-job.v1"] = "terraform-generation-job.v1"
    user_id: str
    approved_plan_artifact: ArtifactReferenceV1
    output_artifact_id: str
    output_container: str
    approved_plan_id: str
    approved_plan_revision: int = Field(ge=1)
    approved_plan_digest: str = Field(pattern=SHA256_PATTERN)
    target_environment: Literal["test", "production"]
    target_subscription_id: str
    target_tenant_id: str
    target_resource_group: str = Field(min_length=1, max_length=90)
    iac_engine: Literal["opentofu"]
    terraform_version: Literal["1.13.2"]
    input_variables: list[TerraformInputVariableV1] = Field(max_length=64)
    maximum_resource_changes: int = Field(ge=1, le=500)
    maximum_delete_count: int = Field(ge=0, le=100)
    maximum_replace_count: int = Field(ge=0, le=100)

    @field_validator(
        "job_id",
        "tenant_id",
        "project_id",
        "run_id",
        "correlation_id",
        "user_id",
        "output_artifact_id",
        "approved_plan_id",
        "target_subscription_id",
        "target_tenant_id",
    )
    @classmethod
    def validate_uuid_fields(cls, value: str, info: Any) -> str:
        return _canonical_uuid(value, field=info.field_name)

    @field_validator("target_resource_group")
    @classmethod
    def validate_resource_group(cls, value: str) -> str:
        if value.endswith(".") or not re.fullmatch(r"[A-Za-z0-9._()\-]{1,90}", value):
            raise ValueError("target_resource_group is invalid")
        return value

    @field_validator("enqueued_at")
    @classmethod
    def validate_enqueued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("enqueued_at must include a timezone")
        normalized = value.astimezone(timezone.utc)
        if normalized > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("enqueued_at cannot be in the future")
        return normalized

    @model_validator(mode="after")
    def validate_limits_and_variables(self) -> "TerraformGenerationJobV1":
        names = [item.name for item in self.input_variables]
        if len(names) != len(set(names)):
            raise ValueError("Terraform input variable names must be unique")
        if self.maximum_delete_count > self.maximum_resource_changes:
            raise ValueError("maximum_delete_count exceeds maximum_resource_changes")
        if self.maximum_replace_count > self.maximum_resource_changes:
            raise ValueError("maximum_replace_count exceeds maximum_resource_changes")
        if len(self.model_dump_json(exclude={"approved_plan_artifact"}).encode("utf-8")) > 65_536:
            raise ValueError("Terraform execution inputs exceed the 64 KiB contract limit")
        return self


class BundleReferenceV1(StrictContract):
    uri: str
    etag: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(gt=0, le=104_857_600)

    @model_validator(mode="after")
    def validate_blob_uri(self) -> "BundleReferenceV1":
        parsed = urlparse(self.uri)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith(".blob.core.windows.net")
            or parsed.username
            or parsed.password
            or parsed.port
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
            or parsed.path.startswith("//")
            or "%" in parsed.path
        ):
            raise ValueError("uri must be a query-free Azure Blob HTTPS URI")
        path_parts = parsed.path[1:].split("/", 1)
        if len(path_parts) != 2 or not _TENANT_CONTAINER.fullmatch(path_parts[0]):
            raise ValueError("uri must identify an opaque tenant artifact")
        match = _USER_ARTIFACT_PATH.fullmatch(path_parts[1])
        if match is None or match.group("sha256") != self.sha256:
            raise ValueError("uri must use the immutable artifact path bound to sha256")
        return self


class InputVariableDefinitionV1(StrictContract):
    name: str
    type: Literal["string", "number", "bool", "list(string)"]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _VARIABLE_NAME.fullmatch(value) or _SECRET_NAME.search(value):
            raise ValueError("input variable definition contains an unsafe name")
        return value


class InputVariablesReferenceV1(StrictContract):
    file_name: Literal["zeroops.auto.tfvars.json"]
    sha256: str = Field(pattern=SHA256_PATTERN)
    definitions: list[InputVariableDefinitionV1] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_sorted_definitions(self) -> "InputVariablesReferenceV1":
        names = [item.name for item in self.definitions]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("input variable definitions must be unique and sorted")
        return self


class ExecutionGuardrailsV1(StrictContract):
    target_resource_group: str = Field(min_length=1, max_length=90)
    allowed_resource_types: list[str] = Field(min_length=1, max_length=120)
    maximum_resource_changes: int = Field(ge=1, le=500)
    maximum_delete_count: int = Field(ge=0, le=100)
    maximum_replace_count: int = Field(ge=0, le=100)
    scope_digest: str = Field(pattern=SHA256_PATTERN)
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    monthly_budget_microunits: int | None = Field(default=None, ge=0)
    budget_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")

    @model_validator(mode="after")
    def validate_guardrails(self) -> "ExecutionGuardrailsV1":
        if not _RESOURCE_GROUP.fullmatch(self.target_resource_group) or self.target_resource_group.endswith("."):
            raise ValueError("target_resource_group is invalid")
        if (
            self.allowed_resource_types != sorted(self.allowed_resource_types)
            or len(self.allowed_resource_types) != len(set(self.allowed_resource_types))
            or any(not _RESOURCE_TYPE.fullmatch(item) for item in self.allowed_resource_types)
        ):
            raise ValueError("allowed_resource_types must be unique, sorted AzureRM types")
        if self.maximum_delete_count > self.maximum_resource_changes:
            raise ValueError("maximum_delete_count exceeds maximum_resource_changes")
        if self.maximum_replace_count > self.maximum_resource_changes:
            raise ValueError("maximum_replace_count exceeds maximum_resource_changes")
        if (self.monthly_budget_microunits is None) != (self.budget_currency is None):
            raise ValueError("budget amount and currency must be provided together")
        if self.monthly_budget_microunits is not None and self.monthly_budget_microunits > 10**15:
            raise ValueError("monthly budget exceeds the contract limit")
        return self


class SavedPlanReferenceV1(StrictContract):
    blob_name: str = Field(min_length=1, max_length=1_024)
    etag: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=SHA256_PATTERN)
    plan_job_digest: str = Field(pattern=SHA256_PATTERN)
    bundle_sha256: str = Field(pattern=SHA256_PATTERN)
    input_variables_sha256: str = Field(pattern=SHA256_PATTERN)
    scope_digest: str = Field(pattern=SHA256_PATTERN)
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("blob_name")
    @classmethod
    def validate_blob_name(cls, value: str) -> str:
        if not _SAFE_PATH.fullmatch(value) or ".." in value.split("/") or not value.endswith(".tfplan"):
            raise ValueError("saved plan blob_name is invalid")
        return value


class VerifiedCostEstimateV1(StrictContract):
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    monthly_cost_microunits: int = Field(ge=0)
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        normalized = value.astimezone(timezone.utc)
        if normalized > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("captured_at cannot be in the future")
        return normalized


class ApplyApprovalV1(StrictContract):
    approval_id: str
    decision: Literal["approved"]
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    apply_job_id: str
    plan_job_digest: str = Field(pattern=SHA256_PATTERN)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)
    plan_etag: str = Field(min_length=1, max_length=256)
    bundle_sha256: str = Field(pattern=SHA256_PATTERN)
    input_variables_sha256: str = Field(pattern=SHA256_PATTERN)
    scope_digest: str = Field(pattern=SHA256_PATTERN)
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    cost_estimate_sha256: str = Field(pattern=SHA256_PATTERN)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    monthly_cost_microunits: int = Field(ge=0)

    @field_validator("approval_id", "approved_by", "apply_job_id")
    @classmethod
    def validate_ids(cls, value: str, info: Any) -> str:
        return _canonical_uuid(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_approval_window(self) -> "ApplyApprovalV1":
        for field_name in ("approved_at", "expires_at"):
            value = getattr(self, field_name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must include a timezone")
        approved_at = self.approved_at.astimezone(timezone.utc)
        expires_at = self.expires_at.astimezone(timezone.utc)
        if approved_at > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("approved_at cannot be in the future")
        if expires_at <= approved_at or expires_at - approved_at > timedelta(hours=24):
            raise ValueError("approval expiry must be after approval and within 24 hours")
        return self


class TerraformApplyEnvelopeV1(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    operation: Literal["apply"] = "apply"
    job_id: str
    tenant_id: str
    project_id: str
    user_id: str
    workflow_id: str
    revision: int = Field(ge=1)
    bundle: BundleReferenceV1
    input_variables: InputVariablesReferenceV1
    guardrails: ExecutionGuardrailsV1
    state_key: str
    target_subscription_id: str
    target_tenant_id: str
    iac_engine: Literal["opentofu"]
    terraform_version: Literal["1.13.2"]
    requested_at: datetime
    saved_plan: SavedPlanReferenceV1
    cost_estimate: VerifiedCostEstimateV1
    approval: ApplyApprovalV1
    job_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator(
        "job_id",
        "tenant_id",
        "project_id",
        "user_id",
        "workflow_id",
        "target_subscription_id",
        "target_tenant_id",
    )
    @classmethod
    def validate_envelope_ids(cls, value: str, info: Any) -> str:
        return _canonical_uuid(value, field=info.field_name)

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("requested_at must include a timezone")
        normalized = value.astimezone(timezone.utc)
        if normalized > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("requested_at cannot be in the future")
        return normalized

    @model_validator(mode="after")
    def verify_bindings(self) -> "TerraformApplyEnvelopeV1":
        material = self.model_dump(mode="json", exclude={"job_digest"})
        if canonical_digest(material) != self.job_digest:
            raise ValueError("job_digest does not match the immutable apply envelope")
        if self.job_id != self.approval.apply_job_id:
            raise ValueError("approval is not bound to this apply job")
        if self.saved_plan.plan_job_digest != self.approval.plan_job_digest:
            raise ValueError("approval plan job binding is invalid")
        if self.saved_plan.sha256 != self.approval.plan_sha256:
            raise ValueError("approval saved-plan digest binding is invalid")
        if self.saved_plan.etag != self.approval.plan_etag:
            raise ValueError("approval saved-plan ETag binding is invalid")
        if self.bundle.sha256 != self.saved_plan.bundle_sha256 or self.bundle.sha256 != self.approval.bundle_sha256:
            raise ValueError("approval bundle binding is invalid")
        if self.input_variables.sha256 != self.saved_plan.input_variables_sha256 or self.input_variables.sha256 != self.approval.input_variables_sha256:
            raise ValueError("approval input-variable binding is invalid")
        if self.guardrails.scope_digest != self.saved_plan.scope_digest or self.guardrails.scope_digest != self.approval.scope_digest:
            raise ValueError("approval scope binding is invalid")
        if self.guardrails.policy_digest != self.saved_plan.policy_digest or self.guardrails.policy_digest != self.approval.policy_digest:
            raise ValueError("approval policy binding is invalid")
        if self.cost_estimate.artifact_sha256 != self.approval.cost_estimate_sha256:
            raise ValueError("approval cost evidence binding is invalid")
        if self.cost_estimate.currency != self.approval.currency or self.cost_estimate.monthly_cost_microunits != self.approval.monthly_cost_microunits:
            raise ValueError("approval cost amount binding is invalid")
        expected_prefix = f"tenants/{self.tenant_id}/workflows/{self.workflow_id}/plans/"
        if not self.saved_plan.blob_name.startswith(expected_prefix):
            raise ValueError("saved plan is outside the tenant workflow prefix")
        if self.cost_estimate.captured_at > self.approval.approved_at.astimezone(timezone.utc):
            raise ValueError("cost evidence was captured after approval")
        if self.approval.expires_at.astimezone(timezone.utc) <= self.requested_at.astimezone(timezone.utc):
            raise ValueError("approval expired before the apply request")
        if self.guardrails.monthly_budget_microunits is not None and (
            self.guardrails.budget_currency != self.cost_estimate.currency
            or self.cost_estimate.monthly_cost_microunits > self.guardrails.monthly_budget_microunits
        ):
            raise ValueError("cost estimate exceeds the approved budget guardrail")
        return self


__all__ = [
    "ApplyApprovalV1",
    "ArtifactReferenceV1",
    "BundleReferenceV1",
    "ExecutionGuardrailsV1",
    "InputVariableDefinitionV1",
    "InputVariablesReferenceV1",
    "RepositoryAnalysisJobV1",
    "SavedPlanReferenceV1",
    "TerraformApplyEnvelopeV1",
    "TerraformGenerationJobV1",
    "TerraformInputVariableV1",
    "VerifiedCostEstimateV1",
    "canonical_digest",
    "canonical_json_bytes",
]

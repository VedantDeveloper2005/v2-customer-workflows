"""Existing-app observations accept facts only from the pinned customer job."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input
from backend.contracts.customer_evidence import ImageObservation

SHA = r"^[0-9a-f]{64}$"


class BaselineInput(Input):
    reader_client_id: UUID
    reader_principal_id: UUID
    environment: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    app_name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,58}[a-z0-9]$")
    registry_name: str = Field(pattern=r"^[a-z][a-z0-9]{4,49}$")
    image_repository: str = Field(max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*){0,5}$")
    image_sha256: str = Field(pattern=SHA)
    image_source_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    build_workflow: str = Field(default=".github/workflows/build.yml", max_length=100, pattern=r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")


class BaselineAttest(Input):
    request_sha256: str = Field(pattern=SHA)


class HealthTelemetry(Input):
    requests: int = Field(strict=True, ge=1, le=2**53-1)
    http_5xx: int = Field(strict=True, ge=0, le=2**53-1)
    minutes: int = Field(strict=True, ge=2, le=10)
    response_sha256: str = Field(pattern=SHA)


class BaselineHealth(Input):
    outcome: Literal["verified"]
    observation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    image_sha256: str = Field(pattern=SHA)
    policy_sha256: str = Field(pattern=SHA)
    checks: list[Literal["synthetic", "dependencies", "azure-monitor"]] = Field(min_length=3, max_length=3)
    samples: int = Field(strict=True, ge=1, le=1000)
    window_start: str = Field(max_length=40)
    window_end: str = Field(max_length=40)
    telemetry: HealthTelemetry
    probe_chain_sha256: str = Field(pattern=SHA)


class BaselineReport(BaselineAttest):
    outcome: Literal["observed", "failed", "unavailable"]
    no_apply: bool = Field(strict=True)
    health: BaselineHealth | None = None
    image: ImageObservation | None = None
    failure_code: Literal["TRUST_REJECTED", "FEDERATION_REJECTED", "IMAGE_UNVERIFIED", "HEALTH_FAILED", "HEALTH_UNAVAILABLE", "API_UNAVAILABLE", "TOOLS_UNAVAILABLE"] | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.no_apply is not True: raise ValueError("Baseline observation never authorizes apply")
        if self.outcome == "observed":
            if not self.health or not self.image or self.image.status != "verified" or self.image.failure_code or not self.image.output_sha256 or self.failure_code: raise ValueError("Observation requires full health and image provenance")
        elif self.health or self.image or not self.failure_code: raise ValueError("Unsuccessful observations contain only a bounded failure code")
        return self


class BaselineDecision(Input):
    observation_sha256: str = Field(pattern=SHA)
    decision: Literal["approve", "reject"]
    confirmed: bool = Field(strict=True)
    scope_acknowledged: bool = Field(default=False, strict=True)
    reason: Literal["WRONG_IMAGE", "UNCLEAR_HEALTH", "WRONG_SCOPE", "CHANGE_NEEDED"] | None = None

    @model_validator(mode="after")
    def consent(self):
        if self.confirmed is not True or (self.decision == "approve" and (not self.scope_acknowledged or self.reason)) or (self.decision == "reject" and not self.reason): raise ValueError("Confirm the exact historical evidence and review scope")
        return self

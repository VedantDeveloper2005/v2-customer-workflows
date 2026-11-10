"""Non-secret exact-artifact execution requests and bounded runner outcomes."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input
from backend.contracts.customer_baseline import BaselineHealth

SHA = r"^[0-9a-f]{64}$"


class ExecutionInput(Input):
    review_sha256: str = Field(pattern=SHA)
    rehearsal_id: UUID
    environment: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    confirmed: bool = Field(strict=True)

    @model_validator(mode="after")
    def consent(self):
        if self.confirmed is not True:
            raise ValueError("Explicit confirmation of this exact approved execution is required")
        return self


class ExecutionAttest(Input):
    request_sha256: str = Field(pattern=SHA)


class ExecutionCheckpoint(ExecutionAttest):
    operation_id: UUID


class ExecutionApply(ExecutionAttest):
    operation_id: UUID
    current_image_sha256: str = Field(pattern=SHA)
    artifact_set_sha256: str = Field(pattern=SHA)


class ExecutionRollback(ExecutionAttest):
    operation_id: UUID
    current_image_sha256: str = Field(pattern=SHA)
    rollback_action_sha256: str = Field(pattern=SHA)


class ExecutionVerify(ExecutionAttest):
    operation_id: UUID
    current_image_sha256: str = Field(pattern=SHA)
    observation_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class UnverifiedHealth(Input):
    outcome: Literal["failed", "unavailable"]
    failure_code: Literal["TARGET_REJECTED", "HTTP_REJECTED", "PROBE_RESPONSE_REJECTED", "PROBE_UNAVAILABLE", "ACTIVE_IMAGE_CHANGED", "AZURE_READ_UNAVAILABLE", "TELEMETRY_THRESHOLD_FAILED", "TELEMETRY_UNAVAILABLE", "TIMING_UNAVAILABLE", "DEPENDENCY_FAILED", "HEALTH_UNAVAILABLE"]
    samples: int = Field(strict=True, ge=0, le=1000)


class ExecutionReport(ExecutionAttest):
    status: Literal["SUCCEEDED", "FAILED", "MANUAL_INTERVENTION"]
    apply_outcome: Literal["not-started", "applied", "failed"]
    artifact_set_sha256: str = Field(pattern=SHA)
    recovery: Literal["not-needed", "verified", "unverified"]
    serving_image_sha256: str | None = Field(default=None, pattern=SHA)
    health: BaselineHealth | UnverifiedHealth | None = None
    recovery_health: BaselineHealth | UnverifiedHealth | None = None
    failure_code: Literal["TRUST_REJECTED", "FEDERATION_REJECTED", "ARTIFACT_MISMATCH", "PLAN_REJECTED", "TOOLS_UNAVAILABLE", "API_UNAVAILABLE", "APPLY_FAILED", "HEALTH_FAILED", "HEALTH_UNAVAILABLE", "ROLLBACK_UNAVAILABLE", "AUTHORITY_REJECTED", "CURRENT_IMAGE_CHANGED", "ROLLBACK_FAILED", "ATOMIC_WRITE_UNAVAILABLE"] | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.status == "SUCCEEDED":
            if self.apply_outcome != "applied" or self.recovery != "not-needed" or not isinstance(self.health, BaselineHealth) or not self.serving_image_sha256 or self.recovery_health or self.failure_code:
                raise ValueError("Success requires applied candidate and full health without recovery")
        elif not self.failure_code:
            raise ValueError("Unsuccessful execution requires a bounded failure code")
        if self.recovery == "verified" and (self.status != "FAILED" or not isinstance(self.recovery_health, BaselineHealth) or not self.serving_image_sha256):
            raise ValueError("Verified recovery is a failed candidate with full previous-image health")
        if self.status == "MANUAL_INTERVENTION" and (self.recovery != "unverified" or self.serving_image_sha256):
            raise ValueError("Uncertain recovery cannot claim a serving image")
        if self.apply_outcome == "not-started" and (self.status != "FAILED" or self.recovery != "not-needed" or self.health or self.recovery_health or self.serving_image_sha256):
            raise ValueError("A pre-write failure has no release health or recovery")
        return self

"""Read-only execution rehearsal and workspace stop inputs."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input


class RehearsalInput(Input):
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reader_client_id: UUID
    reader_principal_id: UUID
    environment: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class RehearsalAttest(Input):
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RehearsalReport(RehearsalAttest):
    outcome: Literal["verified", "failed", "unavailable"]
    no_apply: bool = Field(strict=True)
    artifact_set_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_code: Literal["TRUST_REJECTED", "FEDERATION_REJECTED", "ARTIFACT_MISMATCH", "PLAN_REJECTED", "TOOLS_UNAVAILABLE", "API_UNAVAILABLE"] | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.no_apply is not True: raise ValueError("Rehearsals cannot authorize or report apply")
        if self.outcome == "verified":
            if not self.artifact_set_sha256 or self.failure_code: raise ValueError("Verification requires the exact artifact set")
        elif not self.failure_code or self.artifact_set_sha256:
            raise ValueError("An unsuccessful rehearsal needs only a bounded failure code")
        return self


class WriteControlInput(Input):
    expected_generation: int = Field(strict=True, ge=0, le=2**31 - 2)
    confirmed: bool = Field(strict=True)

    @model_validator(mode="after")
    def confirm(self):
        if self.confirmed is not True: raise ValueError("Explicit confirmation is required")
        return self

"""Strict non-secret customer-runner registration and preflight reports."""
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRunner(Input):
    azure_tenant_id: UUID
    subscription_id: UUID
    client_id: UUID
    principal_id: UUID
    resource_group: str = Field(min_length=1, max_length=90, pattern=r"^[A-Za-z0-9_()-][A-Za-z0-9_.()-]*[A-Za-z0-9_()-]$|^[A-Za-z0-9_()-]$")
    environment: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    subject_format: Literal["immutable", "legacy", "workflow-bound"] = "immutable"


class Generation(Input):
    generation: int = Field(strict=True, ge=1, le=2**31 - 1)


class Attest(Input):
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PreflightReport(Attest):
    outcome: Literal["passed", "failed", "unavailable"]
    identity_match: bool = Field(strict=True)
    scope_match: bool = Field(strict=True)
    reader_only: bool = Field(strict=True)
    permissions_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_code: Literal["IDENTITY_MISMATCH", "SCOPE_MISMATCH", "PERMISSIONS_REJECTED", "AZURE_UNAVAILABLE"] | None = None

    @model_validator(mode="after")
    def coherent_result(self):
        if self.outcome == "passed":
            if not all((self.identity_match, self.scope_match, self.reader_only, self.permissions_sha256)) or self.failure_code:
                raise ValueError("A passed report requires all Reader preflight checks and a permissions digest")
        elif self.failure_code is None:
            raise ValueError("A failed or unavailable report requires a bounded failure code")
        return self

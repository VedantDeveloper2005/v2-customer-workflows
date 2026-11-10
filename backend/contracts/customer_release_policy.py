"""Only versioned configuration is accepted; health cannot be supplied by a user."""
from typing import Literal
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input
from backend.contracts.release_safety import validate


class ReleasePolicy(Input):
    schema_version: Literal["v2.release-policy.v1"] = "v2.release-policy.v1"
    synthetic_path: str
    dependency_path: str
    dependencies: list[str] = Field(min_length=1, max_length=8)
    stabilization_minutes: int = Field(default=3, strict=True, ge=2, le=10)
    poll_seconds: int = Field(default=15, strict=True, ge=15, le=30)
    telemetry_grace_seconds: int = Field(default=120, strict=True, ge=60, le=180)
    min_requests_per_minute: int = Field(default=1, strict=True, ge=1, le=60)
    max_5xx_basis_points: int = Field(default=0, strict=True, ge=0, le=100)
    database_change: Literal["none"] = "none"
    automatic_rollback: bool = Field(default=True, strict=True)
    first_release: Literal["blocked"] = "blocked"

    @model_validator(mode="after")
    def supported(self):
        validate(self.model_dump(mode="json"))
        return self


class SaveReleasePolicy(Input):
    expected_version: int = Field(strict=True, ge=0, le=2**31 - 2)
    confirmed: bool = Field(strict=True)
    policy: ReleasePolicy

    @model_validator(mode="after")
    def confirm(self):
        if self.confirmed is not True: raise ValueError("Confirm that changes invalidate earlier plans and approvals")
        return self

"""Bounded observations from the pinned customer planning workflow."""
from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator
from backend.contracts.customer_runner import Input


class HostingObservation(Input):
    service_plan_id: str = Field(max_length=300, pattern=r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft.Web/serverFarms/[A-Za-z0-9_-]+$")
    sku: str = Field(pattern=r"^(?:B[1-3]|S[1-3]|P[1-3]v[2-4])$")
    instances: int = Field(strict=True, ge=1, le=30)
    location: str = Field(pattern=r"^[a-z][a-z0-9]{1,39}$")
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None: raise ValueError("An observation needs a timezone")
        return value


class ImageObservation(Input):
    status: Literal["verified", "unavailable", "rejected"]
    verifier: Literal["gh-2.103.3"] = "gh-2.103.3"
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    signer_workflow: str = Field(max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
    failure_code: Literal["TOOLS_UNAVAILABLE", "REGISTRY_UNAVAILABLE", "ATTESTATION_REJECTED"] | None = None


class VerifyEvidence(Input):
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

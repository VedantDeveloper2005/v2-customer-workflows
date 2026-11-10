"""Independent source review records intent, never fictional migration tests."""
from typing import Literal
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input


class CompatibilityRequest(Input):
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CompatibilityDecision(Input):
    challenge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approve", "reject"]
    confirmed: bool = Field(strict=True)
    source_reviewed: bool = Field(default=False, strict=True)
    no_database_changes: bool = Field(default=False, strict=True)
    both_images_compatible: bool = Field(default=False, strict=True)
    timing_policy_acknowledged: bool = Field(default=False, strict=True)
    timing_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason: Literal["DATABASE_CHANGE", "UNCLEAR_COMPATIBILITY", "WRONG_IMAGE", "CHANGE_NEEDED"] | None = None

    @model_validator(mode="after")
    def consent(self):
        if self.confirmed is not True: raise ValueError("Confirm this exact review")
        if self.decision == "approve" and (not self.source_reviewed or not self.no_database_changes or not self.both_images_compatible or self.reason): raise ValueError("Review source and explicitly confirm compatibility in both directions without database changes")
        if self.decision == "approve" and (self.timing_policy_acknowledged is not True or not self.timing_policy_sha256): raise ValueError("Acknowledge the exact timing policy for this compatibility statement")
        if self.decision == "reject" and not self.reason: raise ValueError("Choose a bounded rejection reason")
        return self

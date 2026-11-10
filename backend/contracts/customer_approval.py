"""Human review inputs contain exact hashes and bounded decision codes only."""
from typing import Literal
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input


class RequestApproval(Input):
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ApprovalDecision(Input):
    challenge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approve", "reject"]
    confirmed: bool = Field(strict=True)
    cost_scope_acknowledged: bool = Field(default=False, strict=True)
    cost_scope_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    timing_policy_acknowledged: bool = Field(default=False, strict=True)
    timing_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason: Literal["CHANGE_NEEDED", "COST_UNCLEAR", "WRONG_TARGET", "SECURITY_CONCERN"] | None = None

    @model_validator(mode="after")
    def explicit_decision(self):
        if not self.confirmed or (self.decision == "reject" and not self.reason) or (self.decision == "approve" and self.reason):
            raise ValueError("An explicit confirmation and a bounded rejection reason are required")
        if self.decision == "approve" and (self.timing_policy_acknowledged is not True or not self.timing_policy_sha256):
            raise ValueError("Acknowledge the exact approved timing policy before approving")
        return self

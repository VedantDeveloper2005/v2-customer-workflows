"""Inputs for credential-free, single-resource-group Azure audit consent."""
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class StartAudit(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    subscription_id: UUID
    resource_group: str = Field(min_length=1, max_length=90, pattern=r"^[A-Za-z0-9_()-][A-Za-z0-9_.()-]*[A-Za-z0-9_()-]$|^[A-Za-z0-9_()-]$")


class AuditGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generation: int = Field(strict=True, ge=1, le=2**31 - 1)

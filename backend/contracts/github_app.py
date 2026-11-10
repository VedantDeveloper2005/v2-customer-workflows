"""Strict user inputs for the read-only GitHub App integration."""

from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SetupInput(Input):
    state: str = Field(min_length=32, max_length=4096)
    installation_id: int = Field(strict=True, gt=0, le=2**63 - 1)


class StartExistingInput(Input):
    account_login: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$")


class CompleteInput(Input):
    state: str = Field(min_length=32, max_length=4096)
    code: str = Field(min_length=1, max_length=1024)


class ConnectionInput(Input):
    connection_id: UUID
    generation: int = Field(strict=True, ge=1, le=2**31 - 1)


class ImportInput(ConnectionInput):
    repository_id: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    branch: str = Field(min_length=1, max_length=255)

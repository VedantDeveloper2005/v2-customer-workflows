"""Non-secret inputs and bounded customer-runner planning evidence."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from backend.contracts.customer_runner import Input
from backend.contracts.customer_evidence import HostingObservation, ImageObservation

SHA = r"^[0-9a-f]{64}$"
NAME = r"^[a-z][a-z0-9-]{1,58}[a-z0-9]$"


class PlanInput(Input):
    operation: Literal["create", "update-image"] = "create"
    baseline_id: UUID | None = None
    currency: Literal["USD", "INR"] = "USD"
    build_workflow: str = Field(default=".github/workflows/build.yml", max_length=100, pattern=r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
    planning_client_id: UUID
    planning_principal_id: UUID
    environment: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    execution_environment: str = Field(default="v2-execution", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    app_name: str = Field(pattern=NAME)
    location: str = Field(pattern=r"^[a-z][a-z0-9]{1,39}$")
    service_plan_name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,60}$")
    registry_name: str = Field(pattern=r"^[a-z][a-z0-9]{4,49}$")
    runtime_identity_name: str = Field(pattern=r"^[A-Za-z0-9_-]{3,60}$")
    runtime_client_id: UUID
    image_repository: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*){0,5}$", max_length=128)
    image_sha256: str = Field(pattern=SHA)
    container_port: int = Field(strict=True, ge=1, le=65535)
    storage_account: str = Field(pattern=r"^[a-z][a-z0-9]{2,23}$")
    state_container: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", min_length=3, max_length=63)
    plans_container: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", min_length=3, max_length=63)

    @model_validator(mode="after")
    def separate_storage(self):
        if self.state_container == self.plans_container:
            raise ValueError("State and protected plans require separate containers")
        if self.execution_environment == self.environment:
            raise ValueError("Declare a separate protected execution environment before approval")
        if (self.operation == "update-image") != (self.baseline_id is not None):
            raise ValueError("Image updates require a qualified baseline; creates cannot adopt one")
        return self


class PlanAttest(Input):
    request_sha256: str = Field(pattern=SHA)


class Artifact(Input):
    sha256: str = Field(pattern=SHA)
    size_bytes: int = Field(strict=True, ge=1, le=32 * 1024 * 1024)
    blob_name: str = Field(max_length=160, pattern=r"^plans/[0-9a-f-]{36}/(?:what-if|saved-plan|bundle|image-provenance)-[0-9a-f]{64}$")
    version_id: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,24}Z$", max_length=40)
    etag: str = Field(pattern=r'^"0x[0-9A-Fa-f]{8,32}"$')


class PlanReport(PlanAttest):
    outcome: Literal["reviewable", "failed", "unavailable"]
    # No raw ARM/Tofu output, arbitrary text, prices, URLs, settings or secrets.
    artifacts: dict[Literal["what-if", "saved-plan", "bundle", "image-provenance"], Artifact] = Field(default_factory=dict, max_length=4)
    hosting: HostingObservation | None = None
    image: ImageObservation | None = None
    bundle_sha256: str | None = Field(default=None, pattern=SHA)
    execution_request_sha256: str | None = Field(default=None, pattern=SHA)
    create_count: int = Field(default=0, strict=True, ge=0, le=1)
    update_count: int = Field(default=0, strict=True, ge=0, le=1)
    failure_code: Literal["TOOLS_UNAVAILABLE", "IDENTITY_MISMATCH", "AZURE_UNAVAILABLE", "STORAGE_REJECTED", "PLAN_REJECTED", "PLAN_FAILED"] | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.outcome == "reviewable":
            if not {"what-if", "saved-plan", "bundle"} <= set(self.artifacts) or not self.bundle_sha256 or not self.execution_request_sha256 or self.create_count + self.update_count != 1 or self.failure_code:
                raise ValueError("Review requires both plans, the exact bundle and execution binding")
            if self.image and self.image.status == "verified":
                if self.image.failure_code or not self.image.output_sha256 or "image-provenance" not in self.artifacts or self.artifacts["image-provenance"].sha256 != self.image.output_sha256:
                    raise ValueError("Verified image evidence requires its exact protected verification output")
            elif "image-provenance" in self.artifacts:
                raise ValueError("Provenance artifacts require a verified image observation")
        elif not self.failure_code or self.artifacts or self.bundle_sha256 or self.execution_request_sha256 or self.create_count or self.update_count or self.hosting or self.image:
            raise ValueError("A failed report requires only a bounded failure code")
        return self

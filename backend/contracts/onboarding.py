"""Read-only onboarding records; these never authorize cloud execution."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class OnboardingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OnboardingAction(OnboardingRecord):
    label: str
    href: str


class OnboardingStep(OnboardingRecord):
    id: str
    title: str
    status: Literal["complete", "in_progress", "pending", "blocked", "unavailable"]
    detail: str
    action: OnboardingAction | None = None


class OnboardingProject(OnboardingRecord):
    id: UUID
    name: str
    branch: str
    source_type: Literal["github", "zip", "unknown"]


class OnboardingWorkspace(OnboardingRecord):
    id: UUID
    name: str
    kind: str
    role: str


class OnboardingSnapshot(OnboardingRecord):
    schema_version: Literal["v2.onboarding.v1"] = "v2.onboarding.v1"
    actor_user_id: UUID
    generated_at: datetime
    workspace: OnboardingWorkspace
    projects: list[OnboardingProject]
    project_count: int
    selected_project: OnboardingProject | None
    steps: list[OnboardingStep]
    completed_steps: int
    total_steps: int
    next_step_id: str | None
    deployment_authorization: Literal["not_evaluated"] = "not_evaluated"

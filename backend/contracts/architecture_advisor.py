"""Strict contracts for Microsoft Foundry Architecture Advisor outputs.

The architecture advisor is an advisory/reasoning component that uses GPT-5.6 Terra,
File Search (zeroops-knowledge vector store), and Web Search. It does NOT generate
Terraform, execute deployments, or modify approved infrastructure plans directly.
Only services supported by the ZeroOps capability/allowlist can progress to deployment.
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictAdvisorContract(BaseModel):
    """Base contract rejecting unknown fields and stripping whitespace."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ComponentRecommendation(StrictAdvisorContract):
    """An individual architecture component recommended by the advisor."""

    id: str = Field(description="Unique identifier for the component (e.g. application, database)")
    role: str = Field(description="Component architectural role or category (e.g. Application runtime, Database)")
    service: str = Field(description="Target Azure service name (e.g. Azure App Service, Azure Database for PostgreSQL Flexible Server)")
    proposed_sku: str | None = Field(default=None, description="Recommended SKU tier or sizing (e.g. B1, Burstable B1ms)")
    instance_count: str | int | None = Field(default=None, description="Instance count or min/max autoscale bounds")
    reason: str = Field(description="Detailed rationale for selecting this component and SKU")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence references from repository facts or knowledge")
    security_requirements: list[str] = Field(default_factory=list, description="Security configurations (e.g. VNet integration, managed identity)")
    availability_recovery: str | None = Field(default=None, description="Availability targets, backup schedule, or recovery considerations")
    cost_status: str | None = Field(default=None, description="Cost driver notes or qualitative sizing tier")
    validation_required: list[str] = Field(default_factory=list, description="Pre-deployment validation required before provisioning")
    deployable: bool = Field(default=False, description="Whether ZeroOps deployment automation currently supports this service")
    status_note: str | None = Field(
        default=None,
        description="Deployment status note (e.g. 'Supported by current engine' or 'Advisory recommendation — deployment automation not currently supported')",
    )


class CitationEvidence(StrictAdvisorContract):
    """Structured citation returned by the Foundry Agent tools."""

    id: str = Field(description="Citation identifier")
    source_type: Literal["knowledge", "web", "repository", "assumption"] = Field(
        description="Distinguishes ZeroOps knowledge evidence, current web documentation, repository facts, and assumptions"
    )
    title: str | None = Field(default=None, description="Title or source heading")
    citation: str = Field(description="Excerpt, URL, or citation text")
    url: str | None = Field(default=None, description="Source URL if from Web Search")


class ArchitectureRecommendation(StrictAdvisorContract):
    """Clean internal result model for architecture advisor recommendations."""

    schema_version: Literal["architecture-recommendation.v1"] = "architecture-recommendation.v1"
    recommendation: str = Field(description="Executive architectural summary and overall recommendation")
    confidence: Literal["high", "medium", "low"] = Field(description="Confidence level based on available evidence")
    assumptions: list[str] = Field(default_factory=list, description="Explicit assumptions made when sizing or choosing services")
    missing_information: list[str] = Field(default_factory=list, description="Important questions or unmeasured metrics needed for exact sizing")
    proposed_components: list[ComponentRecommendation] = Field(default_factory=list, description="Recommended Azure architecture components")
    cost_status: str = Field(default="requires_connected_azure_subscription", description="Cost status or explanation")
    cost_considerations: list[str] = Field(default_factory=list, description="Qualitative cost drivers, pricing uncertainties, or tradeoffs")
    evidence_sources: list[CitationEvidence] = Field(default_factory=list, description="Evidence and citations from File Search, Web Search, or repository")
    unsupported_services: list[str] = Field(default_factory=list, description="Services recommended that are not currently automated by ZeroOps")
    validation_required: list[str] = Field(default_factory=list, description="Ordered checklist of checks required before provisioning")
    provenance: dict[str, Any] = Field(default_factory=dict, description="Metadata on agent name, version, latency, tokens, and correlation ID")


__all__ = [
    "StrictAdvisorContract",
    "ComponentRecommendation",
    "CitationEvidence",
    "ArchitectureRecommendation",
]

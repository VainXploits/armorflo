"""
armorflo/models.py
------------------
Typed Pydantic models for ArmorFlo.
ArmorFloAction and ArmorFloObservation subclass the OpenEnv spec base classes
so that the environment passes openenv validate and the HTTP server works correctly.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from openenv.core.env_server.types import Action, Observation


class CvssVector(BaseModel):
    attack_vector: Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"] = "NETWORK"
    attack_complexity: Literal["LOW", "HIGH"] = "LOW"
    privileges_required: Literal["NONE", "LOW", "HIGH"] = "NONE"
    user_interaction: Literal["NONE", "REQUIRED"] = "NONE"
    scope: Literal["UNCHANGED", "CHANGED"] = "UNCHANGED"
    confidentiality: Literal["NONE", "LOW", "HIGH"] = "NONE"
    integrity: Literal["NONE", "LOW", "HIGH"] = "NONE"
    availability: Literal["NONE", "LOW", "HIGH"] = "NONE"


class VulnerabilityReport(BaseModel):
    cve_id: str
    title: str
    description: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: CvssVector
    affected_products: List[str]
    patch_available: bool
    exploit_public: bool
    published_date: str
    references: List[str] = Field(default_factory=list)


class AssetRecord(BaseModel):
    asset_id: str
    name: str
    product: str
    version: str
    environment: Literal["production", "staging", "development"]
    internet_facing: bool
    business_criticality: Literal["critical", "high", "medium", "low"]


class RemediationStep(BaseModel):
    priority: int
    action: str
    target_asset_ids: List[str]
    rationale: str


class ArmorFloAction(Action):
    """
    Single triage action. Set action_type and fill the matching fields.
    All other fields default to empty / empty list.

    action_type choices:
      assess              — query for more context on a CVE or asset
      classify            — declare CVSS severity tier + affected components
      check_applicability — mark a CVE applicable/not-applicable for an asset
      recommend           — submit a prioritised remediation plan
      escalate            — escalate to a team with justification
      defer               — defer a CVE with documented reason
      close               — close the report with final summary
    """
    action_type: Literal[
        "assess",
        "classify",
        "check_applicability",
        "recommend",
        "escalate",
        "defer",
        "close",
    ] = Field(..., description="Which triage action to perform")

    query: str = Field(default="", description="Context query (assess)")

    severity_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", ""] = Field(
        default="", description="CVSS severity tier (classify)"
    )
    affected_components: List[str] = Field(
        default_factory=list,
        description="Affected asset_ids or product names (classify)",
    )
    cvss_score_estimate: float = Field(
        default=0.0, ge=0.0, le=10.0,
        description="Agent CVSS base score estimate (classify)",
    )

    cve_id: str = Field(default="", description="CVE ID (check_applicability)")
    asset_id: str = Field(default="", description="Asset ID (check_applicability)")
    applicable: bool = Field(default=True)
    inapplicability_reason: str = Field(default="")

    remediation_plan: List[RemediationStep] = Field(
        default_factory=list,
        description="Ordered remediation steps (recommend)",
    )

    team: Literal["security", "platform", "network", "development", "management", ""] = Field(
        default="", description="Team to escalate to"
    )
    justification: str = Field(default="")

    defer_reason: str = Field(default="")
    defer_until: str = Field(default="", description="ISO date YYYY-MM-DD")

    resolution_summary: str = Field(
        default="",
        description="Full post-triage summary: findings, decisions, actions, rationale",
    )


class ArmorFloObservation(Observation):
    """
    Full observation returned by reset() and step().
    `reward` and `done` are inherited from openenv.core.env_server.types.Observation.
    """
    task_id: str = Field(default="")
    report_id: str = Field(default="")
    step_count: int = Field(default=0)
    max_steps: int = Field(default=20)

    reports: List[VulnerabilityReport] = Field(default_factory=list)
    assets: List[AssetRecord] = Field(default_factory=list)

    applicability_decisions: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    assess_result: Optional[str] = Field(default=None)

    score_breakdown: Dict[str, float] = Field(default_factory=dict)


class RewardBreakdown(BaseModel):
    severity_score: float = 0.0
    cvss_score_accuracy: float = 0.0
    applicability_score: float = 0.0
    remediation_score: float = 0.0
    escalation_score: float = 0.0
    summary_quality: float = 0.0
    efficiency_bonus: float = 0.0
    loop_penalty: float = 0.0
    false_positive_penalty: float = 0.0

    @property
    def total(self) -> float:
        raw = (
            self.severity_score        * 0.20
            + self.cvss_score_accuracy * 0.10
            + self.applicability_score * 0.20
            + self.remediation_score   * 0.25
            + self.escalation_score    * 0.10
            + self.summary_quality     * 0.15
            + self.efficiency_bonus
            - self.loop_penalty
            - self.false_positive_penalty
        )
        return max(0.0, min(1.0, round(raw, 4)))

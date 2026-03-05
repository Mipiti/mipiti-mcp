"""Pydantic response models for the Mipiti API.

All models use ``extra="allow"`` so new API fields pass through automatically
as attributes — no client update needed when the backend adds fields.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


# ------------------------------------------------------------------
# Base
# ------------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow")


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------


class SecurityProperty(str, Enum):
    C = "C"
    I = "I"  # noqa: E741
    A = "A"
    U = "U"


# ------------------------------------------------------------------
# Domain models
# ------------------------------------------------------------------


class Asset(_Base):
    id: str
    name: str
    description: str = ""
    security_properties: list[SecurityProperty] = []
    impact: str = "M"
    notes: str = ""


class Attacker(_Base):
    id: str
    capability: str
    position: str = ""
    archetype: str = ""
    likelihood: str = "M"


class TrustBoundary(_Base):
    id: str
    description: str
    crosses: list[str] = []


class ControlObjective(_Base):
    id: str
    asset_id: str
    security_property: SecurityProperty | None = None
    security_properties: list[SecurityProperty] = []
    attacker_id: str
    statement: str
    risk_tier: str = "medium"


class Assumption(_Base):
    id: str
    description: str
    status: str = "active"


class ControlEvidence(_Base):
    type: str = "code"
    label: str = ""
    url: str = ""
    collected_at: str = ""
    collected_by: str = ""


class Control(_Base):
    id: str
    control_objective_ids: list[str] = []
    description: str
    status: str = "not_implemented"
    implementation_notes: str = ""
    evidence: list[ControlEvidence] = []
    source: str = ""
    source_label: str = ""
    framework_refs: list[str] = []
    is_verified: bool = False
    verification_status: str = "pending"


class ThreatModel(_Base):
    id: str = ""
    feature_description: str = ""
    title: str = ""
    version: int = 1
    created_at: str = ""
    trust_boundaries: list[TrustBoundary] = []
    assets: list[Asset] = []
    attackers: list[Attacker] = []
    control_objectives: list[ControlObjective] = []
    assumptions: list[Assumption] = []


class ModelSummary(_Base):
    id: str
    title: str = ""
    feature_description: str = ""
    created_at: str = ""
    version: int = 1


# ------------------------------------------------------------------
# SSE streaming results
# ------------------------------------------------------------------


class GenerateResult(_Base):
    """Result from generate/refine SSE stream (``result`` event)."""
    threat_model: ThreatModel = ThreatModel()
    model_id: str = ""
    version: int = 1
    markdown: str = ""
    csv: str = ""


class ChatResponse(_Base):
    """Result from query/general SSE stream (``chat_response`` event)."""
    content: str = ""


# ------------------------------------------------------------------
# Controls responses
# ------------------------------------------------------------------


class ControlsResponse(_Base):
    controls: list[Control] = []
    model_id: str = ""
    model_version: int = 0


class EvidenceActionResult(_Base):
    control_id: str = ""
    evidence_count: int = 0


class ImportConfirmResult(_Base):
    imported: int = 0
    controls: list[Control] = []


class DeleteControlResult(_Base):
    deleted: bool = False
    control_id: str = ""


class GapAnalysisResult(_Base):
    suggestions: list[dict[str, Any]] = []
    model_id: str = ""


class ScanPromptResult(_Base):
    control_id: str = ""
    prompt: str = ""
    message: str = ""


class ControlObjectivesResponse(_Base):
    model_id: str = ""
    version: int = 1
    total: int = 0
    returned: int = 0
    control_objectives: list[dict[str, Any]] = []


# ------------------------------------------------------------------
# Assurance
# ------------------------------------------------------------------


class AssessmentResult(_Base):
    """Deterministic assurance assessment result."""
    pass


class ReviewQueueResponse(_Base):
    """Stale controls not reviewed in 90+ days."""
    items: list[dict[str, Any]] = []


# ------------------------------------------------------------------
# Compliance
# ------------------------------------------------------------------


class ComplianceFramework(_Base):
    id: str
    name: str = ""
    version: str = ""
    description: str = ""
    source: str = ""
    total_requirements: int = 0


class SelectFrameworksResult(_Base):
    model_id: str = ""
    selected_frameworks: list[str] = []
    added: list[str] = []
    framework_count: int = 0


class ComplianceReport(_Base):
    framework_id: str = ""
    framework_name: str = ""
    coverage: int = 0


class AutoMapResult(_Base):
    mappings_created: int = 0
    controls_mapped: int = 0
    controls_total: int = 0


class RemediationSuggestions(_Base):
    suggestions: list[dict[str, Any]] = []
    gap_count: int = 0


class RemediationApplyResult(_Base):
    assets_added: int = 0
    attackers_added: int = 0
    exclusions_created: int = 0
    controls_generated: int = 0
    mappings_created: int = 0
    version: int = 0


# ------------------------------------------------------------------
# Workspaces & Systems
# ------------------------------------------------------------------


class Workspace(_Base):
    id: str = ""
    name: str = ""
    description: str = ""
    is_personal: bool = False


class System(_Base):
    id: str = ""
    workspace_id: str = ""
    name: str = ""
    description: str = ""
    model_count: int = 0


class SystemSelectFrameworksResult(_Base):
    system_id: str = ""
    selected_frameworks: list[str] = []
    model_count: int = 0
    propagated_to_models: int = 0


# ------------------------------------------------------------------
# Assertions & Verification
# ------------------------------------------------------------------


class EvidenceAssertion(_Base):
    id: str = ""
    control_id: str = ""
    model_id: str = ""
    type: str = ""
    params: dict[str, Any] = {}
    description: str = ""
    tier1_status: str = "pending"
    tier2_status: str = "pending"


class SubmitAssertionsResult(_Base):
    assertions: list[EvidenceAssertion] = []
    coherence_warnings: list[dict[str, Any]] = []


class VerificationReport(_Base):
    model_id: str = ""
    version: int = 0
    total_assertions: int = 0
    tier1: dict[str, int] = {}
    tier2: dict[str, int] = {}
    controls: dict[str, dict[str, int]] = {}


class MarkEvidenceCompleteResult(_Base):
    model_id: str = ""
    control_id: str = ""
    marked_at: str = ""
    sufficiency_status: str = "pending"


# ------------------------------------------------------------------
# Findings
# ------------------------------------------------------------------


class Finding(_Base):
    id: str = ""
    control_id: str = ""
    model_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    status: str = "discovered"


# ------------------------------------------------------------------
# Generic action results
# ------------------------------------------------------------------


class RenameResult(_Base):
    id: str = ""
    title: str = ""


class OkResult(_Base):
    ok: bool = False

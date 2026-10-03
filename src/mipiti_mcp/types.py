"""Pydantic response models for the Mipiti API.

All models use ``extra="allow"`` so new API fields pass through automatically
as attributes — no client update needed when the backend adds fields.

A model declares only what the answer it parses carries: a declared field the
answer lacks is read back as its default, and an agent reports that default as
fact. A field only some variants of an answer carry defaults to ``None``, which
reads as "not sent".
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
    # Soft-delete lifecycle. A deleted asset keeps its ID forever
    # (never reused); its linked (asset × attacker) control objectives
    # tombstone, and controls mapped to those COs surface as orphaned.
    # Restore via POST /assets/{id}/restore (MCP: restore_asset tool).
    deleted: bool = False
    deleted_at: str = ""
    deleted_by: str = ""


class Attacker(_Base):
    id: str
    capability: str
    position: str = ""
    archetype: str = ""
    likelihood: str = "M"
    # Same soft-delete lifecycle as Asset.
    deleted: bool = False
    deleted_at: str = ""
    deleted_by: str = ""


class TrustBoundary(_Base):
    id: str
    description: str
    crosses: list[str] = []


class ControlObjective(_Base):
    id: str
    asset_id: str
    security_properties: list[SecurityProperty] = []
    attacker_id: str
    statement: str
    risk_tier: str = "medium"
    # Tombstone: a CO whose (asset, attacker) pair was removed in a
    # later version. The CO ID stays allocated forever (never reused)
    # so controls referring to it surface as "orphaned" rather than
    # silently rebinding to a different pair. Filter removed=True out
    # of live-CO views (coverage math, LLM prompts, etc.).
    removed: bool = False
    removed_at: str = ""
    removed_in_version: int = 0


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
    verification_status: str = "pending"
    # Derived at read time: True when every mapped CO is tombstoned.
    # Orphaned controls are hidden from the default get_controls
    # listing — pass include_orphaned=True to see them. Remap to
    # live COs via remap_control, or soft-delete explicitly.
    orphaned: bool = False


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
    # Refine-path semantic guard surfaces entries here when the LLM
    # proposed a rewrite that would have semantically replaced an
    # existing asset/attacker under its stable ID. Each entry:
    #   {"kind": "asset"|"attacker", "id": "A-N"|"T-N",
    #    "classification": "replace"|"ambiguous"|"unavailable",
    #    "reason": "...", "per_field": {...}}
    # The corresponding entity's identity fields in ``threat_model``
    # were reverted to pre-refine values, so the LLM's proposed
    # rewrite did not apply. Agents surfacing a refine result to the
    # operator should check this array and present each rejection. Sent by
    # a broad refine only; ``None`` on a generation or a targeted edit, which
    # run no such guard.
    semantic_rejections: list[dict[str, Any]] | None = None


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
    total: int = 0
    returned: int = 0


class ControlSummary(_Base):
    """A control as the compact (``summary_only``) listing gives it."""
    id: str
    description: str
    status: str = "not_implemented"
    verification_status: str = "pending"
    assertion_count: int = 0
    co_ids: list[str] = []
    assumption_groups: dict[str, list[str]] = {}
    attestation_dependency: Any = None


class ControlSummariesResponse(_Base):
    """The compact (``summary_only``) control listing."""
    controls: list[ControlSummary] = []
    model_id: str = ""
    model_version: int = 0
    total: int = 0
    returned: int = 0


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
    """One of three answers: one control's prompt (``control_id`` and
    ``prompt``); the batch of every control not yet implemented
    (``controls``, ``included``, ``total_controls``, ``truncated``); or, when
    every control is implemented, a ``message``."""
    control_id: str | None = None
    prompt: str | None = None
    message: str | None = None
    controls: list[dict[str, Any]] | None = None
    included: int | None = None
    total_controls: int | None = None
    truncated: bool | None = None


class ControlObjectivesResponse(_Base):
    """The count, and, when ``offset``/``limit`` asked for them, the
    objectives themselves (``None`` when they were not asked for)."""
    model_id: str = ""
    version: int = 1
    total: int = 0
    returned: int | None = None
    control_objectives: list[dict[str, Any]] | None = None


# ------------------------------------------------------------------
# Assurance
# ------------------------------------------------------------------


class AssessmentResult(_Base):
    """Deterministic assurance assessment result."""
    pass


class ReviewQueueResponse(_Base):
    """What needs a person, ranked; each row's ``item_type`` names its kind
    (escalation, proposal, unaccepted_assumption, open_assumption,
    stale_control)."""
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
    """The frameworks selected, and the auto-remediation job started for each
    (none when the model has no controls yet)."""
    selected: list[str] = []
    auto_remediate_jobs: list[dict[str, Any]] = []


class ComplianceReport(_Base):
    """A model's or a system's report on one framework (the scope's id is
    ``model_id`` or ``system_id``)."""
    framework_id: str = ""
    framework_name: str = ""
    total_requirements: int = 0
    covered: int = 0
    partial: int = 0
    uncovered: int = 0
    unmapped: int = 0
    excluded: int = 0
    coverage_percent: float = 0.0
    assessments: list[dict[str, Any]] = []


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
    # Remediation can also reanimate soft-deleted entities whose
    # identity matches a proposal (via the restore-candidate LLM gate).
    # Callers that report "what changed" to the operator should
    # include restored counts alongside added counts.
    assets_restored: int = 0
    attackers_restored: int = 0
    restored_asset_ids: list[str] = []
    restored_attacker_ids: list[str] = []
    # Per-proposal skip reasons — populated for ``similar`` verdicts and
    # fail-closed LLM failures. Each entry: {"kind": "asset"|"attacker",
    # "name"|"capability": "...", "reason": "..."}.
    skipped: list[dict] = []
    exclusions_created: int = 0
    # The control objectives the remediation's new version left without a
    # control, for which a control build is now proposed. Nothing is built
    # until a person starts that build.
    build_proposed_for: list[str] = []
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
    """A system. The listing gives each one's ``model_count``; creating or
    reading one gives its ``model_ids`` (and, read, its ``models``)."""
    id: str = ""
    workspace_id: str = ""
    name: str = ""
    description: str = ""
    model_count: int | None = None
    model_ids: list[str] | None = None


class SystemSelectFrameworksResult(_Base):
    """The frameworks selected, and how many member models they reached."""
    selected: list[str] = []
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
    total_assertions: int = 0
    tier1: dict[str, int] = {}
    tier2: dict[str, int] = {}
    controls_fully_verified: int = 0
    controls_partially_verified: int = 0
    controls_unverified: int = 0
    controls_total_filtered: int = 0
    controls_returned: int = 0
    control_details: list[dict[str, Any]] = []


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
# Findings / Risk aggregates
# ------------------------------------------------------------------


class FindingsRisksReport(_Base):
    """Workspace-scoped triage dashboard combining open findings, active
    risk acceptances, and at-risk Control Objectives across every model
    the workspace can access. Field shapes (severity, status, risk_tier,
    impact, likelihood, etc.) are validated server-side; per-row dicts
    are surfaced verbatim so new attributes added on the backend pass
    through automatically via ``extra="allow"``."""

    workspace_id: str = ""
    evaluated_at: str = ""
    models: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    risk_acceptances: list[dict[str, Any]] = []
    at_risk_cos: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}


class ModelRiskView(_Base):
    """Per-model Prioritized Risk View. One row per live Control
    Objective with derived risk tier, asset impact, attacker
    likelihood, control coverage counts, and open-finding count."""

    model_id: str = ""
    model_title: str = ""
    total: int = 0
    rows: list[dict[str, Any]] = []


class SystemRiskView(_Base):
    """System-level cross-model Prioritized Risk View. One row per live
    Control Objective across every model in the system, with model
    context attached to each row."""

    system_id: str = ""
    system_name: str = ""
    total: int = 0
    models: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []


# ------------------------------------------------------------------
# Generic action results
# ------------------------------------------------------------------


class RenameResult(_Base):
    id: str = ""
    title: str = ""


class OkResult(_Base):
    ok: bool = False

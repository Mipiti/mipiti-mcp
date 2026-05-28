"""Unit tests for MCP tool implementations."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.types import (
    ChatResponse,
    Control,
    ControlsResponse,
    FindingsRisksReport,
    GenerateResult,
    ModelRiskView,
    ModelSummary,
    RenameResult,
    SystemRiskView,
    ThreatModel,
)
from mipiti_mcp.server import (
    add_asset,
    add_attacker,
    add_evidence,
    add_model_to_system,
    assess_model,
    auto_remediate,
    auto_map_controls,
    check_control_gaps,
    create_system,
    delete_assertion,
    delete_control,
    delete_threat_model,
    get_control_assumption_groups,
    set_control_assumption_groups,
    edit_asset,
    edit_attacker,
    export_threat_model,
    export_threat_model_archive,
    generate_threat_model,
    import_threat_model_archive,
    get_compliance_report,
    get_control_objectives,
    get_controls,
    get_findings_risks,
    get_model_risk_view,
    get_review_queue,
    get_scan_prompt,
    get_system,
    get_system_compliance_report,
    get_system_risk_view,
    get_threat_model,
    get_verification_report,
    import_controls,
    list_assertions,
    list_compliance_frameworks,
    list_findings,
    list_risk_acceptances,
    list_systems,
    list_threat_models,
    list_workspaces,
    map_control_to_requirement,
    query_threat_model,
    refine_threat_model,
    regenerate_controls,
    remove_asset,
    remove_attacker,
    remove_evidence,
    rename_threat_model,
    select_compliance_frameworks,
    select_system_compliance_frameworks,
    submit_assertions,
    submit_findings,
    refine_control,
    remap_control,
    reevaluate_threat_model_factors,
    restore_asset,
    restore_attacker,
    update_control_status,
    update_finding,
    model_coherence_report,
    get_reachability_verdicts,
    get_composition_overview,
    list_effective_entities,
    list_effective_control_objectives,
    get_effective_coverage,
    get_reach_verdicts,
    list_effective_attack_paths,
    list_reconciliation_candidates,
    apply_certain_reconciliation_match,
    reject_reconciliation_candidate,
    unreject_reconciliation_candidate,
    list_reconciliation_rejections,
    lift_composition_entity,
    split_composition_entity,
    preview_undo_lift_composition,
    undo_lift_composition_event,
    preview_undo_split_composition,
    undo_split_composition_event,
    get_control_objective,
    get_asset,
    get_attacker,
    get_component,
    get_trust_boundary,
    get_assumption,
    get_control,
)

from .conftest import SAMPLE_CONTROLS, SAMPLE_MODELS_LIST, SAMPLE_THREAT_MODEL


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------



def _mock_client(**overrides: AsyncMock) -> AsyncMock:
    """Create a mocked MipitiClient with sensible defaults."""
    client = AsyncMock()
    client.api_url = "https://api.mipiti.io"

    _tm = ThreatModel.model_validate(SAMPLE_THREAT_MODEL)
    _controls = [Control.model_validate(c) for c in SAMPLE_CONTROLS["controls"]]

    defaults = {
        "generate_threat_model": GenerateResult(threat_model=_tm, model_id="tm-001", version=1),
        "refine_threat_model": GenerateResult(threat_model=_tm, model_id="tm-001", version=2),
        "query_threat_model": ChatResponse(content="The model covers SQL injection."),
        "list_models": [ModelSummary.model_validate(m) for m in SAMPLE_MODELS_LIST],
        "get_model": _tm,
        "rename_model": RenameResult(id="tm-001", title="New"),
        "delete_model": None,
        "start_export_model": "job_export_csv",
        "start_export_model_full": "job_export_full",
        "fetch_operation_result": b"AssetID,Name\nA1,Tokens\n",
        "get_controls": ControlsResponse(controls=_controls),
        "regenerate_controls": {"job_id": "job_regen"},
        "update_control_status": {"id": "CTRL-01", "status": "implemented"},
        "add_evidence": {"control_id": "CTRL-01", "evidence_count": 2},
        "remove_evidence": {"control_id": "CTRL-01", "evidence_count": 0},
        "import_controls": {"imported": 3},
        "delete_control": {"deleted": True},
        "check_control_gaps": {"job_id": "job_gaps"},
        "get_scan_prompt": {"prompt": "Scan for..."},
        "get_control_objectives": {"model_id": "tm-001", "total": 1},
        # Realistic API envelope shape: the backend returns a dict
        # with `model` + carry-forward metadata, not a raw entity.
        "add_asset": {"model": {"id": "tm-001", "assets": [{"id": "A3"}]},
                      "controls_carried": 0, "controls_orphaned": 0},
        "edit_asset": {"model": {"id": "tm-001", "assets": [{"id": "A1"}]},
                       "controls_carried": 0, "controls_orphaned": 0},
        "remove_asset": {"model": {"id": "tm-001", "assets": []},
                         "controls_carried": 0, "controls_orphaned": 0},
        "add_attacker": {"model": {"id": "tm-001", "attackers": [{"id": "T2"}]},
                         "controls_carried": 0, "controls_orphaned": 0},
        "edit_attacker": {"model": {"id": "tm-001", "attackers": [{"id": "T1"}]},
                          "controls_carried": 0, "controls_orphaned": 0},
        "remove_attacker": {"model": {"id": "tm-001", "attackers": []},
                            "controls_carried": 0, "controls_orphaned": 0},
        "reevaluate_factors": {
            "model_id": "tm-001",
            "assets_reevaluated": 2,
            "attackers_reevaluated": 1,
            "deltas": {
                "assets": [
                    {
                        "id": "A1",
                        "before": {
                            "confidentiality_subscore": "Medium",
                            "integrity_subscore": "Medium",
                            "availability_subscore": "Low",
                            "usage_subscore": "Low",
                            "blast_radius": "Single",
                            "recoverability": "Hours",
                            "regulatory_scope": "None",
                            "impact": "Medium",
                            "impact_rationale": "old",
                        },
                        "after": {
                            "confidentiality_subscore": "High",
                            "integrity_subscore": "Medium",
                            "availability_subscore": "Low",
                            "usage_subscore": "Low",
                            "blast_radius": "Single",
                            "recoverability": "Hours",
                            "regulatory_scope": "None",
                            "impact": "High",
                            "impact_rationale": "new",
                        },
                    },
                ],
                "attackers": [
                    {
                        "id": "T1",
                        "before": {
                            "attack_vector": "Network",
                            "privileges_required": "None",
                            "attack_complexity": "Low",
                            "user_interaction": "None",
                            "capability_prevalence": "Commodity",
                            "likelihood": "High",
                            "likelihood_rationale": "old",
                        },
                        "after": {
                            "attack_vector": "Network",
                            "privileges_required": "None",
                            "attack_complexity": "High",
                            "user_interaction": "None",
                            "capability_prevalence": "Niche",
                            "likelihood": "Medium",
                            "likelihood_rationale": "new",
                        },
                    },
                ],
            },
        },
        "assess_model": {"mitigated": 1, "at_risk": 0},
        "get_review_queue": {"items": []},
        "list_compliance_frameworks": {"frameworks": [{"id": "owasp-asvs"}]},
        "select_compliance_frameworks": {"selected": 1},
        "get_compliance_report": {"coverage": 0.8},
        "map_control_to_requirement": {"mapped": True},
        "auto_map_controls": {"job_id": "job_automap"},
        "auto_remediate": {"job_id": "job_auto_rem"},
        "get_operation": {"status": "completed", "result": {}},
        "select_system_compliance_frameworks": {"selected": 1},
        "get_system_compliance_report": {"coverage": 0.9},
        "submit_assertions": {"count": 2},
        "list_assertions": {"assertions": []},
        "delete_assertion": None,
        "get_verification_report": {"tier1_pass": 3},
        "submit_findings": {"count": 1},
        "list_findings": {"findings": []},
        "update_finding": {"id": "f1", "status": "acknowledged"},
        # Findings / risk aggregate defaults — clients return Pydantic
        # response models; the tool wrapper passes through unchanged via
        # _dump. The defaults below mirror the production response shape.
        "get_findings_risks": FindingsRisksReport(
            workspace_id="ws-1",
            evaluated_at="2026-05-13T00:00:00Z",
            models=[{"id": "tm-001", "title": "Login Service"}],
            findings=[{
                "id": "F-1", "model_id": "tm-001", "model_title": "Login Service",
                "control_id": "CTRL-01", "severity": "high",
                "status": "discovered", "title": "Missing rate limit",
                "created_at": "2026-05-01T00:00:00Z", "risk_tier": "high",
            }],
            risk_acceptances=[{
                "id": "RA-1", "model_id": "tm-001", "model_title": "Login Service",
                "control_objective_id": "CO1", "owner": "Platform Team",
                "justification": "Mitigated by upstream WAF.",
                "status": "active",
                "accepted_at": "2026-03-01T00:00:00Z",
                "review_by": "2026-09-01T00:00:00Z", "risk_tier": "medium",
            }],
            at_risk_cos=[{
                "model_id": "tm-002", "model_title": "Payments Service",
                "co_id": "CO9", "statement": "Protect data at rest",
                "asset_name": "Card Token Store",
                "attacker_capability": "Insider with DB access",
                "impact": "H", "likelihood": "M", "risk_tier": "high",
                "total_controls": 4, "implemented_controls": 2,
                "verified_controls": 1,
                "missing_controls": ["CTRL-09", "CTRL-10"],
                "risk_reason": "missing_controls",
            }],
            summary={
                "open_findings": 1, "total_findings": 1,
                "active_risk_acceptances": 1, "total_risk_acceptances": 1,
                "at_risk_cos": 1,
            },
        ),
        "get_model_risk_view": ModelRiskView(
            model_id="tm-001", model_title="Login Service", total=1,
            rows=[{
                "co_id": "CO1", "co_statement": "Protect session tokens",
                "asset_id": "A1", "asset_name": "Session Token",
                "attacker_id": "T1", "attacker_capability": "Network adversary",
                "impact": "H", "likelihood": "M", "risk_tier": "high",
                "total_controls": 3, "implemented_controls": 2,
                "verified_controls": 1, "open_findings": 1,
                "coverage_ratio": 0.66,
            }],
        ),
        "get_system_risk_view": SystemRiskView(
            system_id="sys-1", system_name="Customer Platform", total=2,
            models=[
                {"id": "tm-001", "title": "Login Service"},
                {"id": "tm-002", "title": "Payments Service"},
            ],
            rows=[
                {
                    "model_id": "tm-001", "model_title": "Login Service",
                    "co_id": "CO1", "co_statement": "Protect session tokens",
                    "asset_id": "A1", "asset_name": "Session Token",
                    "attacker_id": "T1", "attacker_capability": "Network adversary",
                    "impact": "H", "likelihood": "M", "risk_tier": "high",
                    "total_controls": 3, "implemented_controls": 2,
                    "verified_controls": 1, "open_findings": 1,
                    "coverage_ratio": 0.66,
                },
                {
                    "model_id": "tm-002", "model_title": "Payments Service",
                    "co_id": "CO9", "co_statement": "Protect data at rest",
                    "asset_id": "A4", "asset_name": "Card Token Store",
                    "attacker_id": "T3", "attacker_capability": "Insider",
                    "impact": "H", "likelihood": "M", "risk_tier": "high",
                    "total_controls": 4, "implemented_controls": 2,
                    "verified_controls": 1, "open_findings": 0,
                    "coverage_ratio": 0.5,
                },
            ],
        ),
        "list_risk_acceptances": [
            {
                "id": "RA-1", "model_id": "tm-001",
                "control_objective_id": "CO1",
                "owner": "Platform Team",
                "justification": "Mitigated by upstream WAF.",
                "status": "active",
                "accepted_at": "2026-03-01T00:00:00Z",
                "review_by": "2026-09-01T00:00:00Z",
            },
        ],
        "list_workspaces": {"workspaces": []},
        "list_systems": {"systems": []},
        "get_system": {"id": "sys-1", "name": "Platform"},
        "create_system": {"id": "sys-2", "name": "New"},
        "add_model_to_system": {"added": True},
        "refine_control": {"accepted": True, "reason": "Coverage maintained.", "control": {"id": "CTRL-01"}},
        "remap_control": {
            "control": {"id": "CTRL-01", "control_objective_ids": ["CO1", "CO3"]},
            "model_id": "tm-001", "model_version": 2,
            "change_reason": "Restore mappings after v1->v2 renumber",
        },
        "restore_asset": {"id": "A1", "deleted": False},
        "restore_attacker": {"id": "T1", "deleted": False},
        "get_control_assumption_groups": {
            "control_id": "CTRL-01",
            "control_description": "Test control",
            "groups": {"1": [{"id": "AS1", "description": "AWS KMS", "active": True, "missing": False}]},
            "unmapped": [],
        },
        "set_control_assumption_groups": {
            "control_id": "CTRL-01",
            "assumption_groups": {"1": ["AS1"]},
            "justification": "AWS KMS handles this control.",
        },
        "model_coherence_report": {
            "model_id": "tm-001", "model_version": 1,
            "components_count": 1,
            "findings": [{"type": "co_asset_unbounded", "severity": "medium",
                          "co_id": "CO3", "asset_id": "A1", "attacker_id": "T1",
                          "reason": "asset_unbounded", "message": "...", "narration": "..."}],
            "summary": {"total": 1, "by_type": {}, "by_severity": {}},
        },
        "model_reachability_verdicts": {
            "model_id": "tm-001", "model_version": 1,
            "verdicts": [{"co_id": "CO3", "kind": "indeterminate",
                          "reason": "asset_unbounded", "narration": "...",
                          "boundary_id": "", "assumption_id": ""}],
        },
        # Composition (recursive-tree effective model) defaults. Flag-on
        # shapes mirror the live backend payloads (see
        # backend/app/routes/composition.py + composition_index.empty_index).
        "composition_index": {
            "model_id": "tm-001", "model_version": 1, "flag_enabled": True,
            "tree": {"parent_id": None, "ancestor_chain": [],
                     "depth": 0, "child_ids": []},
            "counts": {
                "entities": {
                    "trust_boundaries": {"own": 1, "inherited": 0},
                    "components": {"own": 0, "inherited": 0},
                    "assets": {"own": 2, "inherited": 0},
                    "attackers": {"own": 1, "inherited": 0},
                },
                "control_objectives": {
                    "total": 1, "live": 1, "covered": 1, "uncovered": 0,
                    "indeterminate": 0,
                    "by_origin": {"own": 1, "cross": 0, "inherited": 0},
                },
                "reconciliation_candidates": {"certain": 0, "heuristic": 0},
            },
            "warnings": [],
        },
        "composition_entities": {
            "model_id": "tm-001", "flag_enabled": True,
            "kinds": {
                "trust_boundaries": [],
                "components": [],
                "assets": [
                    {"kind": "asset",
                     "qualified_id": "tm-001::A1",
                     "owner_model_id": "tm-001",
                     "owner_title": "Login",
                     "origin": "own",
                     "entity": {"id": "A1", "name": "Tokens"}},
                ],
                "attackers": [],
            },
        },
        "composition_control_objectives": {
            "model_id": "tm-001", "flag_enabled": True,
            "control_objectives": [
                {"co_qid": "tm-001::CO1",
                 "asset_qid": "tm-001::A1",
                 "attacker_qid": "tm-001::T1",
                 "security_properties": ["C"],
                 "origin": "own"},
            ],
        },
        "composition_coverage": {
            "model_id": "tm-001", "flag_enabled": True,
            "coverage": [
                {"co_qid": "tm-001::CO1",
                 "is_covered": True,
                 "own_credit": 1.0,
                 "inherited_credit": 0.0,
                 "contributing_controls": [
                     {"control_id": "CTRL-01",
                      "owner_model_id": "tm-001",
                      "origin": "own",
                      "is_verified": False,
                      "mitigation_group": 1},
                 ]},
            ],
        },
        "composition_reachability": {
            "model_id": "tm-001", "flag_enabled": True,
            "verdicts": [
                {"co_qid": "tm-001::CO1",
                 "asset_qid": "tm-001::A1",
                 "attacker_qid": "tm-001::T1",
                 "kind": "indeterminate",
                 "reason": "asset_unbounded"},
            ],
        },
        "composition_attack_paths": {
            "model_id": "tm-001", "flag_enabled": True,
            "effective_paths": [],
            "lattice_positions": 0,
            "authored_paths": 0,
            "suggestions": {"missing_path": [], "dangling_path": []},
        },
        "composition_reconciliation": {
            "model_id": "tm-001", "flag_enabled": True,
            "total": 0,
            "tiers": {"certain": 0, "heuristic": 0},
            "page": 1, "page_size": 50,
            "candidates": [],
        },
        "apply_certain_reconciliation_match": {
            "model": {"id": "tm-001", "assets": []},
            "controls_carried": 0,
            "controls_orphaned": 0,
            "orphaned_control_ids": [],
        },
        "reject_reconciliation_candidate": {
            "id": "rej-001",
            "model_id": "tm-001",
            "kind": "assets",
            "own_qid": "child:A1",
            "inherited_qid": "parent:A1",
            "rejected_by": "user-1",
            "rejected_at": "2026-05-27T00:00:00+00:00",
        },
        "unreject_reconciliation_candidate": {"ok": True},
        "list_reconciliation_rejections": {
            "model_id": "tm-001", "flag_enabled": True, "rejections": [],
        },
        "lift_composition_entity": {
            "lift_id": "lift-001",
            "lca_model": {"id": "tm-lca", "assets": [{"id": "A1"}]},
            "descendant_a_model": {"id": "tm-da", "assets": []},
            "descendant_b_model": {"id": "tm-db", "assets": []},
            "applied_migrations": [],
            "lift_event": {
                "lift_id": "lift-001",
                "kind": "assets",
                "source_model_ids": ["tm-da", "tm-db"],
                "source_entity_ids": ["A1", "A1"],
                "lca_model_id": "tm-lca",
                "new_entity_id": "A1",
            },
        },
        "split_composition_entity": {
            "split_id": "split-001",
            "ancestor_model": {"id": "tm-anc", "assets": []},
            "descendant_models": [
                {"id": "tm-d1", "assets": [{"id": "A1"}]},
                {"id": "tm-d2", "assets": [{"id": "A1"}]},
            ],
            "applied_duplications": [],
            "split_event": {
                "split_id": "split-001",
                "kind": "assets",
                "ancestor_model_id": "tm-anc",
                "source_entity_id": "A1",
                "target_descendants": ["tm-d1", "tm-d2"],
                "new_entity_ids": {"tm-d1": "A1", "tm-d2": "A1"},
            },
        },
        "preview_lift_undo": {
            "plan": {
                "kind": "lift",
                "original_event_id": "lift-001",
                "state_ops": [],
            },
            "refusal": None,
        },
        "undo_lift": {
            "undone_event_id": "undo-001",
            "original_event_id": "lift-001",
            "applied_state_ops": [],
            "models": {
                "lca_model": {"id": "tm-lca", "assets": []},
                "source_descendant_models": [
                    {"id": "tm-da", "assets": [{"id": "A1"}]},
                    {"id": "tm-db", "assets": [{"id": "A1"}]},
                ],
            },
        },
        "preview_split_undo": {
            "plan": {
                "kind": "split",
                "original_event_id": "split-001",
                "state_ops": [],
            },
            "refusal": None,
        },
        "undo_split": {
            "undone_event_id": "undo-002",
            "original_event_id": "split-001",
            "applied_state_ops": [],
            "models": {
                "ancestor_model": {"id": "tm-anc", "assets": [{"id": "A1"}]},
                "descendant_models": [
                    {"id": "tm-d1", "assets": []},
                    {"id": "tm-d2", "assets": []},
                ],
            },
        },
        "get_control_objective": {
            "model_id": "tm-001", "model_version": 1,
            "control_objective": {"id": "CO3", "asset_id": "A1", "attacker_id": "T1",
                                  "security_properties": ["C"], "statement": "...",
                                  "risk_tier": "medium", "boundary_reachable": False,
                                  "boundary_unreachable_reason": "", "removed": False,
                                  "removed_at": "", "removed_in_version": 0,
                                  "controls": []},
            "reachability_verdict": {"kind": "indeterminate", "reason": "asset_unbounded",
                                     "narration": "...", "boundary_id": "",
                                     "assumption_id": ""},
        },
        "get_asset": {"model_id": "tm-001", "model_version": 1,
                       "asset": {"id": "A1", "name": "Tokens"}},
        "get_attacker": {"model_id": "tm-001", "model_version": 1,
                          "attacker": {"id": "T1", "capability": "Network"}},
        "get_component": {"model_id": "tm-001", "model_version": 1,
                           "component": {"id": "C1", "name": "api", "repo_url": ""}},
        "get_trust_boundary": {"model_id": "tm-001", "model_version": 1,
                                "trust_boundary": {"id": "TB1", "passes": ["Network"]}},
        "get_assumption": {"model_id": "tm-001", "model_version": 1,
                            "assumption": {"id": "AS1", "description": "x",
                                           "deleted": False, "exclusion": None}},
        "get_control": {"model_id": "tm-001", "model_version": 1,
                         "control": {"id": "CTRL-01", "description": "test"}},
    }

    for name, default_val in defaults.items():
        mock_fn = overrides.get(name, AsyncMock(return_value=default_val))
        setattr(client, name, mock_fn)

    return client


def _mock_ctx() -> AsyncMock:
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()
    return ctx


def _patch_client(mock=None):
    if mock is None:
        mock = _mock_client()
    return patch("mipiti_mcp.server._get_client", return_value=mock)


# ------------------------------------------------------------------
# Threat Model Generation & Management
# ------------------------------------------------------------------


class TestGenerateThreatModel:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await generate_threat_model(server_version="0", feature_description="User login", ctx=ctx)
        assert result["model_id"] == "tm-001"
        assert result["asset_count"] == 2
        mock.generate_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_similar_models_short_circuit(self) -> None:
        """Backend returns similar_models instead of generating. Tool
        must pass the candidate IDs through with a suggestion, not
        raise a tool error."""
        mock = _mock_client(generate_threat_model=AsyncMock(return_value={
            "similar_models": [
                {"id": "tm-existing", "title": "Login Page",
                 "reason": "Same auth surface."},
            ],
        }))
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await generate_threat_model(
                server_version="0",
                feature_description="User login",
                ctx=ctx,
            )
        assert "similar_models" in result
        assert result["similar_models"][0]["id"] == "tm-existing"
        assert "refine_threat_model" in result["suggestion"]
        assert "force=True" in result["suggestion"]

    @pytest.mark.asyncio
    async def test_force_is_forwarded_to_client(self) -> None:
        """The `force` tool arg must reach the client as
        ``force_generate=True`` — otherwise retry-with-force has no
        effect and the agent stays stuck on the similar-models loop."""
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            await generate_threat_model(
                server_version="0",
                feature_description="User login",
                ctx=ctx,
                force=True,
            )
        call_kwargs = mock.generate_threat_model.await_args.kwargs
        assert call_kwargs.get("force_generate") is True


class TestRefineThreatModel:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(server_version="0", model_id="tm-001", instruction="Add CSRF", ctx=ctx)
        assert result["model_id"] == "tm-001"
        # Live-count keys are present and agree with mock shape.
        assert "live_asset_count" in result
        assert "live_attacker_count" in result
        assert "live_control_objective_count" in result
        # Semantic-rejections array surfaced (empty on happy path).
        assert result["semantic_rejections"] == []
        mock.refine_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_semantic_rejections_surfaced(self) -> None:
        """When the refine-path guard reverted an identity-bearing
        rewrite, the tool must pass the rejection array through so
        the agent can surface what refine chose not to apply."""
        from mipiti_mcp.types import GenerateResult, ThreatModel
        rejected = GenerateResult(
            threat_model=ThreatModel(id="tm-001", title="t"),
            model_id="tm-001",
            version=3,
            semantic_rejections=[
                {
                    "kind": "asset", "id": "A-04",
                    "classification": "replace",
                    "reason": "Rename from OIDC Token to CI Attestation Bundle is a different asset.",
                    "per_field": {"name": "OIDC Token -> CI Attestation Bundle"},
                },
            ],
        )
        mock = _mock_client(refine_threat_model=AsyncMock(return_value=rejected))
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(
                server_version="0", model_id="tm-001",
                instruction="Rename A-04", ctx=ctx,
            )
        rejections = result["semantic_rejections"]
        assert len(rejections) == 1
        assert rejections[0]["kind"] == "asset"
        assert rejections[0]["id"] == "A-04"
        assert rejections[0]["classification"] == "replace"

    @pytest.mark.asyncio
    async def test_live_counts_exclude_soft_deleted(self) -> None:
        """live_asset_count / live_attacker_count / live_control_
        objective_count must exclude soft-deleted / tombstoned entries
        so agents don't surface stale totals."""
        from mipiti_mcp.types import (
            GenerateResult, ThreatModel, Asset, Attacker, ControlObjective,
        )
        tm = ThreatModel(
            id="tm-001",
            title="t",
            assets=[
                Asset(id="A1", name="Live"),
                Asset(id="A2", name="Dead", deleted=True),
            ],
            attackers=[
                Attacker(id="T1", capability="Live"),
                Attacker(id="T2", capability="Dead", deleted=True),
            ],
            control_objectives=[
                ControlObjective(id="CO1", asset_id="A1", attacker_id="T1", statement="s"),
                ControlObjective(id="CO2", asset_id="A2", attacker_id="T1",
                                 statement="", removed=True),
            ],
        )
        mock = _mock_client(refine_threat_model=AsyncMock(
            return_value=GenerateResult(threat_model=tm, model_id="tm-001", version=2),
        ))
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(
                server_version="0", model_id="tm-001",
                instruction="..", ctx=ctx,
            )
        assert result["asset_count"] == 2
        assert result["live_asset_count"] == 1
        assert result["attacker_count"] == 2
        assert result["live_attacker_count"] == 1
        assert result["control_objective_count"] == 2
        assert result["live_control_objective_count"] == 1


class TestProgressChannelClosed:
    """Streaming tools must tolerate the MCP progress channel closing
    mid-call. A ClosedResourceError from ctx.report_progress means the
    client is no longer listening, but the upstream work has already
    completed and persisted — the tool must still return its result
    instead of raising.
    """

    @pytest.mark.asyncio
    async def test_generate_returns_result_when_channel_closed(self) -> None:
        from anyio import ClosedResourceError

        async def _client_call(_desc, force_generate=False, on_progress=None):
            if on_progress is not None:
                await on_progress(1.0, 5.0, "Working")
            _tm = ThreatModel.model_validate(SAMPLE_THREAT_MODEL)
            return GenerateResult(threat_model=_tm, model_id="tm-001", version=1)

        mock = _mock_client(generate_threat_model=AsyncMock(side_effect=_client_call))
        ctx = AsyncMock()
        ctx.report_progress = AsyncMock(side_effect=ClosedResourceError())
        ctx.info = AsyncMock()
        with _patch_client(mock):
            result = await generate_threat_model(
                server_version="0",
                feature_description="Test feature",
                ctx=ctx,
            )
        assert result["model_id"] == "tm-001"

    @pytest.mark.asyncio
    async def test_refine_returns_result_when_channel_broken(self) -> None:
        from anyio import BrokenResourceError

        async def _client_call(_model_id, _instruction, on_progress=None):
            if on_progress is not None:
                await on_progress(2.0, 5.0, "Refining")
            _tm = ThreatModel.model_validate(SAMPLE_THREAT_MODEL)
            return GenerateResult(threat_model=_tm, model_id="tm-001", version=2)

        mock = _mock_client(refine_threat_model=AsyncMock(side_effect=_client_call))
        ctx = AsyncMock()
        ctx.report_progress = AsyncMock(side_effect=BrokenResourceError())
        ctx.info = AsyncMock()
        with _patch_client(mock):
            result = await refine_threat_model(
                server_version="0",
                model_id="tm-001",
                instruction="Add CSRF",
                ctx=ctx,
            )
        assert result["model_id"] == "tm-001"


class TestQueryThreatModel:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await query_threat_model(server_version="0", model_id="tm-001", question="SQL injection?", ctx=ctx)
        assert result["answer"] == "The model covers SQL injection."


class TestListThreatModels:
    @pytest.mark.asyncio
    async def test_returns_items(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_threat_models(server_version="0")
        assert result["count"] == 2
        assert result["items"][0]["id"] == "tm-001"
        # Default: lean response, no assessment_summary field
        assert "assessment_summary" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_empty(self) -> None:
        mock = _mock_client(list_models=AsyncMock(return_value=[]))
        with _patch_client(mock):
            result = await list_threat_models(server_version="0")
        assert result["count"] == 0

    @pytest.mark.asyncio
    async def test_source_filter_forwarded(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await list_threat_models(server_version="0", source="mcp")
        mock.list_models.assert_awaited_once_with(source="mcp", include="")

    @pytest.mark.asyncio
    async def test_include_assessment_summary_forwards_include_param(self) -> None:
        """When the caller requests posture, the tool must pass include=
        to the backend so the list response inlines the summary."""
        mock = _mock_client()
        with _patch_client(mock):
            await list_threat_models(
                server_version="0", include_assessment_summary=True,
            )
        mock.list_models.assert_awaited_once_with(
            source="", include="assessment_summary",
        )

    @pytest.mark.asyncio
    async def test_include_assessment_summary_surfaces_in_items(self) -> None:
        """When the backend returns an inlined assessment, the tool copies
        it onto each item as `assessment_summary`."""
        # Build a ModelSummary with the inlined assessment via extra="allow".
        tm_with_asmt = ModelSummary.model_validate({
            "id": "tm-001",
            "title": "Login API",
            "feature_description": "...",
            "created_at": "2026-01-01T00:00:00+00:00",
            "version": 1,
            "assessment": {
                "summary": {"mitigated": 9, "at_risk": 3, "unassessed": 0},
                "message": "13 controls not implemented, blocking 3 COs.",
            },
        })
        mock = _mock_client(list_models=AsyncMock(return_value=[tm_with_asmt]))
        with _patch_client(mock):
            result = await list_threat_models(
                server_version="0", include_assessment_summary=True,
            )
        assert result["count"] == 1
        item = result["items"][0]
        assert item["id"] == "tm-001"
        assert "assessment_summary" in item
        assert item["assessment_summary"]["summary"]["at_risk"] == 3
        assert "13 controls" in item["assessment_summary"]["message"]


class TestRenameThreatModel:
    @pytest.mark.asyncio
    async def test_rename(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await rename_threat_model(server_version="0", model_id="tm-001", name="New Name")
        assert result["title"] == "New"
        mock.rename_model.assert_awaited_once_with("tm-001", "New Name")


class TestDeleteThreatModel:
    @pytest.mark.asyncio
    async def test_delete(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await delete_threat_model(server_version="0", model_id="tm-001")
        assert result["deleted"] is True
        mock.delete_model.assert_awaited_once()


class TestExportThreatModelArchive:
    @pytest.mark.asyncio
    async def test_returns_envelope(self) -> None:
        import json as _json
        envelope = {
            "format_version": 1,
            "title": "Checkout",
            "versions": [{"version": 1, "data": {}, "created_at": "2026-04-20T00:00:00Z"}],
        }
        mock = _mock_client(
            start_export_model_full=AsyncMock(return_value="job_full_1"),
            get_operation=AsyncMock(return_value={"status": "completed", "result": {
                "kind": "file", "filename": "audit.json",
                "content_type": "application/json", "content_b64": "",
            }}),
            fetch_operation_result=AsyncMock(
                return_value=_json.dumps(envelope).encode("utf-8"),
            ),
        )
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await export_threat_model_archive(
                server_version="0", model_id="tm-001", ctx=ctx,
            )
        assert result["envelope"] == envelope
        mock.start_export_model_full.assert_awaited_once_with("tm-001")
        mock.fetch_operation_result.assert_awaited_once_with("job_full_1")


class TestImportThreatModelArchive:
    @pytest.mark.asyncio
    async def test_imports_and_returns_new_id(self) -> None:
        mock = _mock_client()
        mock.import_model_full = AsyncMock(return_value={"model_id": "tm-new"})
        envelope = {"format_version": 1, "versions": [{"version": 1, "data": {}}]}
        with _patch_client(mock):
            result = await import_threat_model_archive(
                server_version="0", envelope=envelope, workspace_id="ws-1",
            )
        assert result["model_id"] == "tm-new"
        mock.import_model_full.assert_awaited_once_with(envelope, "ws-1")

    @pytest.mark.asyncio
    async def test_requires_envelope_dict(self) -> None:
        with _patch_client():
            with pytest.raises(ToolError):
                await import_threat_model_archive(
                    server_version="0", envelope="not a dict", workspace_id="ws-1",  # type: ignore[arg-type]
                )

    @pytest.mark.asyncio
    async def test_requires_workspace_id(self) -> None:
        with _patch_client():
            with pytest.raises(ToolError):
                await import_threat_model_archive(
                    server_version="0", envelope={"format_version": 1}, workspace_id="",
                )


class TestGetThreatModel:
    @pytest.mark.asyncio
    async def test_latest(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_threat_model(server_version="0", model_id="tm-001")
        assert result["id"] == "tm-001"
        mock.get_model.assert_awaited_once_with("tm-001", None)

    @pytest.mark.asyncio
    async def test_specific_version(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await get_threat_model(server_version="0", model_id="tm-001", version=3)
        mock.get_model.assert_awaited_once_with("tm-001", 3)


class TestExportThreatModel:
    @pytest.mark.asyncio
    async def test_csv(self) -> None:
        mock = _mock_client(
            start_export_model=AsyncMock(return_value="job_csv_1"),
            get_operation=AsyncMock(return_value={"status": "completed", "result": {
                "kind": "file", "filename": "report.csv",
                "content_type": "text/csv", "content_b64": "",
            }}),
            fetch_operation_result=AsyncMock(return_value=b"AssetID,Name\nA1,Tokens\n"),
        )
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await export_threat_model(
                server_version="0", model_id="tm-001", ctx=ctx, format="csv",
            )
        assert result["format"] == "csv"
        assert result["filename"] == "report.csv"
        assert "AssetID,Name" in result["content"]
        mock.start_export_model.assert_awaited_once_with("tm-001", "csv")

    @pytest.mark.asyncio
    async def test_pdf_returns_b64(self) -> None:
        import base64 as _b64
        pdf_bytes = b"%PDF-binary"
        mock = _mock_client(
            start_export_model=AsyncMock(return_value="job_pdf_1"),
            get_operation=AsyncMock(return_value={"status": "completed", "result": {
                "kind": "file", "filename": "report.pdf",
                "content_type": "application/pdf", "content_b64": "",
            }}),
            fetch_operation_result=AsyncMock(return_value=pdf_bytes),
        )
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await export_threat_model(
                server_version="0", model_id="tm-001", ctx=ctx, format="pdf",
            )
        assert result["format"] == "pdf"
        assert result["filename"] == "report.pdf"
        assert result["content_type"] == "application/pdf"
        assert _b64.b64decode(result["content_b64"]) == pdf_bytes
        mock.start_export_model.assert_awaited_once_with("tm-001", "pdf")

    @pytest.mark.asyncio
    async def test_invalid_format(self) -> None:
        ctx = _mock_ctx()
        with pytest.raises(ToolError, match="format must be"):
            await export_threat_model(
                server_version="0", model_id="tm-001", ctx=ctx, format="xml",
            )


# ------------------------------------------------------------------
# Controls
# ------------------------------------------------------------------


class TestGetControls:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await get_controls(server_version="0", model_id="tm-001", ctx=ctx)
        assert result["total"] == 2
        assert result["returned"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_status(self) -> None:
        """Status filter is passed to the backend (server-side filtering)."""
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            await get_controls(server_version="0", model_id="tm-001", ctx=ctx, status="implemented")
        mock.get_controls.assert_awaited_once()
        call_kwargs = mock.get_controls.call_args[1]
        assert call_kwargs["status"] == "implemented"

    @pytest.mark.asyncio
    async def test_pagination(self) -> None:
        """Offset/limit are passed to the backend (server-side pagination)."""
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            await get_controls(server_version="0", model_id="tm-001", ctx=ctx, offset=0, limit=1)
        mock.get_controls.assert_awaited_once()
        call_kwargs = mock.get_controls.call_args[1]
        assert call_kwargs["limit"] == 1


class TestRegenerateControls:
    @pytest.mark.asyncio
    async def test_with_backend_job(self) -> None:
        mock = _mock_client()
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"controls": [{"id": "CTRL-01"}], "total": 1},
        })
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await regenerate_controls(server_version="0", model_id="tm-001", ctx=ctx)
        assert result["total"] == 1
        mock.get_operation.assert_awaited_once_with("job_regen")


class TestUpdateControlStatus:
    @pytest.mark.asyncio
    async def test_valid_status(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await update_control_status(server_version="0", model_id="tm-001", control_id="CTRL-01", status="implemented")
        assert result["status"] == "implemented"

    @pytest.mark.asyncio
    async def test_invalid_status(self) -> None:
        with pytest.raises(ToolError, match="status must be"):
            await update_control_status(server_version="0", model_id="tm-001", control_id="CTRL-01", status="invalid")



class TestRefineControl:
    @pytest.mark.asyncio
    async def test_accepted(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await refine_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                description="Updated description matching implementation.",
                justification="Implementation uses FastAPI Depends, not middleware.",
            )
        assert result["accepted"] is True
        mock.refine_control.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rejected(self) -> None:
        mock = _mock_client(
            refine_control=AsyncMock(return_value={
                "accepted": False,
                "reason": "CO1 would no longer be satisfied.",
                "per_co": {"CO1": {"satisfied": False, "reasoning": "Weakened."}},
            }),
        )
        with _patch_client(mock):
            result = await refine_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                description="Weaker description.",
                justification="Trying to weaken the control.",
            )
        assert result["accepted"] is False
        assert "CO1" in result["per_co"]

    @pytest.mark.asyncio
    async def test_empty_description_and_findings(self) -> None:
        with pytest.raises(ToolError, match="Either description or codebase_findings is required"):
            await refine_control(server_version="0", model_id="tm-001", control_id="CTRL-01", description="  ", justification="Some justification here.")

    @pytest.mark.asyncio
    async def test_short_justification(self) -> None:
        with pytest.raises(ToolError, match="justification must be at least 10"):
            await refine_control(server_version="0", model_id="tm-001", control_id="CTRL-01", description="New desc.", justification="Short")


class TestRemapControl:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await remap_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                co_ids="CO1, CO3",
                change_reason="Restore mappings after v1->v2 renumber",
            )
        assert "control" in result
        mock.remap_control.assert_awaited_once()
        args = mock.remap_control.await_args
        assert args.args[2] == ["CO1", "CO3"]

    @pytest.mark.asyncio
    async def test_empty_co_ids_rejected(self) -> None:
        with pytest.raises(ToolError, match="at least one CO ID"):
            await remap_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                co_ids="",
                change_reason="Any valid change reason here.",
            )

    @pytest.mark.asyncio
    async def test_short_change_reason_rejected(self) -> None:
        with pytest.raises(ToolError, match="at least 10"):
            await remap_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                co_ids="CO1",
                change_reason="short",
            )


class TestRestoreAssetAttacker:
    @pytest.mark.asyncio
    async def test_restore_asset(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await restore_asset(
                server_version="0", model_id="tm-001", asset_id="A1",
            )
        assert result["deleted"] is False
        mock.restore_asset.assert_awaited_once_with("tm-001", "A1")

    @pytest.mark.asyncio
    async def test_restore_attacker(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await restore_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
            )
        assert result["deleted"] is False
        mock.restore_attacker.assert_awaited_once_with("tm-001", "T1")


class TestReevaluateThreatModelFactors:
    """The bulk factor re-eval tool wraps a single backend POST. It
    must (a) appear in the server's registered tool list, (b) pass
    the model_id and optional change_reason through verbatim, and
    (c) translate client errors via the `_api_error` convention."""

    @pytest.mark.asyncio
    async def test_tool_is_registered(self) -> None:
        tool = await server.mcp.get_tool("reevaluate_threat_model_factors")
        assert tool is not None
        assert tool.name == "reevaluate_threat_model_factors"

    @pytest.mark.asyncio
    async def test_success_returns_envelope(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await reevaluate_threat_model_factors(
                server_version="0", model_id="tm-001",
            )
        assert result["model_id"] == "tm-001"
        assert result["assets_reevaluated"] == 2
        assert result["attackers_reevaluated"] == 1
        assert result["deltas"]["assets"][0]["id"] == "A1"
        assert result["deltas"]["attackers"][0]["id"] == "T1"
        # No change_reason passed → client method called with None.
        mock.reevaluate_factors.assert_awaited_once_with(
            "tm-001", change_reason=None,
        )

    @pytest.mark.asyncio
    async def test_change_reason_threaded_through(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await reevaluate_threat_model_factors(
                server_version="0", model_id="tm-001",
                change_reason="Re-eval after refinement bug fix v0.39.0",
            )
        mock.reevaluate_factors.assert_awaited_once_with(
            "tm-001",
            change_reason="Re-eval after refinement bug fix v0.39.0",
        )

    @pytest.mark.asyncio
    async def test_client_error_wrapped_as_tool_error(self) -> None:
        import httpx
        request = httpx.Request("POST", "https://api/factors/reevaluate")
        response = httpx.Response(
            503, request=request,
            json={"detail": "LLM evaluator unreachable"},
        )
        mock = _mock_client(reevaluate_factors=AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "503 Service Unavailable", request=request, response=response,
            ),
        ))
        with _patch_client(mock):
            with pytest.raises(ToolError, match="LLM evaluator unreachable"):
                await reevaluate_threat_model_factors(
                    server_version="0", model_id="tm-001",
                )


class TestAddEvidence:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_evidence(server_version="0", model_id="tm-001", control_id="CTRL-01", type="code", label="bcrypt usage")
        assert result["evidence_count"] == 2

    @pytest.mark.asyncio
    async def test_empty_label(self) -> None:
        with pytest.raises(ToolError, match="label is required"):
            await add_evidence(server_version="0", model_id="tm-001", control_id="CTRL-01", type="code", label="  ")


class TestRemoveEvidence:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await remove_evidence(server_version="0", model_id="tm-001", control_id="CTRL-01", evidence_index=0)
        assert result["evidence_count"] == 0


class TestImportControls:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await import_controls(server_version="0", model_id="tm-001", ctx=ctx, free_text="Encrypt data at rest")
        assert result["imported"] == 3


class TestDeleteControl:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await delete_control(server_version="0", model_id="tm-001", control_id="CTRL-01", reason="Duplicate")
        assert result["deleted"] is True


class TestCheckControlGaps:
    @pytest.mark.asyncio
    async def test_with_backend_job(self) -> None:
        mock = _mock_client()
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"gaps": [], "gap_count": 0},
        })
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await check_control_gaps(server_version="0", model_id="tm-001", ctx=ctx)
        assert result["gap_count"] == 0
        mock.get_operation.assert_awaited_once_with("job_gaps")


# ------------------------------------------------------------------
# Control Objectives & Assurance
# ------------------------------------------------------------------


class TestGetControlObjectives:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_control_objectives(server_version="0", model_id="tm-001")
        assert result["total"] == 1


class TestAssessModel:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await assess_model(server_version="0", model_id="tm-001")
        assert result["mitigated"] == 1


class TestGetReviewQueue:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_review_queue(server_version="0")
        assert "items" in result


# ------------------------------------------------------------------
# Assets & Attackers
# ------------------------------------------------------------------


class TestAddAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        """Normal create: API returns {"model": ..., "controls_carried": ...}."""
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_asset(server_version="0", model_id="tm-001", name="Session Store")
        assert "model" in result
        assert result["controls_carried"] == 0
        mock.add_asset.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_auto_restore_response_surfaced(self) -> None:
        """When the backend classifies the proposed asset as the same
        entity as a soft-deleted one, it auto-restores and returns
        `auto_restored: True`, `restored_asset_id`, and
        `discarded_fields`. The MCP tool must pass all of those
        through so the agent knows the call wasn't a fresh create
        AND can reapply non-identity proposed values if appropriate."""
        mock = _mock_client(add_asset=AsyncMock(return_value={
            "model": {"id": "tm-001", "assets": [{"id": "A-04"}]},
            "controls_carried": 2,
            "controls_orphaned": 0,
            "auto_restored": True,
            "restored_asset_id": "A-04",
            "reason": "Proposed asset matched soft-deleted A-04; restored it.",
            "discarded_fields": [
                {"field": "notes", "proposed_value": "extra context",
                 "preserved_value": "", "identity_bearing": False,
                 "reason": "Restored asset keeps archived notes."},
            ],
        }))
        with _patch_client(mock):
            result = await add_asset(
                server_version="0", model_id="tm-001",
                name="OIDC Token", notes="extra context",
            )
        assert result["auto_restored"] is True
        assert result["restored_asset_id"] == "A-04"
        # Agent needs the discarded fields to decide whether to reapply.
        assert len(result["discarded_fields"]) == 1
        assert result["discarded_fields"][0]["field"] == "notes"
        assert result["discarded_fields"][0]["identity_bearing"] is False

    @pytest.mark.asyncio
    async def test_add_asset_invalid_response_raises_502(self) -> None:
        """Distinct from 503 (evaluator down), 502 means the evaluator
        responded but output was malformed. Agent's retry profile
        differs: retry-same-prompt for 502, retry-with-backoff for 503."""
        import httpx
        err = httpx.HTTPStatusError(
            "502 Bad Gateway",
            request=httpx.Request("POST", "http://test"),
            response=httpx.Response(502, json={
                "detail": "Asset restore-candidate evaluator returned malformed output.",
            }),
        )
        mock = _mock_client(add_asset=AsyncMock(side_effect=err))
        with _patch_client(mock), pytest.raises(ToolError):
            await add_asset(server_version="0", model_id="tm-001", name="X")

    @pytest.mark.asyncio
    async def test_similar_verdict_rejected_with_suggestion(self) -> None:
        """When the LLM classifies as `similar` (might be the same but
        not confident), backend returns {accepted: False, ...} at
        HTTP 200. Tool passes the structured rejection through."""
        mock = _mock_client(add_asset=AsyncMock(return_value={
            "accepted": False,
            "classification": "similar",
            "candidate_restore_id": "A-04",
            "reason": "Names match but descriptions diverge.",
            "suggestion": "Call restore_asset, or re-submit with a distinctive description.",
        }))
        with _patch_client(mock):
            result = await add_asset(server_version="0", model_id="tm-001", name="OIDC Token")
        assert result["accepted"] is False
        assert result["classification"] == "similar"
        assert result["candidate_restore_id"] == "A-04"
        assert "restore_asset" in result["suggestion"]

    @pytest.mark.asyncio
    async def test_llm_unavailable_raises_tool_error(self) -> None:
        """503 from the backend (LLM evaluator down) surfaces as a
        tool error that agents can retry."""
        import httpx
        err = httpx.HTTPStatusError(
            "503 Service Unavailable",
            request=httpx.Request("POST", "http://test"),
            response=httpx.Response(503, json={
                "detail": "Asset restore-candidate evaluator unavailable.",
            }),
        )
        mock = _mock_client(add_asset=AsyncMock(side_effect=err))
        with _patch_client(mock), pytest.raises(ToolError):
            await add_asset(server_version="0", model_id="tm-001", name="OIDC Token")


class TestEditAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await edit_asset(server_version="0", model_id="tm-001", asset_id="A1", name="Updated")
        assert "model" in result

    @pytest.mark.asyncio
    async def test_semantic_rejection_surfaced(self) -> None:
        """When the LLM classifies the edit as `replace` or
        `ambiguous`, backend returns HTTP 200 with a structured
        rejection. Tool passes it through so the agent can act."""
        mock = _mock_client(edit_asset=AsyncMock(return_value={
            "accepted": False,
            "classification": "replace",
            "reason": "Rename changes semantic identity.",
            "per_field": {"name": "Card Data -> Audit Log is a different asset"},
            "suggestion": "Soft-delete + add new.",
        }))
        with _patch_client(mock):
            result = await edit_asset(
                server_version="0", model_id="tm-001", asset_id="A1",
                name="Audit Log",
            )
        assert result["accepted"] is False
        assert result["classification"] == "replace"
        assert "per_field" in result

    @pytest.mark.asyncio
    async def test_llm_unavailable_raises_tool_error(self) -> None:
        import httpx
        err = httpx.HTTPStatusError(
            "503 Service Unavailable",
            request=httpx.Request("PUT", "http://test"),
            response=httpx.Response(503, json={
                "detail": "Asset semantic-preservation evaluator unavailable.",
            }),
        )
        mock = _mock_client(edit_asset=AsyncMock(side_effect=err))
        with _patch_client(mock), pytest.raises(ToolError):
            await edit_asset(
                server_version="0", model_id="tm-001", asset_id="A1",
                name="Renamed",
            )


class TestRemoveAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        """Soft-delete: asset stays in model with deleted=True."""
        mock = _mock_client()
        with _patch_client(mock):
            result = await remove_asset(server_version="0", model_id="tm-001", asset_id="A1")
        assert "model" in result


class TestAddAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_attacker(server_version="0", model_id="tm-001", capability="Phishing")
        assert "model" in result

    @pytest.mark.asyncio
    async def test_auto_restore_response_surfaced(self) -> None:
        mock = _mock_client(add_attacker=AsyncMock(return_value={
            "model": {"id": "tm-001", "attackers": [{"id": "T-03"}]},
            "controls_carried": 1,
            "controls_orphaned": 0,
            "auto_restored": True,
            "restored_attacker_id": "T-03",
            "reason": "Matched soft-deleted T-03.",
        }))
        with _patch_client(mock):
            result = await add_attacker(
                server_version="0", model_id="tm-001", capability="Supply chain",
            )
        assert result["auto_restored"] is True
        assert result["restored_attacker_id"] == "T-03"

    @pytest.mark.asyncio
    async def test_similar_verdict_rejected(self) -> None:
        mock = _mock_client(add_attacker=AsyncMock(return_value={
            "accepted": False,
            "classification": "similar",
            "candidate_restore_id": "T-03",
            "reason": "Capability close but archetype differs.",
            "suggestion": "Call restore_attacker(T-03) or distinguish the new one.",
        }))
        with _patch_client(mock):
            result = await add_attacker(
                server_version="0", model_id="tm-001", capability="Supply chain",
            )
        assert result["accepted"] is False
        assert result["classification"] == "similar"


class TestEditAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await edit_attacker(server_version="0", model_id="tm-001", attacker_id="T1", capability="Updated")
        assert "model" in result

    @pytest.mark.asyncio
    async def test_semantic_rejection_surfaced(self) -> None:
        mock = _mock_client(edit_attacker=AsyncMock(return_value={
            "accepted": False,
            "classification": "replace",
            "reason": "Archetype change is a different adversary.",
            "per_field": {"archetype": "Unauthenticated -> Supply chain"},
            "suggestion": "Soft-delete + add new.",
        }))
        with _patch_client(mock):
            result = await edit_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
                archetype="Supply chain",
            )
        assert result["accepted"] is False
        assert result["classification"] == "replace"


class TestRemoveAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await remove_attacker(server_version="0", model_id="tm-001", attacker_id="T1")
        assert "model" in result


# ------------------------------------------------------------------
# Compliance
# ------------------------------------------------------------------


class TestListComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_compliance_frameworks(server_version="0")
        assert len(result["frameworks"]) == 1


class TestSelectComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await select_compliance_frameworks(server_version="0", model_id="tm-001", framework_ids="owasp-asvs")
        assert result["selected"] == 1


class TestGetComplianceReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_compliance_report(server_version="0", model_id="tm-001", framework_id="owasp-asvs")
        assert result["coverage"] == 0.8


class TestMapControlToRequirement:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await map_control_to_requirement(
                server_version="0", model_id="tm-001", framework_id="owasp-asvs",
                requirement_id="V2.1.1", control_id="CTRL-01",
            )
        assert result["mapped"] is True


class TestAutoMapControls:
    @pytest.mark.asyncio
    async def test_with_backend_job(self) -> None:
        """Backend returns job_id, tool polls until completion."""
        mock = _mock_client()
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"mappings_created": 9, "controls_mapped": 5, "controls_total": 12},
        })
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx)
        assert result["mappings_created"] == 9
        mock.get_operation.assert_awaited_once_with("job_automap")

    @pytest.mark.asyncio
    async def test_sync_response(self) -> None:
        """Backend returns result directly (e.g. all already mapped)."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"mappings_created": 0, "controls_mapped": 0, "controls_total": 5}))
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx)
        assert result["controls_total"] == 5


class TestAutoRemediate:
    @pytest.mark.asyncio
    async def test_with_backend_job(self) -> None:
        mock = _mock_client(auto_remediate=AsyncMock(return_value={"job_id": "job_rem"}))
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"coverage": 0.95},
        })
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await auto_remediate(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx)
        assert result["coverage"] == 0.95


class TestAwaitBackendJob:
    @pytest.mark.asyncio
    async def test_failure(self) -> None:
        """Backend job fails — ToolError raised with error message."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_fail"}))
        mock.get_operation = AsyncMock(return_value={
            "status": "failed",
            "error": "LLM rate limit exceeded",
        })
        ctx = _mock_ctx()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="LLM rate limit exceeded"):
                await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        """Backend job never completes — ToolError raised after timeout."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_hang"}))
        mock.get_operation = AsyncMock(return_value={
            "status": "running",
            "poll_after_seconds": 0,
        })
        ctx = _mock_ctx()
        # Make time.monotonic() jump past deadline on second call
        monotonic_values = iter([0, 0, 999])
        with _patch_client(mock), patch("mipiti_mcp.server.time") as mock_time:
            mock_time.monotonic = lambda: next(monotonic_values)
            with pytest.raises(ToolError, match="timed out"):
                await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

    @pytest.mark.asyncio
    async def test_client_disconnect_aborts_polling(self) -> None:
        """Client disconnects mid-poll — ToolError raised, no further polling."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_disconnect"}))
        mock.get_operation = AsyncMock(return_value={"status": "running", "poll_after_seconds": 0})
        ctx = _mock_ctx()

        fake_request = AsyncMock()
        fake_request.is_disconnected = AsyncMock(return_value=True)

        with _patch_client(mock), patch(
            "fastmcp.server.dependencies.get_http_request", return_value=fake_request
        ):
            with pytest.raises(ToolError, match="Client disconnected"):
                await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        # Verify we did NOT keep polling — at most one get_operation call (the disconnect
        # check happens at the top of the loop, before the operation poll).
        assert mock.get_operation.await_count == 0

    @pytest.mark.asyncio
    async def test_stdio_no_http_request_polls_normally(self) -> None:
        """stdio transport — no HTTP request — polling proceeds normally without disconnect check."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_stdio"}))
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"mappings_created": 3, "controls_mapped": 2, "controls_total": 5},
        })
        ctx = _mock_ctx()

        with _patch_client(mock), patch(
            "fastmcp.server.dependencies.get_http_request",
            side_effect=RuntimeError("No active HTTP request found."),
        ):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        assert result["mappings_created"] == 3
        mock.get_operation.assert_awaited_once_with("job_stdio")

    @pytest.mark.asyncio
    async def test_is_disconnected_raises_treated_as_connected(self) -> None:
        """is_disconnected() raises an exception — treat as still-connected (no false positive)."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_robust"}))
        mock.get_operation = AsyncMock(return_value={
            "status": "completed",
            "result": {"mappings_created": 1, "controls_mapped": 1, "controls_total": 1},
        })
        ctx = _mock_ctx()

        fake_request = AsyncMock()
        fake_request.is_disconnected = AsyncMock(side_effect=RuntimeError("transport in unusual state"))

        with _patch_client(mock), patch(
            "fastmcp.server.dependencies.get_http_request", return_value=fake_request
        ):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        assert result["controls_total"] == 1
        mock.get_operation.assert_awaited_once_with("job_robust")

    # ----- Progress monotonicity & total-constancy (MCP invariants) -----
    #
    # These tests drive _await_backend_job through scripted get_operation
    # responses and assert on captured ctx.report_progress calls. We don't
    # mock _safe_report_progress — the guard-wrapper must stay in the path.

    @staticmethod
    def _script(responses: list[dict]) -> AsyncMock:
        """Build a get_operation mock that yields a scripted response sequence
        and then reports `completed` forever."""
        final = {"status": "completed", "result": {"mappings_created": 0, "controls_mapped": 0, "controls_total": 0}}
        it = iter(responses)

        async def _next(_job_id: str) -> dict:
            try:
                return next(it)
            except StopIteration:
                return final

        return AsyncMock(side_effect=_next)

    @pytest.mark.asyncio
    async def test_progress_numeric_happy_path(self) -> None:
        """Backend advertises (cur, tot): (1,5) -> (2,5) -> (3,5).

        Expect three emissions, current strictly increasing, total constant.
        """
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p1"}))
        mock.get_operation = self._script([
            {"status": "running", "progress": "step 1", "progress_current": 1, "progress_total": 5, "poll_after_seconds": 0},
            {"status": "running", "progress": "step 2", "progress_current": 2, "progress_total": 5, "poll_after_seconds": 0},
            {"status": "running", "progress": "step 3", "progress_current": 3, "progress_total": 5, "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        calls = ctx.report_progress.await_args_list
        assert len(calls) == 3
        # Signature: ctx.report_progress(progress, total, message=...)
        assert [c.args[0] for c in calls] == [1.0, 2.0, 3.0]
        assert [c.args[1] for c in calls] == [5.0, 5.0, 5.0]
        assert [c.kwargs["message"] for c in calls] == ["step 1", "step 2", "step 3"]

    @pytest.mark.asyncio
    async def test_progress_duplicate_poll_skipped(self) -> None:
        """Backend repeats (1,5): only one emission (second would violate strict increase)."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p2"}))
        mock.get_operation = self._script([
            {"status": "running", "progress": "step 1", "progress_current": 1, "progress_total": 5, "poll_after_seconds": 0},
            {"status": "running", "progress": "step 1", "progress_current": 1, "progress_total": 5, "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        calls = ctx.report_progress.await_args_list
        assert len(calls) == 1
        assert calls[0].args[:2] == (1.0, 5.0)

    @pytest.mark.asyncio
    async def test_progress_total_changes_midflight_skipped(self) -> None:
        """Phase shift: (3,5) -> (1,10). Second emission is SKIPPED, locked total wins.

        We don't fall back to indeterminate mode either — the bar freezes where
        it was until numerics align with the locked total again.
        """
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p3"}))
        mock.get_operation = self._script([
            {"status": "running", "progress": "phase A", "progress_current": 3, "progress_total": 5, "poll_after_seconds": 0},
            {"status": "running", "progress": "phase B", "progress_current": 1, "progress_total": 10, "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        calls = ctx.report_progress.await_args_list
        assert len(calls) == 1
        assert calls[0].args[:2] == (3.0, 5.0)

    @pytest.mark.asyncio
    async def test_progress_numerics_disappear_after_present(self) -> None:
        """(2,5) first, then numerics disappear leaving only message.

        Indeterminate-mode elif fires with incrementing poll_counter.
        """
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p4"}))
        mock.get_operation = self._script([
            {"status": "running", "progress": "step 2", "progress_current": 2, "progress_total": 5, "poll_after_seconds": 0},
            {"status": "running", "progress": "still working", "poll_after_seconds": 0},
            {"status": "running", "progress": "still working more", "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        calls = ctx.report_progress.await_args_list
        assert len(calls) == 3
        assert calls[0].args[:2] == (2.0, 5.0)
        # Indeterminate: total=None, poll_counter increments 1, 2
        assert calls[1].args == (1, None)
        assert calls[2].args == (2, None)
        assert calls[1].kwargs["message"] == "still working"
        assert calls[2].kwargs["message"] == "still working more"

    @pytest.mark.asyncio
    async def test_progress_indeterminate_only(self) -> None:
        """No numerics ever — only message strings. poll_counter 1, 2, 3 with total=None."""
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p5"}))
        mock.get_operation = self._script([
            {"status": "running", "progress": "msg a", "poll_after_seconds": 0},
            {"status": "running", "progress": "msg b", "poll_after_seconds": 0},
            {"status": "running", "progress": "msg c", "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        calls = ctx.report_progress.await_args_list
        assert len(calls) == 3
        assert [c.args for c in calls] == [(1, None), (2, None), (3, None)]
        assert [c.kwargs["message"] for c in calls] == ["msg a", "msg b", "msg c"]

    @pytest.mark.asyncio
    async def test_progress_empty_poll_no_emission(self) -> None:
        """Poll with no numerics and no message: no emission that poll.

        Preserves the pre-fix behavior of never emitting on empty payloads.
        """
        mock = _mock_client(auto_map_controls=AsyncMock(return_value={"job_id": "job_p6"}))
        mock.get_operation = self._script([
            {"status": "running", "poll_after_seconds": 0},
            {"status": "running", "poll_after_seconds": 0},
        ])
        ctx = _mock_ctx()
        with _patch_client(mock):
            await auto_map_controls(server_version="0", model_id="tm-001", framework_id="f1", ctx=ctx)

        assert ctx.report_progress.await_count == 0


# ------------------------------------------------------------------
# Workspaces & Systems
# ------------------------------------------------------------------


class TestListWorkspaces:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_workspaces(server_version="0")
        assert "workspaces" in result


class TestListSystems:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_systems(server_version="0")
        assert "systems" in result


class TestGetSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_system(server_version="0", system_id="sys-1")
        assert result["id"] == "sys-1"


class TestCreateSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await create_system(server_version="0", name="Platform")
        assert result["id"] == "sys-2"


class TestAddModelToSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_model_to_system(server_version="0", system_id="sys-1", model_id="tm-001")
        assert result["added"] is True


# ------------------------------------------------------------------
# System Compliance
# ------------------------------------------------------------------


class TestSelectSystemComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await select_system_compliance_frameworks(server_version="0", system_id="sys-1", framework_ids="owasp-asvs")
        assert result["selected"] == 1


class TestGetSystemComplianceReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_system_compliance_report(server_version="0", system_id="sys-1", framework_id="owasp-asvs")
        assert result["coverage"] == 0.9


# ------------------------------------------------------------------
# Assertions & Verification
# ------------------------------------------------------------------


class TestSubmitAssertions:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await submit_assertions(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
                assertions_json=json.dumps([{"type": "file_exists", "params": {"path": "auth.py"}}]),
            )
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_bad_json(self) -> None:
        with pytest.raises(ToolError, match="assertions_json must be valid JSON"):
            await submit_assertions(server_version="0", model_id="tm-001", control_id="CTRL-01", assertions_json="not-json")


class TestListAssertions:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_assertions(server_version="0", model_id="tm-001", control_id="CTRL-01")
        assert "assertions" in result


class TestDeleteAssertion:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await delete_assertion(server_version="0", model_id="tm-001", control_id="CTRL-01", assertion_id="a-1")
        assert result["deleted"] is True


class TestGetVerificationReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_verification_report(server_version="0", model_id="tm-001")
        assert result["tier1_pass"] == 3


# ------------------------------------------------------------------
# Findings
# ------------------------------------------------------------------


class TestSubmitFindings:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await submit_findings(
                server_version="0", model_id="tm-001",
                findings_json=json.dumps([{"control_id": "CTRL-01", "title": "Missing encryption"}]),
            )
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_bad_json(self) -> None:
        with pytest.raises(ToolError, match="findings_json must be valid JSON"):
            await submit_findings(server_version="0", model_id="tm-001", findings_json="not-json")


class TestListFindings:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_findings(server_version="0", model_id="tm-001")
        assert "findings" in result


class TestUpdateFinding:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await update_finding(server_version="0", model_id="tm-001", finding_id="f1", status="acknowledged")
        assert result["status"] == "acknowledged"


# ------------------------------------------------------------------
# Scan Prompt
# ------------------------------------------------------------------


class TestGetScanPrompt:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_scan_prompt(server_version="0", model_id="tm-001")
        assert "prompt" in result




# ------------------------------------------------------------------
# Control Assumption Groups
# ------------------------------------------------------------------


class TestGetControlAssumptionGroups:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_control_assumption_groups(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
            )
        assert result["control_id"] == "CTRL-01"
        assert "1" in result["groups"]
        assert result["groups"]["1"][0]["id"] == "AS1"


class TestSetControlAssumptionGroups:
    @pytest.mark.asyncio
    async def test_single_group_single_member(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await set_control_assumption_groups(
                server_version="0",
                model_id="tm-001",
                control_id="CTRL-01",
                groups='{"1": ["AS1"]}',
                justification="AWS KMS handles this control.",
            )
        assert result["assumption_groups"] == {"1": ["AS1"]}

    @pytest.mark.asyncio
    async def test_compound_and_multi_group(self) -> None:
        mock = _mock_client()
        # Match the exact input — the mock returns whatever the fixture returns,
        # so we only need to verify the tool accepts the structure and forwards it.
        mock.set_control_assumption_groups = AsyncMock(return_value={
            "control_id": "CTRL-01",
            "assumption_groups": {"1": ["AS1", "AS2"], "2": ["AS3"]},
            "justification": "Either KMS+review or HSM.",
        })
        with _patch_client(mock):
            result = await set_control_assumption_groups(
                server_version="0",
                model_id="tm-001",
                control_id="CTRL-01",
                groups='{"1": ["AS1", "AS2"], "2": ["AS3"]}',
                justification="Either KMS+review or HSM.",
            )
        assert result["assumption_groups"] == {"1": ["AS1", "AS2"], "2": ["AS3"]}
        # Confirm the parsed dict was forwarded to the client (not the raw string)
        mock.set_control_assumption_groups.assert_awaited_once()
        call_args = mock.set_control_assumption_groups.call_args
        assert call_args.args[2] == {"1": ["AS1", "AS2"], "2": ["AS3"]}

    @pytest.mark.asyncio
    async def test_empty_groups_clears(self) -> None:
        mock = _mock_client()
        mock.set_control_assumption_groups = AsyncMock(return_value={
            "control_id": "CTRL-01",
            "assumption_groups": {},
            "justification": "",
        })
        with _patch_client(mock):
            # Empty groups: justification length check is bypassed.
            result = await set_control_assumption_groups(
                server_version="0",
                model_id="tm-001",
                control_id="CTRL-01",
                groups="{}",
            )
        assert result["assumption_groups"] == {}

    @pytest.mark.asyncio
    async def test_invalid_json_rejected(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="valid JSON"):
                await set_control_assumption_groups(
                    server_version="0",
                    model_id="tm-001",
                    control_id="CTRL-01",
                    groups="not-json",
                    justification="long enough justification",
                )

    @pytest.mark.asyncio
    async def test_groups_not_object_rejected(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="JSON object"):
                await set_control_assumption_groups(
                    server_version="0",
                    model_id="tm-001",
                    control_id="CTRL-01",
                    groups='["AS1"]',
                    justification="long enough justification",
                )

    @pytest.mark.asyncio
    async def test_short_justification_rejected_when_setting(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="justification"):
                await set_control_assumption_groups(
                    server_version="0",
                    model_id="tm-001",
                    control_id="CTRL-01",
                    groups='{"1": ["AS1"]}',
                    justification="too short",
                )


# ------------------------------------------------------------------
# Per-entity GET tools + co_id filters
# ------------------------------------------------------------------


class TestPerIdGets:
    @pytest.mark.asyncio
    async def test_get_control_objective(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_control_objective(
                server_version="0", model_id="tm-001", co_id="CO3",
            )
        assert result["control_objective"]["id"] == "CO3"
        assert result["reachability_verdict"]["kind"] == "indeterminate"
        mock.get_control_objective.assert_awaited_once_with("tm-001", "CO3")

    @pytest.mark.asyncio
    async def test_get_asset(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_asset(
                server_version="0", model_id="tm-001", asset_id="A1",
            )
        assert result["asset"]["id"] == "A1"

    @pytest.mark.asyncio
    async def test_get_attacker(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
            )
        assert result["attacker"]["id"] == "T1"

    @pytest.mark.asyncio
    async def test_get_component(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_component(
                server_version="0", model_id="tm-001", component_id="C1",
            )
        assert result["component"]["id"] == "C1"

    @pytest.mark.asyncio
    async def test_get_trust_boundary(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_trust_boundary(
                server_version="0", model_id="tm-001", tb_id="TB1",
            )
        assert result["trust_boundary"]["id"] == "TB1"
        assert "Network" in result["trust_boundary"]["passes"]

    @pytest.mark.asyncio
    async def test_get_assumption(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_assumption(
                server_version="0", model_id="tm-001", assumption_id="AS1",
            )
        assert result["assumption"]["id"] == "AS1"

    @pytest.mark.asyncio
    async def test_get_control(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_control(
                server_version="0", model_id="tm-001", control_id="CTRL-01",
            )
        assert result["control"]["id"] == "CTRL-01"
        # Default version=0 maps to latest at the API layer.
        mock.get_control.assert_awaited_once_with("tm-001", "CTRL-01", version=0)


class TestCoIdFilters:
    @pytest.mark.asyncio
    async def test_reachability_co_id_passthrough(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await get_reachability_verdicts(
                server_version="0", model_id="tm-001", co_id="CO3",
            )
        mock.model_reachability_verdicts.assert_awaited_once_with("tm-001", co_id="CO3")

    @pytest.mark.asyncio
    async def test_reachability_no_co_id(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await get_reachability_verdicts(server_version="0", model_id="tm-001")
        mock.model_reachability_verdicts.assert_awaited_once_with("tm-001", co_id="")

    @pytest.mark.asyncio
    async def test_coherence_co_id_passthrough(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await model_coherence_report(
                server_version="0", model_id="tm-001", co_id="CO3",
            )
        mock.model_coherence_report.assert_awaited_once_with("tm-001", co_id="CO3")


# ------------------------------------------------------------------
# Findings / Risk aggregates
# ------------------------------------------------------------------


class TestGetFindingsRisks:
    @pytest.mark.asyncio
    async def test_returns_workspace_aggregate(self) -> None:
        """Workspace-scoped aggregate surfaces findings, risk
        acceptances, and at-risk COs in a single envelope."""
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_findings_risks(server_version="0")
        assert result["workspace_id"] == "ws-1"
        assert result["summary"]["open_findings"] == 1
        assert result["summary"]["at_risk_cos"] == 1
        assert len(result["findings"]) == 1
        assert len(result["risk_acceptances"]) == 1
        assert len(result["at_risk_cos"]) == 1
        assert result["at_risk_cos"][0]["risk_tier"] == "high"
        # No params forwarded — the endpoint is workspace-scoped.
        mock.get_findings_risks.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_client_error_wrapped_as_tool_error(self) -> None:
        mock = _mock_client(
            get_findings_risks=AsyncMock(side_effect=RuntimeError("boom")),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await get_findings_risks(server_version="0")


class TestGetModelRiskView:
    @pytest.mark.asyncio
    async def test_returns_rows_for_model(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_model_risk_view(
                server_version="0", model_id="tm-001",
            )
        assert result["model_id"] == "tm-001"
        assert result["total"] == 1
        assert result["rows"][0]["co_id"] == "CO1"
        assert result["rows"][0]["risk_tier"] == "high"
        assert result["rows"][0]["open_findings"] == 1
        mock.get_model_risk_view.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_model_id_threaded_through(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await get_model_risk_view(
                server_version="0", model_id="tm-xyz",
            )
        mock.get_model_risk_view.assert_awaited_once_with("tm-xyz")


class TestGetSystemRiskView:
    @pytest.mark.asyncio
    async def test_rows_carry_model_context(self) -> None:
        """System-level view must attach model_id / model_title per row
        so callers can group by source model without an extra lookup."""
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_system_risk_view(
                server_version="0", system_id="sys-1",
            )
        assert result["system_id"] == "sys-1"
        assert result["total"] == 2
        assert all(
            "model_id" in r and "model_title" in r for r in result["rows"]
        )
        mock.get_system_risk_view.assert_awaited_once_with("sys-1")


class TestListRiskAcceptances:
    @pytest.mark.asyncio
    async def test_wraps_list_in_items(self) -> None:
        """The client returns a bare list; _dump wraps it as
        ``{"items": [...]}`` for the FastMCP structured-content
        contract."""
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_risk_acceptances(
                server_version="0", model_id="tm-001",
            )
        assert "items" in result
        assert result["items"][0]["id"] == "RA-1"
        assert result["items"][0]["status"] == "active"
        assert result["items"][0]["owner"] == "Platform Team"
        mock.list_risk_acceptances.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_empty_list(self) -> None:
        mock = _mock_client(list_risk_acceptances=AsyncMock(return_value=[]))
        with _patch_client(mock):
            result = await list_risk_acceptances(
                server_version="0", model_id="tm-001",
            )
        assert result == {"items": []}

    @pytest.mark.asyncio
    async def test_client_error_wrapped_as_tool_error(self) -> None:
        mock = _mock_client(
            list_risk_acceptances=AsyncMock(side_effect=RuntimeError("boom")),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await list_risk_acceptances(
                    server_version="0", model_id="tm-001",
                )


# ------------------------------------------------------------------
# Composition (recursive-tree effective model)
# ------------------------------------------------------------------


# Flag-off response shapes — each composition endpoint returns this
# stable empty body when ``TREE_COMPOSITION_ENABLED`` is off on the
# backend. Asserting against these confirms the tool wrappers pass the
# disabled-state through without crashing or stripping ``flag_enabled``.
_FLAG_OFF_INDEX = {
    "model_id": "tm-001", "model_version": 0, "flag_enabled": False,
    "tree": {"parent_id": None, "ancestor_chain": [],
             "depth": 0, "child_ids": []},
    "counts": {
        "entities": {
            "trust_boundaries": {"own": 0, "inherited": 0},
            "components": {"own": 0, "inherited": 0},
            "assets": {"own": 0, "inherited": 0},
            "attackers": {"own": 0, "inherited": 0},
        },
        "control_objectives": {
            "total": 0, "live": 0, "covered": 0, "uncovered": 0,
            "indeterminate": 0,
            "by_origin": {"own": 0, "cross": 0, "inherited": 0},
        },
        "reconciliation_candidates": {"certain": 0, "heuristic": 0},
    },
    "warnings": [],
}
_FLAG_OFF_ENTITIES = {
    "model_id": "tm-001", "flag_enabled": False,
    "kinds": {"trust_boundaries": [], "components": [],
              "assets": [], "attackers": []},
}
_FLAG_OFF_COS = {
    "model_id": "tm-001", "flag_enabled": False,
    "control_objectives": [],
}
_FLAG_OFF_COVERAGE = {
    "model_id": "tm-001", "flag_enabled": False, "coverage": [],
}
_FLAG_OFF_REACHABILITY = {
    "model_id": "tm-001", "flag_enabled": False, "verdicts": [],
}
_FLAG_OFF_ATTACK_PATHS = {
    "model_id": "tm-001", "flag_enabled": False,
    "effective_paths": [],
    "lattice_positions": 0,
    "authored_paths": 0,
    "suggestions": {"missing_path": [], "dangling_path": []},
}
_FLAG_OFF_RECONCILIATION = {
    "model_id": "tm-001", "flag_enabled": False, "total": 0,
    "tiers": {"certain": 0, "heuristic": 0},
    "page": 1, "page_size": 50, "candidates": [],
}


def _http_404(method: str = "GET", url: str = "https://api/x") -> Exception:
    """Build an httpx.HTTPStatusError(404) so tests can drive the same
    error-wrapping path the production client raises on a missing model."""
    import httpx
    req = httpx.Request(method, url)
    resp = httpx.Response(404, request=req, json={"detail": "model not found"})
    return httpx.HTTPStatusError("404", request=req, response=resp)


def _http_error(
    status_code: int,
    detail: str,
    method: str = "POST",
    url: str = "https://api/x",
) -> Exception:
    """Build an arbitrary-status httpx.HTTPStatusError for tool-layer tests."""
    import httpx
    req = httpx.Request(method, url)
    resp = httpx.Response(status_code, request=req, json={"detail": detail})
    return httpx.HTTPStatusError(str(status_code), request=req, response=resp)


class TestGetCompositionOverview:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_composition_overview(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        assert result["counts"]["control_objectives"]["total"] == 1
        assert result["tree"]["depth"] == 0
        mock.composition_index.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty_shape(self) -> None:
        mock = _mock_client(
            composition_index=AsyncMock(return_value=_FLAG_OFF_INDEX),
        )
        with _patch_client(mock):
            result = await get_composition_overview(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["counts"]["control_objectives"]["total"] == 0
        assert result["warnings"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_index=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError) as exc_info:
                await get_composition_overview(
                    server_version="0", model_id="tm-missing",
                )
        assert "404" in str(exc_info.value)


class TestListEffectiveEntities:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_effective_entities(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        assert result["kinds"]["assets"][0]["qualified_id"] == "tm-001::A1"
        assert result["kinds"]["assets"][0]["origin"] == "own"
        mock.composition_entities.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty_kinds(self) -> None:
        mock = _mock_client(
            composition_entities=AsyncMock(return_value=_FLAG_OFF_ENTITIES),
        )
        with _patch_client(mock):
            result = await list_effective_entities(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["kinds"]["assets"] == []
        assert result["kinds"]["attackers"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_entities=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await list_effective_entities(
                    server_version="0", model_id="tm-missing",
                )


class TestListEffectiveControlObjectives:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_effective_control_objectives(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        assert len(result["control_objectives"]) == 1
        assert result["control_objectives"][0]["origin"] == "own"
        mock.composition_control_objectives.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty(self) -> None:
        mock = _mock_client(
            composition_control_objectives=AsyncMock(return_value=_FLAG_OFF_COS),
        )
        with _patch_client(mock):
            result = await list_effective_control_objectives(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["control_objectives"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_control_objectives=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await list_effective_control_objectives(
                    server_version="0", model_id="tm-missing",
                )


class TestGetEffectiveCoverage:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_effective_coverage(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        row = result["coverage"][0]
        assert row["is_covered"] is True
        assert row["own_credit"] == 1.0
        assert row["inherited_credit"] == 0.0
        assert row["contributing_controls"][0]["control_id"] == "CTRL-01"
        mock.composition_coverage.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty(self) -> None:
        mock = _mock_client(
            composition_coverage=AsyncMock(return_value=_FLAG_OFF_COVERAGE),
        )
        with _patch_client(mock):
            result = await get_effective_coverage(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["coverage"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_coverage=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await get_effective_coverage(
                    server_version="0", model_id="tm-missing",
                )


class TestGetReachVerdicts:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await get_reach_verdicts(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        v = result["verdicts"][0]
        assert v["co_qid"] == "tm-001::CO1"
        assert v["kind"] in {"reachable", "unreachable", "indeterminate"}
        mock.composition_reachability.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty(self) -> None:
        mock = _mock_client(
            composition_reachability=AsyncMock(return_value=_FLAG_OFF_REACHABILITY),
        )
        with _patch_client(mock):
            result = await get_reach_verdicts(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["verdicts"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_reachability=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await get_reach_verdicts(
                    server_version="0", model_id="tm-missing",
                )


class TestListEffectiveAttackPaths:
    @pytest.mark.asyncio
    async def test_flag_on(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_effective_attack_paths(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        assert "effective_paths" in result
        assert result["suggestions"] == {"missing_path": [], "dangling_path": []}
        mock.composition_attack_paths.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty(self) -> None:
        mock = _mock_client(
            composition_attack_paths=AsyncMock(return_value=_FLAG_OFF_ATTACK_PATHS),
        )
        with _patch_client(mock):
            result = await list_effective_attack_paths(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["effective_paths"] == []
        assert result["lattice_positions"] == 0
        assert result["authored_paths"] == 0

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_attack_paths=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await list_effective_attack_paths(
                    server_version="0", model_id="tm-missing",
                )


class TestListReconciliationCandidates:
    @pytest.mark.asyncio
    async def test_flag_on_default_pagination(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_reconciliation_candidates(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is True
        assert result["page"] == 1
        assert result["page_size"] == 50
        mock.composition_reconciliation.assert_awaited_once_with(
            "tm-001", page=1, page_size=50,
        )

    @pytest.mark.asyncio
    async def test_pagination_forwarded(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await list_reconciliation_candidates(
                server_version="0", model_id="tm-001",
                page=3, page_size=25,
            )
        mock.composition_reconciliation.assert_awaited_once_with(
            "tm-001", page=3, page_size=25,
        )

    @pytest.mark.asyncio
    async def test_invalid_page_rejected(self) -> None:
        with pytest.raises(ToolError):
            await list_reconciliation_candidates(
                server_version="0", model_id="tm-001", page=0,
            )

    @pytest.mark.asyncio
    async def test_invalid_page_size_rejected(self) -> None:
        with pytest.raises(ToolError):
            await list_reconciliation_candidates(
                server_version="0", model_id="tm-001", page_size=0,
            )

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty(self) -> None:
        mock = _mock_client(
            composition_reconciliation=AsyncMock(
                return_value=_FLAG_OFF_RECONCILIATION,
            ),
        )
        with _patch_client(mock):
            result = await list_reconciliation_candidates(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["total"] == 0
        assert result["candidates"] == []

    @pytest.mark.asyncio
    async def test_404_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            composition_reconciliation=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError):
                await list_reconciliation_candidates(
                    server_version="0", model_id="tm-missing",
                )


class TestApplyCertainReconciliationMatch:
    @pytest.mark.asyncio
    async def test_happy_path_returns_envelope_unchanged(self) -> None:
        envelope = {
            "model": {"id": "tm-001", "assets": [{"id": "A1"}]},
            "controls_carried": 2,
            "controls_orphaned": 1,
            "orphaned_control_ids": ["CTRL-09"],
        }
        mock = _mock_client(
            apply_certain_reconciliation_match=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await apply_certain_reconciliation_match(
                server_version="0",
                model_id="tm-001",
                kind="assets",
                own_qid="child:A1",
                inherited_qid="parent:A1",
            )
        assert result == envelope
        mock.apply_certain_reconciliation_match.assert_awaited_once_with(
            "tm-001", "assets", "child:A1", "parent:A1",
        )

    @pytest.mark.asyncio
    async def test_kinds_all_accepted(self) -> None:
        mock = _mock_client()
        for kind in ("assets", "attackers", "components"):
            with _patch_client(mock):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind=kind,
                    own_qid="child:X1",
                    inherited_qid="parent:X1",
                )

    @pytest.mark.asyncio
    async def test_invalid_kind_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="kind must be one of"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assumptions",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_trust_boundaries_kind_rejected_preflight(self) -> None:
        # Reconciliation auto-merge is limited to assets/attackers/components
        # by the backend route; the tool's pre-flight mirrors that exact
        # allowlist rather than the broader composition entity-kind set.
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="kind must be one of"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="trust_boundaries",
                    own_qid="child:TB1",
                    inherited_qid="parent:TB1",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_own_qid_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="own_qid is required"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="",
                    inherited_qid="parent:A1",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_inherited_qid_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="inherited_qid is required"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_own_qid_missing_colon_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="own_qid must be a qualified id"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="A1",
                    inherited_qid="parent:A1",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_inherited_qid_missing_colon_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="inherited_qid must be a qualified id"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="A1",
                )
        mock.apply_certain_reconciliation_match.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_400_heuristic_or_stale_surfaces_clean_tool_error(self) -> None:
        # The backend route maps both heuristic-tier candidates and stale
        # candidates (model moved since detection) to 400. The tool layer
        # surfaces whichever ``detail`` text the route returned.
        mock = _mock_client(
            apply_certain_reconciliation_match=AsyncMock(
                side_effect=_http_error(
                    400,
                    "Candidate is no longer a certain-tier match.",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="400"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )

    @pytest.mark.asyncio
    async def test_404_model_missing_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            apply_certain_reconciliation_match=AsyncMock(
                side_effect=_http_error(404, "Threat model not found.", method="POST"),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-missing",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            apply_certain_reconciliation_match=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await apply_certain_reconciliation_match(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )


class TestRejectReconciliationCandidate:
    @pytest.mark.asyncio
    async def test_happy_path_returns_persisted_record(self) -> None:
        persisted = {
            "id": "rej-001",
            "model_id": "tm-001",
            "kind": "assets",
            "own_qid": "child:A1",
            "inherited_qid": "parent:A1",
            "rejected_by": "user-1",
            "rejected_at": "2026-05-27T00:00:00+00:00",
        }
        mock = _mock_client(
            reject_reconciliation_candidate=AsyncMock(return_value=persisted),
        )
        with _patch_client(mock):
            result = await reject_reconciliation_candidate(
                server_version="0",
                model_id="tm-001",
                kind="assets",
                own_qid="child:A1",
                inherited_qid="parent:A1",
            )
        assert result == persisted
        mock.reject_reconciliation_candidate.assert_awaited_once_with(
            "tm-001", "assets", "child:A1", "parent:A1",
        )

    @pytest.mark.asyncio
    async def test_kinds_all_accepted(self) -> None:
        mock = _mock_client()
        for kind in ("assets", "attackers", "components"):
            with _patch_client(mock):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind=kind,
                    own_qid="child:X1",
                    inherited_qid="parent:X1",
                )

    @pytest.mark.asyncio
    async def test_invalid_kind_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="kind must be one of"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assumptions",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )
        mock.reject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_own_qid_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="own_qid is required"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="",
                    inherited_qid="parent:A1",
                )
        mock.reject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_inherited_qid_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="inherited_qid is required"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="",
                )
        mock.reject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_own_qid_missing_colon_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="own_qid must be a qualified id"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="A1",
                    inherited_qid="parent:A1",
                )
        mock.reject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_inherited_qid_missing_colon_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="inherited_qid must be a qualified id"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="A1",
                )
        mock.reject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_400_partial_body_surfaces_clean_tool_error(self) -> None:
        # Pre-flight catches the common malformed-input cases, but the
        # server may still return 400 if its own validation drifts ahead
        # of the tool layer. Surface whichever detail the route returned.
        mock = _mock_client(
            reject_reconciliation_candidate=AsyncMock(
                side_effect=_http_error(
                    400,
                    "kind, own_qid, and inherited_qid are all required.",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="400"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )

    @pytest.mark.asyncio
    async def test_404_model_missing_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            reject_reconciliation_candidate=AsyncMock(
                side_effect=_http_error(404, "Threat model not found.", method="POST"),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-missing",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            reject_reconciliation_candidate=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await reject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    kind="assets",
                    own_qid="child:A1",
                    inherited_qid="parent:A1",
                )


class TestUnrejectReconciliationCandidate:
    @pytest.mark.asyncio
    async def test_happy_path_returns_ok_envelope(self) -> None:
        mock = _mock_client(
            unreject_reconciliation_candidate=AsyncMock(return_value={"ok": True}),
        )
        with _patch_client(mock):
            result = await unreject_reconciliation_candidate(
                server_version="0",
                model_id="tm-001",
                rejection_id="rej-001",
            )
        assert result == {"ok": True}
        mock.unreject_reconciliation_candidate.assert_awaited_once_with(
            "tm-001", "rej-001",
        )

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await unreject_reconciliation_candidate(
                    server_version="0",
                    model_id="",
                    rejection_id="rej-001",
                )
        mock.unreject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_rejection_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="rejection_id is required"):
                await unreject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    rejection_id="",
                )
        mock.unreject_reconciliation_candidate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_404_unknown_id_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            unreject_reconciliation_candidate=AsyncMock(
                side_effect=_http_error(
                    404, "Rejection not found.", method="DELETE",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await unreject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    rejection_id="rej-missing",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            unreject_reconciliation_candidate=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="DELETE",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await unreject_reconciliation_candidate(
                    server_version="0",
                    model_id="tm-001",
                    rejection_id="rej-001",
                )


class TestListReconciliationRejections:
    @pytest.mark.asyncio
    async def test_happy_path_returns_rejections_list(self) -> None:
        payload = {
            "model_id": "tm-001",
            "flag_enabled": True,
            "rejections": [
                {
                    "id": "rej-001",
                    "model_id": "tm-001",
                    "kind": "assets",
                    "own_qid": "child:A1",
                    "inherited_qid": "parent:A1",
                    "rejected_by": "user-1",
                    "rejected_at": "2026-05-27T00:00:00+00:00",
                },
                {
                    "id": "rej-002",
                    "model_id": "tm-001",
                    "kind": "attackers",
                    "own_qid": "child:T1",
                    "inherited_qid": "parent:T1",
                    "rejected_by": "user-2",
                    "rejected_at": "2026-05-27T01:00:00+00:00",
                },
            ],
        }
        mock = _mock_client(
            list_reconciliation_rejections=AsyncMock(return_value=payload),
        )
        with _patch_client(mock):
            result = await list_reconciliation_rejections(
                server_version="0", model_id="tm-001",
            )
        assert result == payload
        assert len(result["rejections"]) == 2
        mock.list_reconciliation_rejections.assert_awaited_once_with("tm-001")

    @pytest.mark.asyncio
    async def test_flag_off_returns_empty_with_flag_false(self) -> None:
        # Flag-off shape from the backend: empty list + ``flag_enabled:
        # false`` so the caller renders the disabled state without a
        # separate code path.
        payload = {
            "model_id": "tm-001",
            "flag_enabled": False,
            "rejections": [],
        }
        mock = _mock_client(
            list_reconciliation_rejections=AsyncMock(return_value=payload),
        )
        with _patch_client(mock):
            result = await list_reconciliation_rejections(
                server_version="0", model_id="tm-001",
            )
        assert result["flag_enabled"] is False
        assert result["rejections"] == []

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await list_reconciliation_rejections(
                    server_version="0", model_id="",
                )
        mock.list_reconciliation_rejections.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_404_model_missing_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            list_reconciliation_rejections=AsyncMock(side_effect=_http_404()),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await list_reconciliation_rejections(
                    server_version="0", model_id="tm-missing",
                )


class TestLiftCompositionEntity:
    @pytest.mark.asyncio
    async def test_happy_path_returns_envelope_unchanged(self) -> None:
        envelope = {
            "lift_id": "lift-XYZ",
            "lca_model": {"id": "tm-lca", "assets": [{"id": "A1"}]},
            "descendant_a_model": {"id": "tm-da", "assets": []},
            "descendant_b_model": {"id": "tm-db", "assets": []},
            "applied_migrations": [
                {"kind": "assets", "from": "tm-da#A1", "to": "tm-lca#A1"},
            ],
            "lift_event": {
                "lift_id": "lift-XYZ",
                "kind": "assets",
                "source_model_ids": ["tm-da", "tm-db"],
                "source_entity_ids": ["A1", "A1"],
                "lca_model_id": "tm-lca",
                "new_entity_id": "A1",
                "acknowledged_subtrees": [],
                "field_resolutions": {},
                "attached_state_migrations": [],
            },
        }
        mock = _mock_client(
            lift_composition_entity=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await lift_composition_entity(
                server_version="0",
                model_id="tm-ctx",
                kind="assets",
                local_id_a="A1",
                local_id_b="A1",
                descendant_a_id="tm-da",
                descendant_b_id="tm-db",
                lca_model_id="tm-lca",
            )
        assert result == envelope
        mock.lift_composition_entity.assert_awaited_once_with(
            "tm-ctx",
            "assets",
            "A1",
            "A1",
            "tm-da",
            "tm-db",
            "tm-lca",
            lca_descendant_ids=None,
            acknowledged_third_party_subtrees=None,
            field_resolutions=None,
            attached_state_resolutions=None,
            skip_overapplication_gate=False,
        )

    @pytest.mark.asyncio
    async def test_optional_args_forwarded(self) -> None:
        # The route accepts a rich set of operator-confirmation knobs.
        # When the agent supplies them, they all reach the client layer
        # unchanged so the server can run conflict re-detection +
        # over-application gating with the same data the operator saw.
        mock = _mock_client()
        with _patch_client(mock):
            await lift_composition_entity(
                server_version="0",
                model_id="tm-ctx",
                kind="components",
                local_id_a="C1",
                local_id_b="C1",
                descendant_a_id="tm-da",
                descendant_b_id="tm-db",
                lca_model_id="tm-lca",
                lca_descendant_ids=["tm-da", "tm-db", "tm-dc"],
                acknowledged_third_party_subtrees=["tm-dc"],
                field_resolutions={"description": "keep_both"},
                attached_state_resolutions={"state:assertions/AS1": "keep_b"},
                skip_overapplication_gate=True,
            )
        mock.lift_composition_entity.assert_awaited_once_with(
            "tm-ctx",
            "components",
            "C1",
            "C1",
            "tm-da",
            "tm-db",
            "tm-lca",
            lca_descendant_ids=["tm-da", "tm-db", "tm-dc"],
            acknowledged_third_party_subtrees=["tm-dc"],
            field_resolutions={"description": "keep_both"},
            attached_state_resolutions={"state:assertions/AS1": "keep_b"},
            skip_overapplication_gate=True,
        )

    @pytest.mark.asyncio
    async def test_kinds_all_accepted(self) -> None:
        mock = _mock_client()
        for kind in ("assets", "attackers", "components"):
            with _patch_client(mock):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind=kind,
                    local_id_a="X1",
                    local_id_b="X1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )

    @pytest.mark.asyncio
    async def test_invalid_kind_rejected_preflight(self) -> None:
        # Lift, like reconciliation, is restricted to the three entity
        # kinds the composition layer reconciles; trust boundaries +
        # assumptions are out-of-scope at the route layer.
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="kind must be one of"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="trust_boundaries",
                    local_id_a="TB1",
                    local_id_b="TB1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_local_id_a_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="local_id_a is required"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_local_id_b_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="local_id_b is required"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_descendant_a_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="descendant_a_id is required"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_descendant_b_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="descendant_b_id is required"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="",
                    lca_model_id="tm-lca",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_lca_model_id_rejected_preflight(self) -> None:
        # The server can derive the strict LCA from the two descendants,
        # but the tool surface still requires an explicit choice so the
        # agent / operator commits to a target ancestor before applying.
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="lca_model_id is required"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="",
                )
        mock.lift_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_400_stale_resolutions_surfaces_clean_tool_error(self) -> None:
        # Server returns 400 when conflict re-detection finds keys not
        # covered by the operator's resolution map.
        mock = _mock_client(
            lift_composition_entity=AsyncMock(
                side_effect=_http_error(
                    400,
                    "Conflict resolutions are stale or incomplete.",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="400"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )

    @pytest.mark.asyncio
    async def test_404_model_missing_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            lift_composition_entity=AsyncMock(
                side_effect=_http_error(404, "Threat model not found.", method="POST"),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-missing",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            lift_composition_entity=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await lift_composition_entity(
                    server_version="0",
                    model_id="tm-ctx",
                    kind="assets",
                    local_id_a="A1",
                    local_id_b="A1",
                    descendant_a_id="tm-da",
                    descendant_b_id="tm-db",
                    lca_model_id="tm-lca",
                )


class TestSplitCompositionEntity:
    @pytest.mark.asyncio
    async def test_happy_path_returns_envelope_unchanged(self) -> None:
        envelope = {
            "split_id": "split-XYZ",
            "ancestor_model": {"id": "tm-anc", "assets": []},
            "descendant_models": [
                {"id": "tm-d1", "assets": [{"id": "A1"}]},
                {"id": "tm-d2", "assets": [{"id": "A1"}]},
            ],
            "applied_duplications": [
                {"kind": "assets", "from": "tm-anc#A1", "to": "tm-d1#A1"},
                {"kind": "assets", "from": "tm-anc#A1", "to": "tm-d2#A1"},
            ],
            "split_event": {
                "split_id": "split-XYZ",
                "kind": "assets",
                "ancestor_model_id": "tm-anc",
                "source_entity_id": "A1",
                "target_descendants": ["tm-d1", "tm-d2"],
                "new_entity_ids": {"tm-d1": "A1", "tm-d2": "A1"},
                "attached_state_duplications": [],
            },
        }
        mock = _mock_client(
            split_composition_entity=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await split_composition_entity(
                server_version="0",
                model_id="tm-anc",
                kind="assets",
                ancestor_local_id="A1",
                target_descendants=["tm-d1", "tm-d2"],
            )
        assert result == envelope
        mock.split_composition_entity.assert_awaited_once_with(
            "tm-anc", "assets", "A1", ["tm-d1", "tm-d2"],
        )

    @pytest.mark.asyncio
    async def test_kinds_all_accepted(self) -> None:
        mock = _mock_client()
        for kind in ("assets", "attackers", "components"):
            with _patch_client(mock):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind=kind,
                    ancestor_local_id="X1",
                    target_descendants=["tm-d1"],
                )

    @pytest.mark.asyncio
    async def test_invalid_kind_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="kind must be one of"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="trust_boundaries",
                    ancestor_local_id="TB1",
                    target_descendants=["tm-d1"],
                )
        mock.split_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_ancestor_local_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="ancestor_local_id is required"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="assets",
                    ancestor_local_id="",
                    target_descendants=["tm-d1"],
                )
        mock.split_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_target_descendants_rejected_preflight(self) -> None:
        # A split with zero targets is structurally meaningless: there's
        # nowhere for the ancestor's entity to land before the soft-delete.
        # The tool refuses pre-flight to save a server round-trip.
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="target_descendants is required"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="assets",
                    ancestor_local_id="A1",
                    target_descendants=[],
                )
        mock.split_composition_entity.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_400_structural_refusal_surfaces_clean_tool_error(self) -> None:
        # Server returns 400 when the split itself is structurally
        # refused (e.g. the entity is referenced by an attached state
        # element whose duplication isn't supported).
        mock = _mock_client(
            split_composition_entity=AsyncMock(
                side_effect=_http_error(
                    400,
                    "Split refused: entity not present on ancestor.",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="400"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="assets",
                    ancestor_local_id="A1",
                    target_descendants=["tm-d1"],
                )

    @pytest.mark.asyncio
    async def test_404_target_missing_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            split_composition_entity=AsyncMock(
                side_effect=_http_error(
                    404, "Target descendant tm-missing not found.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="assets",
                    ancestor_local_id="A1",
                    target_descendants=["tm-missing"],
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            split_composition_entity=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await split_composition_entity(
                    server_version="0",
                    model_id="tm-anc",
                    kind="assets",
                    ancestor_local_id="A1",
                    target_descendants=["tm-d1"],
                )


class TestPreviewUndoLiftComposition:
    @pytest.mark.asyncio
    async def test_happy_path_plan_returned(self) -> None:
        envelope = {
            "plan": {
                "kind": "lift",
                "original_event_id": "lift-XYZ",
                "state_ops": [
                    {"op": "tombstone", "model_id": "tm-lca", "kind": "assets", "id": "A1"},
                    {"op": "restore", "model_id": "tm-da", "kind": "assets", "id": "A1"},
                ],
            },
            "refusal": None,
        }
        mock = _mock_client(
            preview_lift_undo=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await preview_undo_lift_composition(
                server_version="0",
                model_id="tm-lca",
                lift_id="lift-XYZ",
            )
        assert result == envelope
        mock.preview_lift_undo.assert_awaited_once_with("tm-lca", "lift-XYZ")

    @pytest.mark.asyncio
    async def test_happy_path_refusal_returned(self) -> None:
        # The detector refusal block is returned without any
        # transformation so the agent can surface the structured
        # reasons to the operator.
        envelope = {
            "plan": None,
            "refusal": {
                "reasons": [
                    {"code": "downstream_assertion_present",
                     "model_id": "tm-da",
                     "details": "AS1 was submitted after the lift."},
                ],
            },
        }
        mock = _mock_client(
            preview_lift_undo=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await preview_undo_lift_composition(
                server_version="0",
                model_id="tm-lca",
                lift_id="lift-XYZ",
            )
        assert result == envelope
        assert result["refusal"]["reasons"][0]["code"] == "downstream_assertion_present"

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await preview_undo_lift_composition(
                    server_version="0",
                    model_id="",
                    lift_id="lift-XYZ",
                )
        mock.preview_lift_undo.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_lift_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="lift_id is required"):
                await preview_undo_lift_composition(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="",
                )
        mock.preview_lift_undo.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_404_missing_event_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            preview_lift_undo=AsyncMock(
                side_effect=_http_error(
                    404, "Event lift-missing not found.", method="GET",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await preview_undo_lift_composition(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="lift-missing",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            preview_lift_undo=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="GET",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await preview_undo_lift_composition(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="lift-XYZ",
                )


class TestUndoLiftCompositionEvent:
    @pytest.mark.asyncio
    async def test_happy_path_returns_envelope_unchanged(self) -> None:
        envelope = {
            "undone_event_id": "undo-001",
            "original_event_id": "lift-XYZ",
            "applied_state_ops": [
                {"op": "tombstone", "model_id": "tm-lca", "kind": "assets", "id": "A1"},
            ],
            "models": {
                "lca_model": {"id": "tm-lca", "version": 5, "assets": []},
                "source_descendant_models": [
                    {"id": "tm-da", "version": 7, "assets": [{"id": "A1"}]},
                    {"id": "tm-db", "version": 7, "assets": [{"id": "A1"}]},
                ],
            },
        }
        mock = _mock_client(
            undo_lift=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await undo_lift_composition_event(
                server_version="0",
                model_id="tm-lca",
                lift_id="lift-XYZ",
            )
        assert result == envelope
        mock.undo_lift.assert_awaited_once_with("tm-lca", "lift-XYZ")

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await undo_lift_composition_event(
                    server_version="0",
                    model_id="",
                    lift_id="lift-XYZ",
                )
        mock.undo_lift.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_lift_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="lift_id is required"):
                await undo_lift_composition_event(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="   ",
                )
        mock.undo_lift.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_409_divergence_surfaces_refusal_reasons(self) -> None:
        # The 409 body carries the structured refusal block under
        # ``detail``; the tool surfaces it via the standard API-error
        # path so the agent can present the reasons unchanged.
        import httpx
        req = httpx.Request("POST", "https://api/x")
        resp = httpx.Response(
            409,
            request=req,
            json={
                "detail": {
                    "message": (
                        "Lift undo refused: state has diverged "
                        "since the lift was applied."
                    ),
                    "refusal": {
                        "reasons": [
                            {"code": "downstream_assertion_present",
                             "model_id": "tm-da"},
                            {"code": "co_added_after_event",
                             "model_id": "tm-lca"},
                        ],
                    },
                },
            },
        )
        err = httpx.HTTPStatusError("409", request=req, response=resp)
        mock = _mock_client(undo_lift=AsyncMock(side_effect=err))
        with _patch_client(mock):
            with pytest.raises(ToolError) as excinfo:
                await undo_lift_composition_event(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="lift-XYZ",
                )
        msg = str(excinfo.value)
        assert "409" in msg
        # Refusal reasons must appear verbatim so the agent renders
        # them to the operator without parsing the wrapper text.
        assert "downstream_assertion_present" in msg
        assert "co_added_after_event" in msg

    @pytest.mark.asyncio
    async def test_404_missing_event_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            undo_lift=AsyncMock(
                side_effect=_http_error(
                    404, "Event lift-missing not found.", method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await undo_lift_composition_event(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="lift-missing",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            undo_lift=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await undo_lift_composition_event(
                    server_version="0",
                    model_id="tm-lca",
                    lift_id="lift-XYZ",
                )


class TestPreviewUndoSplitComposition:
    @pytest.mark.asyncio
    async def test_happy_path_plan_returned(self) -> None:
        envelope = {
            "plan": {
                "kind": "split",
                "original_event_id": "split-XYZ",
                "state_ops": [
                    {"op": "restore", "model_id": "tm-anc",
                     "kind": "assets", "id": "A1"},
                ],
            },
            "refusal": None,
        }
        mock = _mock_client(
            preview_split_undo=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await preview_undo_split_composition(
                server_version="0",
                model_id="tm-anc",
                split_id="split-XYZ",
            )
        assert result == envelope
        mock.preview_split_undo.assert_awaited_once_with("tm-anc", "split-XYZ")

    @pytest.mark.asyncio
    async def test_happy_path_refusal_returned(self) -> None:
        envelope = {
            "plan": None,
            "refusal": {
                "reasons": [
                    {"code": "target_entity_edited",
                     "model_id": "tm-d1",
                     "details": "Description was edited after the split."},
                ],
            },
        }
        mock = _mock_client(
            preview_split_undo=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await preview_undo_split_composition(
                server_version="0",
                model_id="tm-anc",
                split_id="split-XYZ",
            )
        assert result["refusal"]["reasons"][0]["code"] == "target_entity_edited"

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await preview_undo_split_composition(
                    server_version="0",
                    model_id="",
                    split_id="split-XYZ",
                )
        mock.preview_split_undo.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_split_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="split_id is required"):
                await preview_undo_split_composition(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="",
                )
        mock.preview_split_undo.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_404_missing_event_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            preview_split_undo=AsyncMock(
                side_effect=_http_error(
                    404, "Event split-missing not found.", method="GET",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await preview_undo_split_composition(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="split-missing",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            preview_split_undo=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="GET",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await preview_undo_split_composition(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="split-XYZ",
                )


class TestUndoSplitCompositionEvent:
    @pytest.mark.asyncio
    async def test_happy_path_returns_envelope_unchanged(self) -> None:
        envelope = {
            "undone_event_id": "undo-002",
            "original_event_id": "split-XYZ",
            "applied_state_ops": [
                {"op": "restore", "model_id": "tm-anc",
                 "kind": "assets", "id": "A1"},
                {"op": "tombstone", "model_id": "tm-d1",
                 "kind": "assets", "id": "A1"},
            ],
            "models": {
                "ancestor_model": {"id": "tm-anc", "version": 8,
                                    "assets": [{"id": "A1"}]},
                "descendant_models": [
                    {"id": "tm-d1", "version": 6, "assets": []},
                    {"id": "tm-d2", "version": 6, "assets": []},
                ],
            },
        }
        mock = _mock_client(
            undo_split=AsyncMock(return_value=envelope),
        )
        with _patch_client(mock):
            result = await undo_split_composition_event(
                server_version="0",
                model_id="tm-anc",
                split_id="split-XYZ",
            )
        assert result == envelope
        mock.undo_split.assert_awaited_once_with("tm-anc", "split-XYZ")

    @pytest.mark.asyncio
    async def test_empty_model_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="model_id is required"):
                await undo_split_composition_event(
                    server_version="0",
                    model_id="",
                    split_id="split-XYZ",
                )
        mock.undo_split.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_split_id_rejected_preflight(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            with pytest.raises(ToolError, match="split_id is required"):
                await undo_split_composition_event(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="",
                )
        mock.undo_split.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_409_divergence_surfaces_refusal_reasons(self) -> None:
        import httpx
        req = httpx.Request("POST", "https://api/x")
        resp = httpx.Response(
            409,
            request=req,
            json={
                "detail": {
                    "message": (
                        "Split undo refused: state has diverged "
                        "since the split was applied."
                    ),
                    "refusal": {
                        "reasons": [
                            {"code": "target_entity_edited",
                             "model_id": "tm-d1"},
                        ],
                    },
                },
            },
        )
        err = httpx.HTTPStatusError("409", request=req, response=resp)
        mock = _mock_client(undo_split=AsyncMock(side_effect=err))
        with _patch_client(mock):
            with pytest.raises(ToolError) as excinfo:
                await undo_split_composition_event(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="split-XYZ",
                )
        msg = str(excinfo.value)
        assert "409" in msg
        assert "target_entity_edited" in msg

    @pytest.mark.asyncio
    async def test_404_missing_event_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            undo_split=AsyncMock(
                side_effect=_http_error(
                    404, "Event split-missing not found.", method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="404"):
                await undo_split_composition_event(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="split-missing",
                )

    @pytest.mark.asyncio
    async def test_503_flag_off_surfaces_clean_tool_error(self) -> None:
        mock = _mock_client(
            undo_split=AsyncMock(
                side_effect=_http_error(
                    503,
                    "Composition is not enabled on this instance.",
                    method="POST",
                ),
            ),
        )
        with _patch_client(mock):
            with pytest.raises(ToolError, match="503"):
                await undo_split_composition_event(
                    server_version="0",
                    model_id="tm-anc",
                    split_id="split-XYZ",
                )

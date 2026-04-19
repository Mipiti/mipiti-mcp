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
    GenerateResult,
    ModelSummary,
    RenameResult,
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
    get_review_queue,
    get_scan_prompt,
    get_system,
    get_system_compliance_report,
    get_threat_model,
    get_verification_report,
    import_controls,
    list_assertions,
    list_compliance_frameworks,
    list_findings,
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
    update_control_status,
    update_finding,
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
        "export_model": b"AssetID,Name\nA1,Tokens\n",
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
        "add_asset": {"id": "A3", "name": "New"},
        "edit_asset": {"id": "A1", "name": "Updated"},
        "remove_asset": {"deleted": True},
        "add_attacker": {"id": "T2", "capability": "New"},
        "edit_attacker": {"id": "T1", "capability": "Updated"},
        "remove_attacker": {"deleted": True},
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
        "list_workspaces": {"workspaces": []},
        "list_systems": {"systems": []},
        "get_system": {"id": "sys-1", "name": "Platform"},
        "create_system": {"id": "sys-2", "name": "New"},
        "add_model_to_system": {"added": True},
        "refine_control": {"accepted": True, "reason": "Coverage maintained.", "control": {"id": "CTRL-01"}},
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


class TestRefineThreatModel:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(server_version="0", model_id="tm-001", instruction="Add CSRF", ctx=ctx)
        assert result["model_id"] == "tm-001"
        mock.refine_threat_model.assert_awaited_once()


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
        mock = _mock_client()
        envelope = {
            "format_version": 1,
            "title": "Checkout",
            "versions": [{"version": 1, "data": {}, "created_at": "2026-04-20T00:00:00Z"}],
        }
        mock.export_model_full = AsyncMock(return_value=envelope)
        with _patch_client(mock):
            result = await export_threat_model_archive(server_version="0", model_id="tm-001")
        assert result["envelope"] == envelope
        mock.export_model_full.assert_awaited_once_with("tm-001")


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
        mock = _mock_client()
        with _patch_client(mock):
            result = await export_threat_model(server_version="0", model_id="tm-001", format="csv")
        assert result["format"] == "csv"
        assert "AssetID,Name" in result["content"]

    @pytest.mark.asyncio
    async def test_pdf_returns_url(self) -> None:
        mock = _mock_client(export_model=AsyncMock(return_value=b"%PDF-binary"))
        with _patch_client(mock):
            result = await export_threat_model(server_version="0", model_id="tm-001", format="pdf")
        assert result["format"] == "pdf"
        assert "/api/models/tm-001/export?format=pdf" in result["download_url"]

    @pytest.mark.asyncio
    async def test_invalid_format(self) -> None:
        with pytest.raises(ToolError, match="format must be"):
            await export_threat_model(server_version="0", model_id="tm-001", format="xml")


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
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_asset(server_version="0", model_id="tm-001", name="Session Store")
        assert result["id"] == "A3"
        mock.add_asset.assert_awaited_once()


class TestEditAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await edit_asset(server_version="0", model_id="tm-001", asset_id="A1", name="Updated")
        assert result["name"] == "Updated"


class TestRemoveAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await remove_asset(server_version="0", model_id="tm-001", asset_id="A1")
        assert result["deleted"] is True


class TestAddAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await add_attacker(server_version="0", model_id="tm-001", capability="Phishing")
        assert result["id"] == "T2"


class TestEditAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await edit_attacker(server_version="0", model_id="tm-001", attacker_id="T1", capability="Updated")
        assert result["capability"] == "Updated"


class TestRemoveAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await remove_attacker(server_version="0", model_id="tm-001", attacker_id="T1")
        assert result["deleted"] is True


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

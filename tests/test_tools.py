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
    apply_compliance_remediation,
    assess_model,
    auto_map_controls,
    check_control_gaps,
    create_system,
    delete_assertion,
    delete_control,
    delete_threat_model,
    edit_asset,
    edit_attacker,
    export_threat_model,
    generate_threat_model,
    get_compliance_report,
    get_control_objectives,
    get_controls,
    get_operation_status,
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
    suggest_compliance_remediation,
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
        "regenerate_controls": ControlsResponse(controls=_controls),
        "update_control_status": {"id": "CTRL-01", "status": "implemented"},
        "add_evidence": {"control_id": "CTRL-01", "evidence_count": 2},
        "remove_evidence": {"control_id": "CTRL-01", "evidence_count": 0},
        "import_controls": {"imported": 3},
        "delete_control": {"deleted": True},
        "check_control_gaps": {"gaps": []},
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
        "auto_map_controls": {"mapped": 5},
        "suggest_compliance_remediation": {"suggestions": [{"action": "add_asset"}]},
        "apply_compliance_remediation": {"applied": 1},
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
    async def test_sync_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await generate_threat_model(server_version="0", feature_description="User login", ctx=ctx, async_mode=False)
        assert result["model_id"] == "tm-001"
        assert result["asset_count"] == 2
        mock.generate_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await generate_threat_model(server_version="0", feature_description="User login", ctx=ctx, async_mode=True)
        assert "job_id" in result
        mock.generate_threat_model.assert_not_awaited()


class TestRefineThreatModel:
    @pytest.mark.asyncio
    async def test_sync_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(server_version="0", model_id="tm-001", instruction="Add CSRF", ctx=ctx, async_mode=False)
        assert result["model_id"] == "tm-001"
        mock.refine_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await refine_threat_model(server_version="0", model_id="tm-001", instruction="Add CSRF", ctx=ctx, async_mode=True)
        assert "job_id" in result


class TestQueryThreatModel:
    @pytest.mark.asyncio
    async def test_sync_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await query_threat_model(server_version="0", model_id="tm-001", question="SQL injection?", ctx=ctx, async_mode=False)
        assert result["answer"] == "The model covers SQL injection."

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await query_threat_model(server_version="0", model_id="tm-001", question="Q?", ctx=ctx, async_mode=True)
        assert "job_id" in result


class TestListThreatModels:
    @pytest.mark.asyncio
    async def test_returns_items(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await list_threat_models(server_version="0")
        assert result["count"] == 2
        assert result["items"][0]["id"] == "tm-001"

    @pytest.mark.asyncio
    async def test_empty(self) -> None:
        mock = _mock_client(list_models=AsyncMock(return_value=[]))
        with _patch_client(mock):
            result = await list_threat_models(server_version="0")
        assert result["count"] == 0


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
            result = await get_controls(server_version="0", model_id="tm-001", ctx=ctx, async_mode=False)
        assert result["total"] == 2
        assert result["returned"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_status(self) -> None:
        """Status filter is passed to the backend (server-side filtering)."""
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            await get_controls(server_version="0", model_id="tm-001", ctx=ctx, status="implemented", async_mode=False)
        mock.get_controls.assert_awaited_once()
        call_kwargs = mock.get_controls.call_args[1]
        assert call_kwargs["status"] == "implemented"

    @pytest.mark.asyncio
    async def test_pagination(self) -> None:
        """Offset/limit are passed to the backend (server-side pagination)."""
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            await get_controls(server_version="0", model_id="tm-001", ctx=ctx, offset=0, limit=1, async_mode=False)
        mock.get_controls.assert_awaited_once()
        call_kwargs = mock.get_controls.call_args[1]
        assert call_kwargs["limit"] == 1

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await get_controls(server_version="0", model_id="tm-001", ctx=ctx, async_mode=True)
        assert "job_id" in result


class TestRegenerateControls:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await regenerate_controls(server_version="0", model_id="tm-001", ctx=ctx, async_mode=False)
        assert "controls" in result
        mock.regenerate_controls.assert_awaited_once()


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
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await import_controls(server_version="0", model_id="tm-001", ctx=ctx, free_text="Encrypt data at rest", async_mode=False)
        assert result["imported"] == 3

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await import_controls(server_version="0", model_id="tm-001", ctx=ctx, async_mode=True)
        assert "job_id" in result


class TestDeleteControl:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await delete_control(server_version="0", model_id="tm-001", control_id="CTRL-01", reason="Duplicate")
        assert result["deleted"] is True


class TestCheckControlGaps:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await check_control_gaps(server_version="0", model_id="tm-001", ctx=ctx, async_mode=False)
        assert "gaps" in result


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
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, async_mode=False)
        assert result["mapped"] == 5

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await auto_map_controls(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, async_mode=True)
        assert "job_id" in result


class TestSuggestComplianceRemediation:
    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await suggest_compliance_remediation(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, async_mode=True)
        assert "job_id" in result

    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await suggest_compliance_remediation(server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, async_mode=False)
        assert "suggestions" in result


class TestApplyComplianceRemediation:
    @pytest.mark.asyncio
    async def test_with_job_id(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        server._jobs["job_test123"] = server._Job(
            id="job_test123", tool_name="suggest_compliance_remediation",
            status="completed",
            result={"suggestions": [{"action": "add_asset"}]},
        )
        try:
            with _patch_client(mock):
                result = await apply_compliance_remediation(
                    server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, job_id="job_test123",
                )
            assert result["applied"] == 1
        finally:
            server._jobs.pop("job_test123", None)

    @pytest.mark.asyncio
    async def test_job_not_found(self) -> None:
        ctx = _mock_ctx()
        with pytest.raises(ToolError, match="not found"):
            await apply_compliance_remediation(
                server_version="0", model_id="tm-001", framework_id="owasp-asvs", ctx=ctx, job_id="job_nonexistent",
            )


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
# Async Operations
# ------------------------------------------------------------------


class TestGetOperationStatus:
    @pytest.mark.asyncio
    async def test_running(self) -> None:
        server._jobs["job_abc"] = server._Job(
            id="job_abc", tool_name="generate_threat_model", status="running",
        )
        try:
            result = await get_operation_status(server_version="0", job_id="job_abc")
            assert result["status"] == "running"
            assert "poll_after_seconds" in result
        finally:
            server._jobs.pop("job_abc", None)

    @pytest.mark.asyncio
    async def test_completed(self) -> None:
        server._jobs["job_done"] = server._Job(
            id="job_done", tool_name="generate_threat_model",
            status="completed", result={"model_id": "tm-001"},
        )
        try:
            result = await get_operation_status(server_version="0", job_id="job_done")
            assert result["status"] == "completed"
            assert result["result"]["model_id"] == "tm-001"
        finally:
            server._jobs.pop("job_done", None)

    @pytest.mark.asyncio
    async def test_failed(self) -> None:
        server._jobs["job_fail"] = server._Job(
            id="job_fail", tool_name="generate_threat_model",
            status="failed", error="Timeout",
        )
        try:
            result = await get_operation_status(server_version="0", job_id="job_fail")
            assert result["status"] == "failed"
            assert result["error"] == "Timeout"
        finally:
            server._jobs.pop("job_fail", None)

    @pytest.mark.asyncio
    async def test_unknown_job(self) -> None:
        with pytest.raises(ToolError, match="Unknown job_id"):
            await get_operation_status(server_version="0", job_id="job_nonexistent")

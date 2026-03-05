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
    mark_evidence_complete,
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
    update_control_status,
    update_finding,
)

from .conftest import SAMPLE_CONTROLS, SAMPLE_MODELS_LIST, SAMPLE_THREAT_MODEL


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

# @mcp.tool() returns FunctionTool objects; .fn gives the raw async function.
_generate_threat_model = generate_threat_model.fn
_refine_threat_model = refine_threat_model.fn
_query_threat_model = query_threat_model.fn
_list_threat_models = list_threat_models.fn
_rename_threat_model = rename_threat_model.fn
_delete_threat_model = delete_threat_model.fn
_get_threat_model = get_threat_model.fn
_export_threat_model = export_threat_model.fn
_get_controls = get_controls.fn
_regenerate_controls = regenerate_controls.fn
_update_control_status = update_control_status.fn
_add_evidence = add_evidence.fn
_remove_evidence = remove_evidence.fn
_import_controls = import_controls.fn
_delete_control = delete_control.fn
_check_control_gaps = check_control_gaps.fn
_get_control_objectives = get_control_objectives.fn
_assess_model = assess_model.fn
_get_review_queue = get_review_queue.fn
_add_asset = add_asset.fn
_edit_asset = edit_asset.fn
_remove_asset = remove_asset.fn
_add_attacker = add_attacker.fn
_edit_attacker = edit_attacker.fn
_remove_attacker = remove_attacker.fn
_list_compliance_frameworks = list_compliance_frameworks.fn
_select_compliance_frameworks = select_compliance_frameworks.fn
_get_compliance_report = get_compliance_report.fn
_map_control_to_requirement = map_control_to_requirement.fn
_auto_map_controls = auto_map_controls.fn
_suggest_compliance_remediation = suggest_compliance_remediation.fn
_apply_compliance_remediation = apply_compliance_remediation.fn
_list_workspaces = list_workspaces.fn
_list_systems = list_systems.fn
_get_system = get_system.fn
_create_system = create_system.fn
_add_model_to_system = add_model_to_system.fn
_select_system_compliance_frameworks = select_system_compliance_frameworks.fn
_get_system_compliance_report = get_system_compliance_report.fn
_submit_assertions = submit_assertions.fn
_list_assertions = list_assertions.fn
_delete_assertion = delete_assertion.fn
_get_verification_report = get_verification_report.fn
_mark_evidence_complete = mark_evidence_complete.fn
_submit_findings = submit_findings.fn
_list_findings = list_findings.fn
_update_finding = update_finding.fn
_get_scan_prompt = get_scan_prompt.fn
_get_operation_status = get_operation_status.fn


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
        "mark_evidence_complete": {"status": "complete"},
        "submit_findings": {"count": 1},
        "list_findings": {"findings": []},
        "update_finding": {"id": "f1", "status": "acknowledged"},
        "list_workspaces": {"workspaces": []},
        "list_systems": {"systems": []},
        "get_system": {"id": "sys-1", "name": "Platform"},
        "create_system": {"id": "sys-2", "name": "New"},
        "add_model_to_system": {"added": True},
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
            result = await _generate_threat_model("User login", ctx, async_mode=False)
        assert result["model_id"] == "tm-001"
        assert result["asset_count"] == 2
        mock.generate_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _generate_threat_model("User login", ctx, async_mode=True)
        assert "job_id" in result
        mock.generate_threat_model.assert_not_awaited()


class TestRefineThreatModel:
    @pytest.mark.asyncio
    async def test_sync_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _refine_threat_model("tm-001", "Add CSRF", ctx, async_mode=False)
        assert result["model_id"] == "tm-001"
        mock.refine_threat_model.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _refine_threat_model("tm-001", "Add CSRF", ctx, async_mode=True)
        assert "job_id" in result


class TestQueryThreatModel:
    @pytest.mark.asyncio
    async def test_sync_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _query_threat_model("tm-001", "SQL injection?", ctx, async_mode=False)
        assert result["answer"] == "The model covers SQL injection."

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _query_threat_model("tm-001", "Q?", ctx, async_mode=True)
        assert "job_id" in result


class TestListThreatModels:
    @pytest.mark.asyncio
    async def test_returns_items(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_threat_models()
        assert result["count"] == 2
        assert result["items"][0]["id"] == "tm-001"

    @pytest.mark.asyncio
    async def test_empty(self) -> None:
        mock = _mock_client(list_models=AsyncMock(return_value=[]))
        with _patch_client(mock):
            result = await _list_threat_models()
        assert result["count"] == 0


class TestRenameThreatModel:
    @pytest.mark.asyncio
    async def test_rename(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _rename_threat_model("tm-001", "New Name")
        assert result["title"] == "New"
        mock.rename_model.assert_awaited_once_with("tm-001", "New Name")


class TestDeleteThreatModel:
    @pytest.mark.asyncio
    async def test_delete(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _delete_threat_model("tm-001")
        assert result["deleted"] is True
        mock.delete_model.assert_awaited_once()


class TestGetThreatModel:
    @pytest.mark.asyncio
    async def test_latest(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_threat_model("tm-001")
        assert result["id"] == "tm-001"
        mock.get_model.assert_awaited_once_with("tm-001", None)

    @pytest.mark.asyncio
    async def test_specific_version(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await _get_threat_model("tm-001", version=3)
        mock.get_model.assert_awaited_once_with("tm-001", 3)


class TestExportThreatModel:
    @pytest.mark.asyncio
    async def test_csv(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _export_threat_model("tm-001", "csv")
        assert "AssetID,Name" in result

    @pytest.mark.asyncio
    async def test_pdf_returns_url(self) -> None:
        mock = _mock_client(export_model=AsyncMock(return_value=b"%PDF-binary"))
        with _patch_client(mock):
            result = await _export_threat_model("tm-001", "pdf")
        assert "Download from:" in result
        assert "/api/models/tm-001/export?format=pdf" in result

    @pytest.mark.asyncio
    async def test_invalid_format(self) -> None:
        with pytest.raises(ToolError, match="format must be"):
            await _export_threat_model("tm-001", "xml")


# ------------------------------------------------------------------
# Controls
# ------------------------------------------------------------------


class TestGetControls:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _get_controls("tm-001", ctx, async_mode=False)
        assert result["total"] == 2
        assert result["returned"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_status(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _get_controls("tm-001", ctx, status="implemented", async_mode=False)
        assert result["total"] == 1
        assert result["controls"][0]["status"] == "implemented"

    @pytest.mark.asyncio
    async def test_pagination(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _get_controls("tm-001", ctx, offset=0, limit=1, async_mode=False)
        assert result["returned"] == 1
        assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_async_mode(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _get_controls("tm-001", ctx, async_mode=True)
        assert "job_id" in result


class TestRegenerateControls:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _regenerate_controls("tm-001", ctx, async_mode=False)
        assert "controls" in result
        mock.regenerate_controls.assert_awaited_once()


class TestUpdateControlStatus:
    @pytest.mark.asyncio
    async def test_valid_status(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _update_control_status("tm-001", "CTRL-01", "implemented")
        assert result["status"] == "implemented"

    @pytest.mark.asyncio
    async def test_invalid_status(self) -> None:
        with pytest.raises(ToolError, match="status must be"):
            await _update_control_status("tm-001", "CTRL-01", "invalid")

    @pytest.mark.asyncio
    async def test_with_evidence_json(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            await _update_control_status(
                "tm-001", "CTRL-01", "implemented",
                evidence='[{"type": "code", "label": "test"}]',
            )
        mock.update_control_status.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bad_evidence_json(self) -> None:
        with pytest.raises(ToolError, match="evidence must be valid JSON"):
            await _update_control_status(
                "tm-001", "CTRL-01", "implemented", evidence="not-json",
            )


class TestAddEvidence:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _add_evidence("tm-001", "CTRL-01", "code", "bcrypt usage")
        assert result["evidence_count"] == 2

    @pytest.mark.asyncio
    async def test_empty_label(self) -> None:
        with pytest.raises(ToolError, match="label is required"):
            await _add_evidence("tm-001", "CTRL-01", "code", "  ")


class TestRemoveEvidence:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _remove_evidence("tm-001", "CTRL-01", 0)
        assert result["evidence_count"] == 0


class TestImportControls:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _import_controls("tm-001", ctx, free_text="Encrypt data at rest", async_mode=False)
        assert result["imported"] == 3

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _import_controls("tm-001", ctx, async_mode=True)
        assert "job_id" in result


class TestDeleteControl:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _delete_control("tm-001", "CTRL-01", "Duplicate")
        assert result["deleted"] is True


class TestCheckControlGaps:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _check_control_gaps("tm-001", ctx, async_mode=False)
        assert "gaps" in result


# ------------------------------------------------------------------
# Control Objectives & Assurance
# ------------------------------------------------------------------


class TestGetControlObjectives:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_control_objectives("tm-001")
        assert result["total"] == 1


class TestAssessModel:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _assess_model("tm-001")
        assert result["mitigated"] == 1


class TestGetReviewQueue:
    @pytest.mark.asyncio
    async def test_basic(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_review_queue()
        assert "items" in result


# ------------------------------------------------------------------
# Assets & Attackers
# ------------------------------------------------------------------


class TestAddAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _add_asset("tm-001", "Session Store")
        assert result["id"] == "A3"
        mock.add_asset.assert_awaited_once()


class TestEditAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _edit_asset("tm-001", "A1", name="Updated")
        assert result["name"] == "Updated"


class TestRemoveAsset:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _remove_asset("tm-001", "A1")
        assert result["deleted"] is True


class TestAddAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _add_attacker("tm-001", "Phishing")
        assert result["id"] == "T2"


class TestEditAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _edit_attacker("tm-001", "T1", capability="Updated")
        assert result["capability"] == "Updated"


class TestRemoveAttacker:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _remove_attacker("tm-001", "T1")
        assert result["deleted"] is True


# ------------------------------------------------------------------
# Compliance
# ------------------------------------------------------------------


class TestListComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_compliance_frameworks()
        assert len(result["frameworks"]) == 1


class TestSelectComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _select_compliance_frameworks("tm-001", ["owasp-asvs"])
        assert result["selected"] == 1


class TestGetComplianceReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_compliance_report("tm-001", "owasp-asvs")
        assert result["coverage"] == 0.8


class TestMapControlToRequirement:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _map_control_to_requirement(
                "tm-001", "owasp-asvs", "V2.1.1", "CTRL-01",
            )
        assert result["mapped"] is True


class TestAutoMapControls:
    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _auto_map_controls("tm-001", "owasp-asvs", ctx, async_mode=False)
        assert result["mapped"] == 5

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _auto_map_controls("tm-001", "owasp-asvs", ctx, async_mode=True)
        assert "job_id" in result


class TestSuggestComplianceRemediation:
    @pytest.mark.asyncio
    async def test_async(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _suggest_compliance_remediation("tm-001", "owasp-asvs", ctx, async_mode=True)
        assert "job_id" in result

    @pytest.mark.asyncio
    async def test_sync(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _suggest_compliance_remediation("tm-001", "owasp-asvs", ctx, async_mode=False)
        assert "suggestions" in result


class TestApplyComplianceRemediation:
    @pytest.mark.asyncio
    async def test_with_suggestions(self) -> None:
        mock = _mock_client()
        ctx = _mock_ctx()
        with _patch_client(mock):
            result = await _apply_compliance_remediation(
                "tm-001", "owasp-asvs", ctx,
                suggestions=[{"action": "add_asset"}],
            )
        assert result["applied"] == 1

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
                result = await _apply_compliance_remediation(
                    "tm-001", "owasp-asvs", ctx, job_id="job_test123",
                )
            assert result["applied"] == 1
        finally:
            server._jobs.pop("job_test123", None)

    @pytest.mark.asyncio
    async def test_job_not_found(self) -> None:
        ctx = _mock_ctx()
        with pytest.raises(ToolError, match="not found"):
            await _apply_compliance_remediation(
                "tm-001", "owasp-asvs", ctx, job_id="job_nonexistent",
            )


# ------------------------------------------------------------------
# Workspaces & Systems
# ------------------------------------------------------------------


class TestListWorkspaces:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_workspaces()
        assert "workspaces" in result


class TestListSystems:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_systems()
        assert "systems" in result


class TestGetSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_system("sys-1")
        assert result["id"] == "sys-1"


class TestCreateSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _create_system("Platform")
        assert result["id"] == "sys-2"


class TestAddModelToSystem:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _add_model_to_system("sys-1", "tm-001")
        assert result["added"] is True


# ------------------------------------------------------------------
# System Compliance
# ------------------------------------------------------------------


class TestSelectSystemComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _select_system_compliance_frameworks("sys-1", ["owasp-asvs"])
        assert result["selected"] == 1


class TestGetSystemComplianceReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_system_compliance_report("sys-1", "owasp-asvs")
        assert result["coverage"] == 0.9


# ------------------------------------------------------------------
# Assertions & Verification
# ------------------------------------------------------------------


class TestSubmitAssertions:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _submit_assertions(
                "tm-001", "CTRL-01",
                json.dumps([{"type": "file_exists", "params": {"path": "auth.py"}}]),
            )
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_bad_json(self) -> None:
        with pytest.raises(ToolError, match="assertions_json must be valid JSON"):
            await _submit_assertions("tm-001", "CTRL-01", "not-json")


class TestListAssertions:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_assertions("tm-001", "CTRL-01")
        assert "assertions" in result


class TestDeleteAssertion:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _delete_assertion("tm-001", "CTRL-01", "a-1")
        assert result["deleted"] is True


class TestGetVerificationReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_verification_report("tm-001")
        assert result["tier1_pass"] == 3


class TestMarkEvidenceComplete:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _mark_evidence_complete("tm-001", "CTRL-01")
        assert result["status"] == "complete"


# ------------------------------------------------------------------
# Findings
# ------------------------------------------------------------------


class TestSubmitFindings:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _submit_findings(
                "tm-001",
                json.dumps([{"control_id": "CTRL-01", "title": "Missing encryption"}]),
            )
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_bad_json(self) -> None:
        with pytest.raises(ToolError, match="findings_json must be valid JSON"):
            await _submit_findings("tm-001", "not-json")


class TestListFindings:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _list_findings("tm-001")
        assert "findings" in result


class TestUpdateFinding:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _update_finding("tm-001", "f1", "acknowledged")
        assert result["status"] == "acknowledged"


# ------------------------------------------------------------------
# Scan Prompt
# ------------------------------------------------------------------


class TestGetScanPrompt:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock = _mock_client()
        with _patch_client(mock):
            result = await _get_scan_prompt("tm-001")
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
            result = await _get_operation_status("job_abc")
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
            result = await _get_operation_status("job_done")
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
            result = await _get_operation_status("job_fail")
            assert result["status"] == "failed"
            assert result["error"] == "Timeout"
        finally:
            server._jobs.pop("job_fail", None)

    @pytest.mark.asyncio
    async def test_unknown_job(self) -> None:
        with pytest.raises(ToolError, match="Unknown job_id"):
            await _get_operation_status("job_nonexistent")

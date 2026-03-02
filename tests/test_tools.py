"""Unit tests for MCP tool implementations."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mipiti_mcp.server import (
    _export_threat_model,
    _format_threat_model,
    _generate_threat_model,
    _get_controls,
    _get_threat_model,
    _list_threat_models,
    _query_threat_model,
    _refine_threat_model,
)
from mipiti_mcp.types import (
    Asset,
    Assumption,
    Attacker,
    SecurityProperty,
    Control,
    ControlObjective,
    ModelSummary,
    ThreatModel,
    TrustBoundary,
)

# ------------------------------------------------------------------
# Sample data
# ------------------------------------------------------------------

SAMPLE_MODEL = ThreatModel(
    id="tm-001",
    feature_description="User login with OAuth",
    title="User Login OAuth",
    version=1,
    trust_boundaries=[
        TrustBoundary(id="TB1", description="Internet to DMZ", crosses=["A1", "T1"]),
    ],
    assets=[
        Asset(
            id="A1",
            name="OAuth Tokens",
            description="Bearer tokens",
            security_properties=[SecurityProperty.C, SecurityProperty.I],
        ),
    ],
    attackers=[
        Attacker(
            id="T1",
            capability="Credential stuffing",
            position="External",
            archetype="Automated",
        ),
    ],
    control_objectives=[
        ControlObjective(
            id="CO1",
            asset_id="A1",
            security_property=SecurityProperty.C,
            attacker_id="T1",
            statement="Ensure confidentiality of OAuth Tokens against Credential stuffing",
        ),
    ],
    assumptions=[
        Assumption(id="AS1", description="OAuth provider is trusted", status="active"),
    ],
)

SAMPLE_SUMMARIES = [
    ModelSummary(
        id="tm-001",
        title="User Login OAuth",
        feature_description="User login with OAuth",
        created_at="2026-02-11T00:00:00",
        version=1,
    ),
    ModelSummary(
        id="tm-002",
        title="Payment Processing",
        feature_description="Stripe payment integration",
        created_at="2026-02-10T00:00:00",
        version=2,
    ),
]

SAMPLE_CONTROLS = [
    Control(
        id="CO1-1",
        control_objective_id="CO1",
        description="Token rotation",
        status="not_implemented",
    ),
    Control(
        id="CO1-2",
        control_objective_id="CO1",
        description="Rate limiting",
        status="implemented",
    ),
]


# ------------------------------------------------------------------
# _format_threat_model tests
# ------------------------------------------------------------------


def test_format_includes_title() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "# Threat Model: User Login OAuth" in result


def test_format_includes_id_and_version() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "`tm-001`" in result
    assert "**Version**: 1" in result


def test_format_includes_trust_boundaries() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "## Trust Boundaries" in result
    assert "Internet to DMZ" in result
    assert "A1, T1" in result


def test_format_includes_assets() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "## Assets" in result
    assert "OAuth Tokens" in result
    assert "C, I" in result


def test_format_includes_attackers() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "## Attackers" in result
    assert "Credential stuffing" in result


def test_format_includes_control_objectives() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "## Control Objectives" in result
    assert "CO1" in result
    assert "Ensure confidentiality" in result


def test_format_includes_assumptions() -> None:
    result = _format_threat_model(SAMPLE_MODEL)
    assert "## Assumptions" in result
    assert "OAuth provider is trusted" in result


def test_format_empty_model() -> None:
    model = ThreatModel(id="empty", feature_description="Nothing")
    result = _format_threat_model(model)
    assert "# Threat Model: Nothing" in result
    assert "## Assets" not in result
    assert "## Attackers" not in result


def test_format_title_fallback() -> None:
    model = ThreatModel(
        id="x",
        feature_description="A very long feature description that should be truncated to 80 chars if there is no title set",
        title="",
    )
    result = _format_threat_model(model)
    assert "# Threat Model: A very long feature" in result


# ------------------------------------------------------------------
# Tool implementation tests (call _impl functions directly)
# ------------------------------------------------------------------


def _mock_client(**overrides: AsyncMock) -> AsyncMock:
    """Create a mocked MipitiClient with sensible defaults."""
    client = AsyncMock()
    client.generate_threat_model = overrides.get(
        "generate_threat_model", AsyncMock(return_value=SAMPLE_MODEL)
    )
    client.refine_threat_model = overrides.get(
        "refine_threat_model", AsyncMock(return_value=SAMPLE_MODEL)
    )
    client.query_threat_model = overrides.get(
        "query_threat_model",
        AsyncMock(return_value="The model covers SQL injection."),
    )
    client.list_models = overrides.get(
        "list_models", AsyncMock(return_value=SAMPLE_SUMMARIES)
    )
    client.get_model = overrides.get(
        "get_model", AsyncMock(return_value=SAMPLE_MODEL)
    )
    client.get_controls = overrides.get(
        "get_controls", AsyncMock(return_value=SAMPLE_CONTROLS)
    )
    client.export_model = overrides.get(
        "export_model", AsyncMock(return_value=b"AssetID,Name\nA1,Tokens\n")
    )
    client.api_url = "https://api.mipiti.io"
    return client


def _mock_ctx() -> AsyncMock:
    """Create a mocked Context object."""
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_generate_threat_model_tool() -> None:
    mock = _mock_client()
    ctx = _mock_ctx()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _generate_threat_model("User login", ctx)
    assert "User Login OAuth" in result
    assert "OAuth Tokens" in result
    mock.generate_threat_model.assert_awaited_once()


@pytest.mark.asyncio
async def test_refine_threat_model_tool() -> None:
    mock = _mock_client()
    ctx = _mock_ctx()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _refine_threat_model("tm-001", "Add CSRF", ctx)
    assert "User Login OAuth" in result
    mock.refine_threat_model.assert_awaited_once()


@pytest.mark.asyncio
async def test_query_threat_model_tool() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _query_threat_model("tm-001", "SQL injection?")
    assert "SQL injection" in result


@pytest.mark.asyncio
async def test_list_threat_models_tool() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _list_threat_models()
    assert "tm-001" in result
    assert "tm-002" in result
    assert "User Login OAuth" in result
    assert "Payment Processing" in result


@pytest.mark.asyncio
async def test_list_threat_models_empty() -> None:
    mock = _mock_client(list_models=AsyncMock(return_value=[]))
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _list_threat_models()
    assert result == "No threat models found."


@pytest.mark.asyncio
async def test_get_threat_model_tool() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _get_threat_model("tm-001")
    assert "User Login OAuth" in result
    mock.get_model.assert_awaited_once_with("tm-001", None)


@pytest.mark.asyncio
async def test_get_threat_model_with_version() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        await _get_threat_model("tm-001", version=3)
    mock.get_model.assert_awaited_once_with("tm-001", 3)


@pytest.mark.asyncio
async def test_get_controls_tool() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _get_controls("tm-001")
    assert "CO1-1" in result
    assert "Token rotation" in result
    assert "Implemented" in result
    assert "Not Implemented" in result


@pytest.mark.asyncio
async def test_get_controls_empty() -> None:
    mock = _mock_client(get_controls=AsyncMock(return_value=[]))
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _get_controls("tm-001")
    assert result == "No controls found for this model."


@pytest.mark.asyncio
async def test_export_csv() -> None:
    mock = _mock_client()
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _export_threat_model("tm-001", "csv")
    assert "AssetID,Name" in result


@pytest.mark.asyncio
async def test_export_pdf_returns_url() -> None:
    mock = _mock_client(export_model=AsyncMock(return_value=b"%PDF-binary"))
    with patch("mipiti_mcp.server._get_client", return_value=mock):
        result = await _export_threat_model("tm-001", "pdf")
    assert "Download from:" in result
    assert "/api/models/tm-001/export?format=pdf" in result


@pytest.mark.asyncio
async def test_export_invalid_format() -> None:
    with pytest.raises(ToolError, match="format must be"):
        await _export_threat_model("tm-001", "xml")

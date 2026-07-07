"""Unit tests for the get_remediation_leverage tool + client method."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import build_instructions, get_remediation_leverage


_PLAN = {
    "model_id": "tm-001",
    "model_version": 3,
    "summary": {
        "total_controls": 5,
        "candidate_controls": 3,
        "total_objectives": 8,
        "currently_mitigated": 2,
        "plan_controls": 2,
        "plan_reaches_mitigated": 6,
        "headline": "8 objectives collapse to 2 controls.",
    },
    "ranked": [
        {"control_id": "CTRL-01", "description": "MFA", "status": "planned",
         "covers": 4, "unlocks": 3},
        {"control_id": "CTRL-07", "description": "Rate limit", "status": "planned",
         "covers": 2, "unlocks": 1},
    ],
    "greedy_plan": [
        {"control_id": "CTRL-01", "description": "MFA",
         "unlocks_now": 3, "cumulative_mitigated": 5},
        {"control_id": "CTRL-07", "description": "Rate limit",
         "unlocks_now": 1, "cumulative_mitigated": 6},
    ],
}


# ------------------------------------------------------------------
# Tool-level tests (mock the MipitiClient)
# ------------------------------------------------------------------


class TestGetRemediationLeverage:
    @pytest.mark.asyncio
    async def test_calls_client_with_model_id(self) -> None:
        """The tool forwards model_id to the client and returns the
        server envelope verbatim — ranked controls + greedy fix order."""
        client = AsyncMock()
        client.get_remediation_leverage = AsyncMock(return_value=_PLAN)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await get_remediation_leverage(
                server_version="0", model_id="tm-001",
            )
        client.get_remediation_leverage.assert_awaited_once_with("tm-001")
        assert result == _PLAN
        assert result["ranked"][0]["control_id"] == "CTRL-01"
        assert result["greedy_plan"][-1]["cumulative_mitigated"] == 6

    @pytest.mark.asyncio
    async def test_404_wrapped_as_tool_error(self) -> None:
        """Non-existent model surfaces as a clean ToolError, not a raw
        httpx exception — the agent surface stays uniform."""
        request = httpx.Request("GET", "http://x/api/models/tm-x/remediation")
        response = httpx.Response(
            404, json={"detail": "Threat model not found."}, request=request,
        )
        client = AsyncMock()
        client.get_remediation_leverage = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "not found", request=request, response=response,
            ),
        )
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="404"):
                await get_remediation_leverage(
                    server_version="0", model_id="tm-x",
                )


# ------------------------------------------------------------------
# Client-level HTTP wiring (verifies path + method)
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_client_uses_get_on_remediation_path(mock_env: None) -> None:
    """get_remediation_leverage must hit GET /api/models/{id}/remediation
    — read-only, no body, no mutation — and pass the envelope through."""
    route = respx.get(
        "https://test.api.mipiti.io/api/models/tm-001/remediation",
    ).mock(return_value=httpx.Response(200, json=_PLAN))
    client = MipitiClient()
    data = await client.get_remediation_leverage("tm-001")
    assert route.called
    assert data["model_id"] == "tm-001"
    assert data["summary"]["plan_controls"] == 2
    assert [s["control_id"] for s in data["greedy_plan"]] == ["CTRL-01", "CTRL-07"]
    await client.close()


# ------------------------------------------------------------------
# Instructions catalog presence
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("organization", "user"),
        ("enterprise", "user"),
        ("developer", "user"),
    ],
)
def test_remediation_leverage_listed_in_instructions(tier: str, role: str) -> None:
    """The tool is discoverable in the instructions catalog across
    tiers/roles so the agent knows to reach for it when prioritizing."""
    text = build_instructions(tier=tier, role=role)
    assert "get_remediation_leverage" in text

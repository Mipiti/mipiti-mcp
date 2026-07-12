"""Unit tests for the recompute_verdicts / get_recompute_quote tools + client methods."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import build_instructions, get_recompute_quote, recompute_verdicts


_RESULT = {
    "model_id": "tm-001",
    "model_version": 4,
    "enqueued_coverage": 12,
    "enqueued_group_sufficiency": 8,
    "total_enqueued": 20,
    "estimated_credits": 42.5,
    "quote": {
        "estimated_credits": 42.5,
        "computed_at": "2026-07-12T10:00:00+00:00",
        "rate_version": "2026-07-01T00:00:00+00:00",
        "informational": True,
    },
    "governor": {"exhausted": False, "resets_at": "2026-07-13T00:00:00+00:00"},
}

_QUOTE = {
    "estimated_credits": 42.5,
    "computed_at": "2026-07-12T10:00:00+00:00",
    "rate_version": "2026-07-01T00:00:00+00:00",
    "informational": True,
    "total_enqueueable": 20,
    "already_evaluated": 5,
    "governor": {"exhausted": True, "resets_at": "2026-07-13T00:00:00+00:00"},
}


# ------------------------------------------------------------------
# Tool-level tests (mock the MipitiClient)
# ------------------------------------------------------------------


class TestRecomputeVerdicts:
    @pytest.mark.asyncio
    async def test_calls_client_and_returns_envelope(self) -> None:
        """The tool forwards model_id and returns the server envelope
        verbatim — enqueue counts, estimate, spend status."""
        client = AsyncMock()
        client.recompute_verdicts = AsyncMock(return_value=_RESULT)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await recompute_verdicts(server_version="0", model_id="tm-001")
        client.recompute_verdicts.assert_awaited_once_with("tm-001")
        assert result == _RESULT
        assert result["total_enqueued"] == 20
        assert result["governor"]["exhausted"] is False

    @pytest.mark.asyncio
    async def test_503_wrapped_as_tool_error(self) -> None:
        """Observability unavailable surfaces as a clean ToolError, not a
        raw httpx exception — the agent surface stays uniform."""
        request = httpx.Request(
            "POST", "http://x/api/models/tm-x/verdict-divergence/recompute",
        )
        response = httpx.Response(
            503, json={"detail": "Verdict observability is not enabled."},
            request=request,
        )
        client = AsyncMock()
        client.recompute_verdicts = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "unavailable", request=request, response=response,
            ),
        )
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="503"):
                await recompute_verdicts(server_version="0", model_id="tm-x")


class TestGetRecomputeQuote:
    @pytest.mark.asyncio
    async def test_calls_client_and_returns_quote(self) -> None:
        client = AsyncMock()
        client.get_recompute_quote = AsyncMock(return_value=_QUOTE)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await get_recompute_quote(server_version="0", model_id="tm-001")
        client.get_recompute_quote.assert_awaited_once_with("tm-001")
        assert result == _QUOTE
        assert result["informational"] is True
        assert result["governor"]["exhausted"] is True


# ------------------------------------------------------------------
# Client-level HTTP wiring (verifies path + method)
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_client_posts_recompute_path(mock_env: None) -> None:
    """recompute_verdicts must POST the recompute path and pass the
    envelope through."""
    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/verdict-divergence/recompute",
    ).mock(return_value=httpx.Response(200, json=_RESULT))
    client = MipitiClient()
    data = await client.recompute_verdicts("tm-001")
    assert route.called
    assert data["enqueued_coverage"] == 12
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_client_gets_quote_path(mock_env: None) -> None:
    """get_recompute_quote must hit GET .../recompute/quote — read-only,
    no body, no mutation."""
    route = respx.get(
        "https://test.api.mipiti.io/api/models/tm-001/verdict-divergence/recompute/quote",
    ).mock(return_value=httpx.Response(200, json=_QUOTE))
    client = MipitiClient()
    data = await client.get_recompute_quote("tm-001")
    assert route.called
    assert data["total_enqueueable"] == 20
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
def test_recompute_verdicts_listed_in_instructions(tier: str, role: str) -> None:
    """The tools are discoverable in the instructions catalog across tiers."""
    text = build_instructions(tier, role)
    assert "recompute_verdicts" in text
    assert "get_recompute_quote" in text

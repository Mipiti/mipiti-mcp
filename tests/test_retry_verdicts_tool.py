"""Unit tests for the retry_verdicts tool + client method."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import retry_verdicts

_RESULT = {
    "model_id": "tm-001",
    "model_version": 4,
    "retried_slots": 7,
    "governor": {"exhausted": False, "resets_at": "2026-07-13T00:00:00+00:00"},
}


class TestRetryVerdicts:
    @pytest.mark.asyncio
    async def test_forwards_model_id_and_returns_envelope(self) -> None:
        """The tool forwards model_id and returns the server envelope verbatim."""
        client = AsyncMock()
        client.retry_verdicts = AsyncMock(return_value=_RESULT)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await retry_verdicts(server_version="0", model_id="tm-001")
        client.retry_verdicts.assert_awaited_once_with("tm-001")
        assert result == _RESULT
        assert result["retried_slots"] == 7


@pytest.mark.asyncio
@respx.mock
async def test_client_posts_retry_path(mock_env: None) -> None:
    """retry_verdicts must POST the retry path and pass the envelope through."""
    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/verdicts/retry",
    ).mock(return_value=httpx.Response(200, json=_RESULT))
    client = MipitiClient()
    data = await client.retry_verdicts("tm-001")
    assert route.called
    assert data["retried_slots"] == 7
    await client.close()

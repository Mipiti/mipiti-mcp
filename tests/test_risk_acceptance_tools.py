"""Unit tests for the create_risk_acceptance tool + client method."""

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import create_risk_acceptance


# ------------------------------------------------------------------
# Tool-level (mock the MipitiClient)
# ------------------------------------------------------------------


class TestCreateRiskAcceptanceTool:
    @pytest.mark.asyncio
    async def test_forwards_fields_and_passes_through(self) -> None:
        """The tool forwards every field to the client and returns the server
        envelope verbatim (server-driven shape)."""
        created = {
            "id": "RA-1", "model_id": "tm-1", "control_objective_id": "CO3",
            "owner": "Security Lead", "justification": "compensating controls in place",
            "status": "active", "review_by": "2027-02-06T00:00:00Z",
        }
        client = AsyncMock()
        client.create_risk_acceptance = AsyncMock(return_value=created)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await create_risk_acceptance(
                server_version="0", model_id="tm-1", control_objective_id="CO3",
                owner="Security Lead", justification="compensating controls in place",
                review_by="2027-02-06T00:00:00Z",
            )
        client.create_risk_acceptance.assert_awaited_once_with(
            "tm-1", control_objective_id="CO3", owner="Security Lead",
            justification="compensating controls in place",
            review_by="2027-02-06T00:00:00Z",
        )
        assert result == created


# ------------------------------------------------------------------
# Client-level (mock the HTTP transport)
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_client_posts_with_body_and_idempotency(mock_env: None) -> None:
    """create_risk_acceptance must POST /api/models/{id}/risk-acceptances with
    the four fields in the body and, being mutating, carry an Idempotency-Key."""
    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-1/risk-acceptances",
    ).mock(return_value=httpx.Response(200, json={"id": "RA-1", "status": "active"}))
    client = MipitiClient()
    data = await client.create_risk_acceptance(
        "tm-1", control_objective_id="CO3", owner="o",
        justification="j", review_by="2027-02-06T00:00:00Z",
    )
    assert route.called
    sent = route.calls.last.request
    assert json.loads(sent.content) == {
        "control_objective_id": "CO3", "owner": "o",
        "justification": "j", "review_by": "2027-02-06T00:00:00Z",
        # The record is discriminated by kind; an acceptance says the exposure
        # is real and is being carried.
        "kind": "risk_accepted",
    }
    assert sent.headers.get("Idempotency-Key"), "mutating call must carry Idempotency-Key"
    assert data["id"] == "RA-1"
    await client.close()

"""Unit tests for the control-objective disposition tools + client methods.

A disposition says an objective does not apply to this system. Its sibling, a
risk acceptance, says the exposure is real and is being carried. They share one
record and one lifecycle and differ only in the claim, so the thing worth
pinning down here is that the claim actually reaches the server and that the
two do not blur into each other.
"""

import httpx
import pytest
import respx
from unittest.mock import AsyncMock, patch

from fastmcp.exceptions import ToolError

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import create_co_disposition, list_co_dispositions


class TestCreateCoDispositionTool:
    @pytest.mark.asyncio
    async def test_records_the_not_applicable_claim(self) -> None:
        """The distinguishing field is the kind: without it the server would
        record the opposite claim about the same objective."""
        created = {
            "id": "D-1", "model_id": "tm-1", "control_objective_id": "CO3",
            "owner": "Platform Lead", "justification": "no such deployment path",
            "status": "active", "review_by": "2027-02-06T00:00:00Z",
            "kind": "not_applicable",
        }
        client = AsyncMock()
        client.create_risk_acceptance = AsyncMock(return_value=created)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await create_co_disposition(
                server_version="0", model_id="tm-1", control_objective_id="CO3",
                owner="Platform Lead", justification="no such deployment path",
                review_by="2027-02-06T00:00:00Z",
            )
        client.create_risk_acceptance.assert_awaited_once_with(
            "tm-1", control_objective_id="CO3", owner="Platform Lead",
            justification="no such deployment path",
            review_by="2027-02-06T00:00:00Z",
            kind="not_applicable",
        )
        assert result == created


class TestListCoDispositionsTool:
    @pytest.mark.asyncio
    async def test_returns_both_kinds_when_unfiltered(self) -> None:
        rows = [
            {"id": "D-1", "kind": "not_applicable", "status": "active"},
            {"id": "RA-1", "kind": "risk_accepted", "status": "expired"},
        ]
        client = AsyncMock()
        client.list_co_dispositions = AsyncMock(return_value=rows)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await list_co_dispositions(server_version="0", model_id="tm-1")
        # Explicitly "all": the endpoint's own default is risk_accepted, so a
        # tool that means both has to say so rather than rely on omission.
        client.list_co_dispositions.assert_awaited_once_with("tm-1", kind="all")
        # Lists are wrapped, as every list-returning tool here does.
        assert result == {"items": rows}

    @pytest.mark.asyncio
    async def test_forwards_the_kind_filter(self) -> None:
        client = AsyncMock()
        client.list_co_dispositions = AsyncMock(return_value=[])
        with patch("mipiti_mcp.server._get_client", return_value=client):
            await list_co_dispositions(
                server_version="0", model_id="tm-1", kind="not_applicable",
            )
        client.list_co_dispositions.assert_awaited_once_with(
            "tm-1", kind="not_applicable",
        )

    @pytest.mark.asyncio
    async def test_an_unknown_kind_is_refused_before_the_call(self) -> None:
        """A word that is not one of the two must not reach the server. It
        would match no record, the call would come back empty, and an agent
        reads an empty list as "nothing has been signed on this model" — a
        false negative wearing the clothes of a definitive answer.

        Case and whitespace ARE normalised (see above); what is refused is a
        value that is a different word rather than a spelling of one of
        these two. Normalising further would be guessing."""
        client = AsyncMock()
        client.list_co_dispositions = AsyncMock(return_value=[])
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError):
                await list_co_dispositions(
                    server_version="0", model_id="tm-1", kind="notapplicable",
                )
        client.list_co_dispositions.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("given", ["NOT_APPLICABLE", " not_applicable ", "Not_Applicable"])
    async def test_case_and_whitespace_are_honoured_not_refused(self, given) -> None:
        """The intent of "NOT_APPLICABLE" is not in doubt. This is a read
        filter with nothing destructive behind it, so serve what was meant
        rather than making the caller guess at punctuation."""
        client = AsyncMock()
        client.list_co_dispositions = AsyncMock(return_value=[])
        with patch("mipiti_mcp.server._get_client", return_value=client):
            await list_co_dispositions(
                server_version="0", model_id="tm-1", kind=given,
            )
        client.list_co_dispositions.assert_awaited_once_with(
            "tm-1", kind="not_applicable",
        )


class TestClientMethods:
    @pytest.mark.asyncio
    @respx.mock
    async def test_create_sends_the_kind(self, mock_env: None) -> None:
        route = respx.post(
            "https://test.api.mipiti.io/api/models/tm-1/risk-acceptances"
        ).mock(return_value=httpx.Response(200, json={"id": "D-1"}))
        client = MipitiClient()
        await client.create_risk_acceptance(
            "tm-1", control_objective_id="CO1", owner="o",
            justification="j", review_by="2027-01-01T00:00:00Z",
            kind="not_applicable",
        )
        assert route.called
        import json as _json
        body = _json.loads(route.calls[0].request.content)
        assert body["kind"] == "not_applicable"

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_defaults_to_risk_accepted(self, mock_env: None) -> None:
        """Existing callers keep recording an acceptance, not a disposition."""
        route = respx.post(
            "https://test.api.mipiti.io/api/models/tm-1/risk-acceptances"
        ).mock(return_value=httpx.Response(200, json={"id": "RA-1"}))
        client = MipitiClient()
        await client.create_risk_acceptance(
            "tm-1", control_objective_id="CO1", owner="o",
            justification="j", review_by="2027-01-01T00:00:00Z",
        )
        import json as _json
        body = _json.loads(route.calls[0].request.content)
        assert body["kind"] == "risk_accepted"

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_appends_the_kind_filter(self, mock_env: None) -> None:
        route = respx.get(
            "https://test.api.mipiti.io/api/models/tm-1/risk-acceptances",
            params={"kind": "not_applicable"},
        ).mock(return_value=httpx.Response(200, json=[]))
        client = MipitiClient()
        await client.list_co_dispositions("tm-1", kind="not_applicable")
        assert route.called

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_omits_the_filter_when_unset(self, mock_env: None) -> None:
        route = respx.get(
            "https://test.api.mipiti.io/api/models/tm-1/risk-acceptances"
        ).mock(return_value=httpx.Response(200, json=[]))
        client = MipitiClient()
        await client.list_co_dispositions("tm-1")
        assert route.called
        assert "kind=" not in str(route.calls[0].request.url)

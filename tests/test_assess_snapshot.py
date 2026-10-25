"""A paged assessment read passes back the snapshot its first page named, so
every page comes from one evaluation, and a snapshot not found is an answer."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import assess_model


ASSESS_URL = "https://test.api.mipiti.io/api/models/tm-1/assess"

_PAGE = {
    "model_id": "tm-1", "mitigated": 3, "at_risk": 2, "unassessed": 0,
    "evaluated_at": "2026-10-25T10:00:00Z",
    "assessments": [{"co_id": "CO3", "risk": "at_risk"}],
    "snapshot": "snap-1", "snapshot_expires_at": "2026-10-25T10:10:00Z",
}


@pytest.mark.asyncio
@respx.mock
async def test_a_read_without_a_snapshot_sends_none(mock_env: None) -> None:
    route = respx.post(ASSESS_URL).mock(return_value=httpx.Response(200, json=_PAGE))
    out = await MipitiClient().assess_model("tm-1", offset=0, limit=1)
    assert "snapshot" not in route.calls.last.request.url.params
    assert route.calls.last.request.url.params["limit"] == "1"
    assert out.model_dump()["snapshot"] == "snap-1"


@pytest.mark.asyncio
@respx.mock
async def test_a_later_page_names_the_snapshot(mock_env: None) -> None:
    route = respx.post(ASSESS_URL).mock(return_value=httpx.Response(200, json=_PAGE))
    out = await MipitiClient().assess_model("tm-1", offset=1, limit=1, snapshot="snap-1")
    params = route.calls.last.request.url.params
    assert params["snapshot"] == "snap-1"
    assert params["offset"] == "1" and params["limit"] == "1"
    assert out.model_dump()["evaluated_at"] == "2026-10-25T10:00:00Z"


@pytest.mark.asyncio
@respx.mock
async def test_a_snapshot_not_found_comes_back_as_data(mock_env: None) -> None:
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(
        410, json={"detail": {"code": "snapshot_not_found", "message": "read again"}}))
    out = (await MipitiClient().assess_model(
        "tm-1", offset=1, limit=1, snapshot="snap-1")).model_dump()
    assert out["http_status"] == 410
    assert out["code"] == "snapshot_not_found" and out["message"] == "read again"


@pytest.mark.asyncio
@respx.mock
async def test_other_failures_raise(mock_env: None) -> None:
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(
        404, json={"detail": "Threat model not found."}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().assess_model("tm-1", snapshot="snap-1")


@pytest.mark.asyncio
async def test_the_tool_passes_the_snapshot_through() -> None:
    client = AsyncMock()
    client.assess_model = AsyncMock(return_value=_PAGE)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await assess_model(server_version="0", model_id="tm-1", offset=1,
                                 limit=1, snapshot=" snap-1 ")
    client.assess_model.assert_awaited_once_with(
        "tm-1", summary_only=False, status="", offset=1, limit=1, snapshot="snap-1")
    assert out["snapshot"] == "snap-1"


@pytest.mark.asyncio
async def test_the_tool_without_a_snapshot_evaluates_now() -> None:
    client = AsyncMock()
    client.assess_model = AsyncMock(return_value=_PAGE)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await assess_model(server_version="0", model_id="tm-1")
    client.assess_model.assert_awaited_once_with(
        "tm-1", summary_only=False, status="", offset=0, limit=0, snapshot="")

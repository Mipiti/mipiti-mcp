"""The client asks for a strengthening estimate before starting one, returns
its refusals as data, and carries an accepted assumption's expiry."""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient


STRENGTHEN_URL = "https://test.api.mipiti.io/api/models/tm-1/controls/strengthen"


@pytest.mark.asyncio
@respx.mock
async def test_strengthen_estimate(mock_env: None) -> None:
    route = respx.post(STRENGTHEN_URL).mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "confirmed": False, "scope": ["CO1"],
                   "estimate": {"credits": 5.0}}))
    out = await MipitiClient().strengthen_controls("tm-1")
    assert out["started"] is False and out["scope"] == ["CO1"]
    assert json.loads(route.calls[0].request.content) == {"confirm_estimate": False}


@pytest.mark.asyncio
@respx.mock
async def test_strengthen_confirmed_sends_scope(mock_env: None) -> None:
    route = respx.post(STRENGTHEN_URL).mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "confirmed": True, "status": "queued"}))
    out = await MipitiClient().strengthen_controls(
        "tm-1", co_ids=["CO1", "CO2"], confirm_estimate=True)
    assert out["started"] is True and out["status"] == "queued"
    assert json.loads(route.calls[0].request.content) == {
        "confirm_estimate": True, "co_ids": ["CO1", "CO2"]}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(409, "generation_active"),
                                         (402, "insufficient_credits")])
async def test_strengthen_refusals_come_back_as_data(mock_env: None, status: int,
                                                     code: str) -> None:
    respx.post(STRENGTHEN_URL).mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m"}}))
    out = await MipitiClient().strengthen_controls("tm-1", confirm_estimate=True)
    assert out["started"] is False and out["http_status"] == status
    assert out["code"] == code


@pytest.mark.asyncio
@respx.mock
async def test_strengthen_other_failures_raise(mock_env: None) -> None:
    respx.post(STRENGTHEN_URL).mock(return_value=httpx.Response(500, json={"detail": "x"}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().strengthen_controls("tm-1")


DECIDE_URL = "https://test.api.mipiti.io/api/models/tm-1/proposals/P-1/decide"


@pytest.mark.asyncio
@respx.mock
async def test_decide_sends_expiry_only_when_given(mock_env: None) -> None:
    route = respx.post(DECIDE_URL).mock(return_value=httpx.Response(
        200, json={"proposal": {"id": "P-1"}, "effect": {}}))
    client = MipitiClient()
    await client.decide_proposal("tm-1", "P-1", "accept",
                                 expires_at="2027-03-29T00:00:00Z")
    assert json.loads(route.calls.last.request.content) == {
        "decision": "accept", "note": "", "expires_at": "2027-03-29T00:00:00Z"}
    await client.decide_proposal("tm-1", "P-1", "reject", note="no")
    assert json.loads(route.calls.last.request.content) == {
        "decision": "reject", "note": "no"}

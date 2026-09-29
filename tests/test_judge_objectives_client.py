"""The client asks for a judging estimate before queueing any judgement, and
returns its refusals as data."""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient


JUDGE_URL = "https://test.api.mipiti.io/api/models/tm-1/control-objectives/judge"


@pytest.mark.asyncio
@respx.mock
async def test_judge_estimate(mock_env: None) -> None:
    route = respx.post(JUDGE_URL).mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "confirmed": False, "queued": 0,
                   "scope": ["CO1"], "ungrouped": ["CO4"],
                   "estimate": {"credits": 3.0, "objectives": 1}}))
    out = await MipitiClient().judge_objectives("tm-1")
    assert out["confirmed"] is False and out["queued"] == 0
    assert out["scope"] == ["CO1"] and out["ungrouped"] == ["CO4"]
    assert json.loads(route.calls[0].request.content) == {"confirm_estimate": False}


@pytest.mark.asyncio
@respx.mock
async def test_judge_confirmed_sends_scope(mock_env: None) -> None:
    route = respx.post(JUDGE_URL).mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "confirmed": True, "queued": 2,
                   "status_detail": {"status": "complete"}}))
    out = await MipitiClient().judge_objectives(
        "tm-1", co_ids=["CO1", "CO2"], confirm_estimate=True)
    assert out["confirmed"] is True and out["queued"] == 2
    assert json.loads(route.calls[0].request.content) == {
        "confirm_estimate": True, "co_ids": ["CO1", "CO2"]}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(409, "control_generation_in_progress"),
                                         (402, "insufficient_credits"),
                                         (402, "quota_exceeded")])
async def test_judge_refusals_come_back_as_data(mock_env: None, status: int,
                                                code: str) -> None:
    respx.post(JUDGE_URL).mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m",
                                 "estimated_credits": 3.0}}))
    out = await MipitiClient().judge_objectives("tm-1", confirm_estimate=True)
    assert out["confirmed"] is False and out["queued"] == 0
    assert out["http_status"] == status and out["code"] == code


@pytest.mark.asyncio
@respx.mock
async def test_judge_unavailable_string_detail_is_carried_as_message(
    mock_env: None,
) -> None:
    respx.post(JUDGE_URL).mock(return_value=httpx.Response(
        503, json={"detail": "Judging is not enabled."}))
    out = await MipitiClient().judge_objectives("tm-1")
    assert out == {"confirmed": False, "queued": 0, "http_status": 503,
                   "message": "Judging is not enabled."}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status", [400, 500])
async def test_judge_other_failures_raise(mock_env: None, status: int) -> None:
    """An unknown objective (400) is a caller error, not an answer to relay."""
    respx.post(JUDGE_URL).mock(return_value=httpx.Response(
        status, json={"detail": "x"}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().judge_objectives("tm-1", co_ids=["CO99"])

"""The client starts a proposed control build only with the values a review
read, discards a held one, reads and undoes control-set revisions, reverts a
version, and asks for the judgement of imported controls -- each refusal
returned as data, every other failure raised."""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient


BASE = "https://test.api.mipiti.io/api/models/tm-1"


@pytest.mark.asyncio
@respx.mock
async def test_start_without_confirmation_sends_no_pin(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/build").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "started": False,
                   "proposal": {"model_version": 4, "set_revision": 7}}))
    out = await MipitiClient().start_control_build("tm-1")
    assert out["started"] is False and out["proposal"]["set_revision"] == 7
    assert json.loads(route.calls[0].request.content) == {"confirm_estimate": False}


@pytest.mark.asyncio
@respx.mock
async def test_start_sends_the_reviewed_values(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/build").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "started": True, "job_id": "j-1",
                   "status": "queued"}))
    out = await MipitiClient().start_control_build(
        "tm-1", model_version=4, set_revision=0, confirm_estimate=True)
    assert out["started"] is True and out["job_id"] == "j-1"
    assert json.loads(route.calls[0].request.content) == {
        "confirm_estimate": True, "model_version": 4, "set_revision": 0}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(409, "review_stale"),
                                         (409, "generation_active"),
                                         (404, "no_proposal"),
                                         (402, "insufficient_credits")])
async def test_start_refusals_come_back_as_data(mock_env: None, status: int,
                                                code: str) -> None:
    respx.post(f"{BASE}/controls/build").mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m"}}))
    out = await MipitiClient().start_control_build(
        "tm-1", model_version=4, set_revision=7, confirm_estimate=True)
    assert out == {"started": False, "http_status": status, "code": code,
                   "message": "m"}


@pytest.mark.asyncio
@respx.mock
async def test_start_other_failures_raise(mock_env: None) -> None:
    respx.post(f"{BASE}/controls/build").mock(
        return_value=httpx.Response(500, json={"detail": "x"}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().start_control_build("tm-1")


@pytest.mark.asyncio
@respx.mock
async def test_discard_and_its_refusal(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/discard")
    route.mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "status": "discarded", "proposal": None}))
    out = await MipitiClient().discard_control_build("tm-1")
    assert out["discarded"] is True and out["status"] == "discarded"
    route.mock(return_value=httpx.Response(
        409, json={"detail": {"code": "pause_first", "status": "generating"}}))
    out = await MipitiClient().discard_control_build("tm-1")
    assert out == {"discarded": False, "http_status": 409,
                   "code": "pause_first", "status": "generating"}


@pytest.mark.asyncio
@respx.mock
async def test_revisions_send_a_version_only_when_given(mock_env: None) -> None:
    route = respx.get(f"{BASE}/controls/revisions").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "revisions": []}))
    client = MipitiClient()
    await client.list_control_revisions("tm-1")
    assert "version" not in route.calls.last.request.url.params
    await client.list_control_revisions("tm-1", version=3)
    assert route.calls.last.request.url.params["version"] == "3"


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("method,path", [
    ("undo_control_change", "controls/undo"),
    ("revert_model_version", "revert"),
])
async def test_undo_and_revert_answers_and_refusals(mock_env: None, method: str,
                                                    path: str) -> None:
    route = respx.post(f"{BASE}/{path}")
    route.mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "model_version": 5}))
    out = await getattr(MipitiClient(), method)("tm-1")
    assert out["applied"] is True and out["model_version"] == 5
    route.mock(return_value=httpx.Response(
        409, json={"detail": {"code": "generation_active", "message": "m"}}))
    out = await getattr(MipitiClient(), method)("tm-1")
    assert out == {"applied": False, "http_status": 409,
                   "code": "generation_active", "message": "m"}
    route.mock(return_value=httpx.Response(404, json={"detail": "x"}))
    with pytest.raises(httpx.HTTPStatusError):
        await getattr(MipitiClient(), method)("tm-1")


@pytest.mark.asyncio
@respx.mock
async def test_judge_imported_estimate_confirm_and_refusal(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/imported/judge")
    route.mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "awaiting_judgement": ["CTRL-09"],
                   "confirmed": False, "queued": 0}))
    client = MipitiClient()
    out = await client.judge_imported_controls("tm-1")
    assert out["awaiting_judgement"] == ["CTRL-09"]
    assert json.loads(route.calls.last.request.content) == {"confirm_estimate": False}
    await client.judge_imported_controls("tm-1", confirm_estimate=True)
    assert json.loads(route.calls.last.request.content) == {"confirm_estimate": True}
    route.mock(return_value=httpx.Response(
        402, json={"detail": {"code": "insufficient_credits", "message": "m"}}))
    out = await client.judge_imported_controls("tm-1", confirm_estimate=True)
    assert out == {"confirmed": False, "queued": 0, "http_status": 402,
                   "code": "insufficient_credits", "message": "m"}


@pytest.mark.asyncio
@respx.mock
async def test_strengthen_sends_the_pin_only_when_given(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/strengthen").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "confirmed": True, "status": "queued"}))
    await MipitiClient().strengthen_controls(
        "tm-1", confirm_estimate=True, model_version=4, set_revision=0)
    assert json.loads(route.calls[0].request.content) == {
        "confirm_estimate": True, "model_version": 4, "set_revision": 0}


@pytest.mark.asyncio
@respx.mock
async def test_regenerate_returns_the_proposal(mock_env: None) -> None:
    respx.post(f"{BASE}/controls/regenerate").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "status": "proposed",
                   "proposal": {"mode": "fresh"}}))
    out = await MipitiClient().regenerate_controls("tm-1")
    assert out["status"] == "proposed" and out["proposal"]["mode"] == "fresh"

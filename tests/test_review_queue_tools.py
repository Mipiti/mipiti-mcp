"""The review queue's tools: decisions taken together, the quality check's
corrections applied as a polled job, an assumption naming the entities it is
about, the behavioural elements never matched matched on request, a link's
compact answer, and the list's count of flagged entities."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient

API = "https://test.api.mipiti.io/api"
MODEL = f"{API}/models/tm-1"


def _ctx() -> AsyncMock:
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _body(route) -> dict:
    return json.loads(route.calls.last.request.content)


@pytest.mark.asyncio
@respx.mock
async def test_decisions_are_taken_together_in_one_call(mock_env: None) -> None:
    answer = {"model_id": "tm-1", "decided": 1, "refused": 1, "results": [
        {"proposal_id": "p1", "ok": True},
        {"proposal_id": "p2", "ok": False, "status_code": 403,
         "detail": {"escalation_id": "e2"}}]}
    route = respx.post(f"{MODEL}/proposals/decide").mock(
        return_value=httpx.Response(200, json=answer))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        out = await server.decide_proposals(
            server_version="0", model_id="tm-1", note="read both",
            decisions=json.dumps([{"proposal_id": "p1", "decision": "accept"},
                                  {"proposal_id": "p2", "decision": "reject"}]))
    assert out == answer
    assert _body(route) == {"decisions": [{"proposal_id": "p1", "decision": "accept"},
                                          {"proposal_id": "p2", "decision": "reject"}],
                            "note": "read both"}


@pytest.mark.asyncio
async def test_a_decision_that_is_neither_accept_nor_reject_is_refused_before_any_call(
        mock_env: None) -> None:
    with pytest.raises(ToolError):
        await server.decide_proposals(server_version="0", model_id="tm-1",
                                      decisions=json.dumps([{"proposal_id": "p1",
                                                             "decision": "maybe"}]))
    with pytest.raises(ToolError):
        await server.decide_proposals(server_version="0", model_id="tm-1",
                                      decisions=json.dumps([]))


@pytest.mark.asyncio
@respx.mock
async def test_corrections_are_applied_as_a_job_polled_to_its_answer(mock_env: None) -> None:
    started = respx.post(f"{MODEL}/entities/apply-proposals-job").mock(
        return_value=httpx.Response(200, json={"job_id": "j1"}))
    respx.get(f"{API}/operations/j1").mock(side_effect=[
        httpx.Response(200, json={"status": "running", "progress": "Checking A-01 (1 of 1)",
                                  "poll_after_seconds": 0}),
        httpx.Response(200, json={"status": "completed", "result": {
            "results": [{"entity_id": "A-01", "outcome": "applied",
                         "correction_kind": "widening"}], "version": 3}}),
    ])
    sync = respx.post(f"{MODEL}/entities/apply-proposals")
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        out = await server.apply_entity_proposals(
            server_version="0", model_id="tm-1", ctx=_ctx(),
            proposals=json.dumps([{"entity_id": "A-01", "input_hash": "k",
                                   "proposal_hash": "p"}]))
    assert out["results"][0]["outcome"] == "applied"
    assert _body(started) == {"proposals": [{"entity_id": "A-01", "input_hash": "k",
                                             "proposal_hash": "p"}]}
    assert not sync.called


@pytest.mark.asyncio
@respx.mock
async def test_an_assumption_names_the_entities_it_is_about(mock_env: None) -> None:
    answer = {"model": {"id": "tm-1", "version": 2, "title": "t"},
              "entities": {"assumptions": [{"id": "AS-1"}]}}
    added = respx.post(f"{MODEL}/assumptions").mock(return_value=httpx.Response(200, json=answer))
    edited = respx.put(f"{MODEL}/assumptions/AS-1").mock(
        return_value=httpx.Response(200, json=answer))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        await server.add_assumption(server_version="0", model_id="tm-1",
                                    description="Assumed until the owner says otherwise.",
                                    entity_ids="A-01, T-02")
        await server.edit_assumption(server_version="0", model_id="tm-1",
                                     assumption_id="AS-1", entity_ids="")
        await server.edit_assumption(server_version="0", model_id="tm-1",
                                     assumption_id="AS-1", description="d")
    assert _body(added)["entity_ids"] == ["A-01", "T-02"]
    first, second = (json.loads(c.request.content) for c in edited.calls)
    # "" names none; omitted leaves them as they are.
    assert first == {"entity_ids": []}
    assert "entity_ids" not in second


@pytest.mark.asyncio
@respx.mock
async def test_matching_estimates_first_and_runs_only_when_confirmed(mock_env: None) -> None:
    estimate = {"model_id": "tm-1", "nodes": ["E-9"], "confirmed": False,
                "estimate": {"credits": 3, "calls": 1}, "message": "Confirm with ..."}
    route = respx.post(f"{MODEL}/behavioural-model/links/match").mock(side_effect=[
        httpx.Response(200, json=estimate),
        httpx.Response(200, json={"job_id": "j2"}),
    ])
    respx.get(f"{API}/operations/j2").mock(return_value=httpx.Response(
        200, json={"status": "completed", "result": {"proposed": ["E-9"]}}))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        first = await server.match_behavioural_links(server_version="0", model_id="tm-1",
                                                     ctx=_ctx())
        second = await server.match_behavioural_links(server_version="0", model_id="tm-1",
                                                      ctx=_ctx(), confirm_estimate=True)
    assert first == estimate
    assert second == {"proposed": ["E-9"]}
    assert [json.loads(c.request.content) for c in route.calls] == [
        {"confirm_estimate": False}, {"confirm_estimate": True}]


@pytest.mark.asyncio
@respx.mock
async def test_the_list_carries_the_count_of_flagged_entities(mock_env: None) -> None:
    respx.get(f"{API}/models").mock(return_value=httpx.Response(200, json=[
        {"id": "tm-1", "title": "One", "version": 2, "created_at": "c",
         "entities_need_review": 4},
        {"id": "tm-2", "title": "Two", "version": 1, "created_at": "c"}]))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        out = await server.list_threat_models(server_version="0")
    by_id = {i["id"]: i for i in out["items"]}
    assert by_id["tm-1"]["entities_flagged"] == 4
    # Unreadable on the server: absent, never read as none flagged.
    assert "entities_flagged" not in by_id["tm-2"]

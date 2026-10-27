"""The quality check's repairs: applying its corrections and answering its
question, through the tools and the client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient

BASE = "https://test.api.mipiti.io/api/models/tm-1/entities"


def _client(**methods: object) -> AsyncMock:
    client = AsyncMock()
    for name, value in methods.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


def _body(route) -> dict:
    return json.loads(route.calls.last.request.content)


@pytest.mark.asyncio
@respx.mock
async def test_the_client_reaches_both_routes(mock_env: None) -> None:
    client = MipitiClient()
    apply = respx.post(BASE + "/apply-proposals").mock(return_value=httpx.Response(
        200, json={"results": [{"entity_id": "A-3", "outcome": "applied"}], "version": 4}))
    out = await client.apply_entity_proposals(
        "tm-1", [{"entity_id": "A-3", "input_hash": "h1"}])
    assert out["version"] == 4
    assert _body(apply) == {"proposals": [{"entity_id": "A-3", "input_hash": "h1"}]}
    answer = respx.post(BASE + "/T-4/answer").mock(return_value=httpx.Response(
        200, json={"entity_id": "T-4", "queued": 1}))
    await client.answer_entity_question("tm-1", "T-4", "Session tokens.", "h2")
    assert _body(answer) == {"text": "Session tokens.", "input_hash": "h2"}


@pytest.mark.asyncio
async def test_the_tools_forward_what_they_were_given_and_name_no_whole_model() -> None:
    model = {"id": "tm-1", "version": 4, "title": "T", "assets": [{"id": "A-3"}]}
    client = _client(
        apply_entity_proposals={"results": [{"entity_id": "A-3", "outcome": "applied"}],
                                "version": 4, "model": model},
        answer_entity_question={"entity_id": "T-4", "queued": 1})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        applied = await server.apply_entity_proposals(
            server_version="0", model_id="tm-1",
            proposals='[{"entity_id": " A-3 ", "input_hash": " h1 "}]')
        await server.answer_entity_question(
            server_version="0", model_id="tm-1", entity_id=" T-4 ",
            text=" Session tokens. ", input_hash=" h2 ")
    client.apply_entity_proposals.assert_awaited_once_with(
        "tm-1", [{"entity_id": "A-3", "input_hash": "h1"}])
    client.answer_entity_question.assert_awaited_once_with(
        "tm-1", "T-4", "Session tokens.", "h2")
    # The whole model is not handed back: its reference is.
    assert "assets" not in json.dumps(applied.get("model"))


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,kwargs", [
    ("apply_entity_proposals", {"proposals": "nope"}),
    ("apply_entity_proposals", {"proposals": "[]"}),
    ("apply_entity_proposals", {"proposals": '[{"entity_id": "A-3"}]'}),
    ("answer_entity_question", {"entity_id": " ", "text": "t", "input_hash": "h"}),
    ("answer_entity_question", {"entity_id": "A-3", "text": " ", "input_hash": "h"}),
    ("answer_entity_question", {"entity_id": "A-3", "text": "x" * 4001, "input_hash": "h"}),
    ("answer_entity_question", {"entity_id": "A-3", "text": "t", "input_hash": " "}),
])
async def test_an_act_the_api_would_refuse_is_refused_before_the_call(
        tool: str, kwargs: dict) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await getattr(server, tool)(server_version="0", model_id="tm-1", **kwargs)
    client.apply_entity_proposals.assert_not_awaited()
    client.answer_entity_question.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_stale_answer_is_reported_as_such() -> None:
    request = httpx.Request("POST", "http://x/answer")
    refusal = httpx.HTTPStatusError("stale", request=request, response=httpx.Response(
        409, json={"detail": {"code": "stale", "input_hash": "h9"}}, request=request))
    client = AsyncMock()
    client.answer_entity_question = AsyncMock(side_effect=refusal)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="409.*stale"):
            await server.answer_entity_question(
                server_version="0", model_id="tm-1", entity_id="A-3", text="t",
                input_hash="h1")


def test_the_tools_are_published_with_their_rules() -> None:
    import asyncio
    tools = {t.name: " ".join((t.description or "").split())
             for t in asyncio.run(server.mcp.list_tools())}
    for word in ("``applied``", "``rejected``", "``stale``", "``none``", "``unavailable``",
                 "never moves a position"):
        assert word in tools["apply_entity_proposals"], word
    for word in ("``not_flagged``", "``defect``", "``invalid``", "never guess",
                 "never weaken a true claim", "It decides nothing",
                 "creates no model version"):
        assert word in tools["answer_entity_question"], word
    assert "``quality``" in tools["get_entity"]
    instructions = server.build_instructions("pro", "user")
    for name in ("apply_entity_proposals", "answer_entity_question"):
        assert f"`{name}`" in instructions, name

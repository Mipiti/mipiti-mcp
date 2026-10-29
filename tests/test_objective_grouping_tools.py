"""The objective grouping tools: the read and the restructure reach their
route with the body the API takes, the restructure names the version read,
and the published text says to relay the groups before grouping."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient

ROUTE = "https://test.api.mipiti.io/api/models/tm-1/objectives/grouping"


@pytest.mark.asyncio
@respx.mock
async def test_the_read_gets_and_the_restructure_posts_the_version(mock_env: None) -> None:
    client = MipitiClient()
    read = respx.get(ROUTE).mock(return_value=httpx.Response(200, json={"grouped": False}))
    assert await client.get_objective_grouping("tm-1") == {"grouped": False}
    assert read.called
    write = respx.post(ROUTE).mock(return_value=httpx.Response(200, json={"changed": True}))
    await client.set_objective_grouping("tm-1", True, 7)
    assert json.loads(write.calls.last.request.content) == {"enabled": True, "model_version": 7}
    await client.set_objective_grouping("tm-1", False, 8)
    assert json.loads(write.calls.last.request.content) == {"enabled": False, "model_version": 8}


@pytest.mark.asyncio
async def test_the_tools_forward_their_arguments() -> None:
    client = AsyncMock()
    client.get_objective_grouping = AsyncMock(return_value={"groups": []})
    client.set_objective_grouping = AsyncMock(return_value={"changed": True, "moved": {}})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        assert await server.get_objective_grouping(server_version="0", model_id="tm-1") == {
            "groups": []}
        await server.set_objective_grouping(server_version="0", model_id="tm-1",
                                            enabled=True, model_version=7)
    client.get_objective_grouping.assert_awaited_once_with("tm-1")
    client.set_objective_grouping.assert_awaited_once_with("tm-1", True, 7)


def test_the_tools_are_published_with_their_rules() -> None:
    tools = {t.name: " ".join((t.description or "").split())
             for t in asyncio.run(server.mcp.list_tools())}
    for word in ("Read-only", "``model_version``", "``available``", "``objectives_after``"):
        assert word in tools["get_objective_grouping"], word
    for word in ("relay the groups", "``review_stale``", "``behavioural_off``",
                 "creates a model version", "``moved``"):
        assert word in tools["set_objective_grouping"], word

"""A factor re-evaluation takes a scope: the entities named, or only those
nobody rated, or both. The tool sends each only when given, and the client
puts them in the body the API reads."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import reevaluate_threat_model_factors

_JOB_URL = "https://test.api.mipiti.io/api/models/tm-001/factors/reevaluate-job"


def _client_with_job(result: dict) -> MagicMock:
    mock = MagicMock()
    mock.start_reevaluate_factors = AsyncMock(return_value={"job_id": "job-reeval"})
    mock.get_operation = AsyncMock(return_value={"status": "completed", "result": result})
    return mock


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_the_scope_reaches_the_client_only_when_given() -> None:
    mock = _client_with_job({"in_scope": 2})
    with patch.object(server, "_get_client", return_value=mock):
        result = await reevaluate_threat_model_factors(
            server_version="0", model_id="tm-001", ctx=_ctx(),
            entity_ids=" T-14, A-03 ,", unrated_only=True,
        )
    assert result == {"in_scope": 2}
    mock.start_reevaluate_factors.assert_awaited_once_with(
        "tm-001", change_reason=None, entity_ids=["T-14", "A-03"], unrated_only=True,
    )


@pytest.mark.asyncio
async def test_unrated_only_alone_sends_no_ids() -> None:
    mock = _client_with_job({})
    with patch.object(server, "_get_client", return_value=mock):
        await reevaluate_threat_model_factors(
            server_version="0", model_id="tm-001", ctx=_ctx(), unrated_only=True,
        )
    mock.start_reevaluate_factors.assert_awaited_once_with(
        "tm-001", change_reason=None, unrated_only=True,
    )


@pytest.mark.asyncio
async def test_no_scope_reevaluates_every_entity_as_before() -> None:
    mock = _client_with_job({})
    with patch.object(server, "_get_client", return_value=mock):
        await reevaluate_threat_model_factors(
            server_version="0", model_id="tm-001", ctx=_ctx(),
        )
    mock.start_reevaluate_factors.assert_awaited_once_with("tm-001", change_reason=None)


@pytest.mark.asyncio
@respx.mock
async def test_the_client_puts_the_scope_in_the_body(mock_env: None) -> None:
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"job_id": "job-reeval"})

    respx.post(_JOB_URL).mock(side_effect=_capture)
    client = MipitiClient()
    await client.start_reevaluate_factors(
        "tm-001", entity_ids=["T-14"], unrated_only=True,
    )
    assert captured["body"] == {"entity_ids": ["T-14"], "unrated_only": True}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_an_empty_list_names_no_entity(mock_env: None) -> None:
    """``entity_ids=[]`` is a scope naming none, which the API answers with no
    call; it is not the same as omitting the scope."""
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"job_id": "job-reeval"})

    respx.post(_JOB_URL).mock(side_effect=_capture)
    client = MipitiClient()
    await client.start_reevaluate_factors("tm-001", entity_ids=[])
    assert captured["body"] == {"entity_ids": []}
    await client.close()


@pytest.mark.asyncio
async def test_stale_only_reaches_the_client_and_the_body(mock_env: None) -> None:
    mock = _client_with_job({})
    with patch.object(server, "_get_client", return_value=mock):
        await reevaluate_threat_model_factors(
            server_version="0", model_id="tm-001", ctx=_ctx(), entity_ids="T-14",
            stale_only=True,
        )
    mock.start_reevaluate_factors.assert_awaited_once_with(
        "tm-001", change_reason=None, entity_ids=["T-14"], stale_only=True,
    )
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"job_id": "job-reeval"})

    with respx.mock:
        respx.post(_JOB_URL).mock(side_effect=_capture)
        client = MipitiClient()
        await client.start_reevaluate_factors("tm-001", entity_ids=["T-14"], stale_only=True)
        await client.close()
    assert captured["body"] == {"entity_ids": ["T-14"], "stale_only": True}


@pytest.mark.asyncio
async def test_the_tool_declares_the_scope_parameters() -> None:
    tool = await server.mcp.get_tool("reevaluate_threat_model_factors")
    params = tool.parameters["properties"]
    assert "entity_ids" in params and "unrated_only" in params and "stale_only" in params
    assert "entity_ids" not in tool.parameters.get("required", [])

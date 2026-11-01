"""An assumption can declare a taxonomy primitive, or one property it entails,
not applicable: the exit for a gap the build proposal reports as missing from
the inventory, such as Usage where every key can be read out."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient
from unittest.mock import patch

URL = "https://test.api.mipiti.io/api/models/tm-1/assumptions"
ANSWER = {"model": {"id": "tm-1", "version": 2, "title": "t"},
          "entities": {"assumptions": [{"id": "AS-1"}]}}


@pytest.mark.asyncio
@respx.mock
async def test_the_tool_sends_the_primitive_and_property_it_declares(mock_env: None) -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ANSWER))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        await server.add_assumption(
            server_version="0", model_id="tm-1",
            description="Every key answering encryption is held in configuration and can be read out.",
            assumption_type="non_applicability",
            taxonomy_primitive="cryptographic_operations", taxonomy_property="U")
    body = json.loads(route.calls.last.request.content)
    assert body["taxonomy_primitive"] == "cryptographic_operations"
    assert body["taxonomy_property"] == "U"
    assert body["assumption_type"] == "non_applicability"


@pytest.mark.asyncio
@respx.mock
async def test_an_assumption_naming_neither_sends_neither(mock_env: None) -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ANSWER))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        await server.add_assumption(server_version="0", model_id="tm-1",
                                    description="The customer restricts egress.")
    body = json.loads(route.calls.last.request.content)
    assert "taxonomy_primitive" not in body and "taxonomy_property" not in body

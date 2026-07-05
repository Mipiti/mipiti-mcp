"""Unit tests for the functional-conformance MCP tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mipiti_mcp.server import (
    add_functional_test,
    check_functional_gaps,
    generate_functional_objectives,
    get_capability,
    get_functional_coverage,
    get_functional_objective,
    get_functional_scan_prompt,
    import_functional_tests,
    list_capabilities,
    list_functional_objectives,
    submit_functional_tests,
)


def _client(**overrides: AsyncMock) -> AsyncMock:
    client = AsyncMock()
    defaults = {
        "generate_functional": {"model_id": "tm-1", "capabilities": [], "functional_objectives": []},
        "list_capabilities": {"model_id": "tm-1", "capabilities": [{"id": "CAP-1", "name": "Checkout"}]},
        "get_capability": {"id": "CAP-1", "name": "Checkout"},
        "list_functional_objectives": {"model_id": "tm-1", "functional_objectives": [{"id": "FO-1"}]},
        "get_functional_objective": {"id": "FO-1", "condition": "nominal"},
        "get_functional_coverage": {"model_id": "tm-1", "summary": {"percent_verified": 50}},
        "get_functional_gaps": {"model_id": "tm-1", "gaps": [], "summary": {}},
        "get_functional_scan_prompt": {"model_id": "tm-1", "instructions": [], "missing_objectives": []},
        "add_functional_test": {"id": "FT-1", "description": "t"},
        "import_functional_tests": {"model_id": "tm-1", "imported": [], "rejected_mappings": []},
        "submit_functional_tests": {"functional_test_id": "FT-1", "assertions": []},
    }
    defaults.update(overrides)
    for name, value in defaults.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


def _patch(client):
    return patch("mipiti_mcp.server._get_client", return_value=client)


@pytest.mark.asyncio
async def test_generate_forwards_refresh():
    c = _client()
    with _patch(c):
        await generate_functional_objectives(server_version="0", model_id="tm-1", refresh=True)
    c.generate_functional.assert_awaited_once_with("tm-1", True)


@pytest.mark.asyncio
async def test_read_tools_passthrough():
    c = _client()
    with _patch(c):
        assert (await list_capabilities(server_version="0", model_id="tm-1"))["capabilities"][0]["id"] == "CAP-1"
        assert (await get_capability(server_version="0", model_id="tm-1", capability_id="CAP-1"))["id"] == "CAP-1"
        assert (await list_functional_objectives(server_version="0", model_id="tm-1"))["functional_objectives"][0]["id"] == "FO-1"
        assert (await get_functional_objective(server_version="0", model_id="tm-1", functional_objective_id="FO-1"))["id"] == "FO-1"
        assert (await get_functional_coverage(server_version="0", model_id="tm-1"))["summary"]["percent_verified"] == 50
        assert "gaps" in await check_functional_gaps(server_version="0", model_id="tm-1")
        assert "instructions" in await get_functional_scan_prompt(server_version="0", model_id="tm-1")


@pytest.mark.asyncio
async def test_add_functional_test_parses_comma_lists():
    c = _client()
    with _patch(c):
        await add_functional_test(
            server_version="0", model_id="tm-1", description="t",
            functional_objective_ids="FO-1, FO-2", component_ids="CMP1",
        )
    c.add_functional_test.assert_awaited_once_with(
        "tm-1", "t", ["FO-1", "FO-2"], "not_implemented", ["CMP1"],
    )


@pytest.mark.asyncio
async def test_add_functional_test_requires_objective():
    with _patch(_client()):
        with pytest.raises(ToolError):
            await add_functional_test(
                server_version="0", model_id="tm-1", description="t",
                functional_objective_ids="  ",
            )


@pytest.mark.asyncio
async def test_submit_functional_tests_parses_json():
    c = _client()
    payload = [{"type": "test_passes", "params": {"pattern": "x"}, "description": "d", "repo": "o/r"}]
    with _patch(c):
        await submit_functional_tests(
            server_version="0", model_id="tm-1", functional_test_id="FT-1",
            assertions_json=json.dumps(payload),
        )
    c.submit_functional_tests.assert_awaited_once_with("tm-1", "FT-1", payload)


@pytest.mark.asyncio
async def test_submit_functional_tests_rejects_bad_json():
    with _patch(_client()):
        with pytest.raises(ToolError):
            await submit_functional_tests(
                server_version="0", model_id="tm-1", functional_test_id="FT-1",
                assertions_json="{not json",
            )
        with pytest.raises(ToolError):
            await submit_functional_tests(
                server_version="0", model_id="tm-1", functional_test_id="FT-1",
                assertions_json='{"not": "a list"}',
            )


@pytest.mark.asyncio
async def test_import_functional_tests_parses_and_forwards():
    c = _client()
    with _patch(c):
        await import_functional_tests(
            server_version="0", model_id="tm-1",
            tests_json='[{"test_name": "test_login", "file_path": "t/test_login.py", '
            '"functional_objective_ids": ["FO-1"]}]',
        )
    c.import_functional_tests.assert_awaited_once_with(
        "tm-1",
        [{"test_name": "test_login", "file_path": "t/test_login.py",
          "functional_objective_ids": ["FO-1"]}],
    )


@pytest.mark.asyncio
async def test_import_functional_tests_rejects_bad_json():
    with _patch(_client()):
        with pytest.raises(ToolError):
            await import_functional_tests(
                server_version="0", model_id="tm-1", tests_json="not json",
            )


@pytest.mark.asyncio
async def test_import_functional_tests_rejects_empty_array():
    with _patch(_client()):
        with pytest.raises(ToolError):
            await import_functional_tests(
                server_version="0", model_id="tm-1", tests_json="[]",
            )

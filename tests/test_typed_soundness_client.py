"""HTTP contract of the binding and inventory-completeness client calls."""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient

_BASE = "https://test.api.mipiti.io"


@pytest.mark.asyncio
@respx.mock
async def test_bind_assertion_puts_the_declaration(mock_env: None) -> None:
    route = respx.put(f"{_BASE}/api/models/tm-001/controls/CTRL-01/assertions/a1/covers").mock(
        return_value=httpx.Response(200, json={"assertion": {"id": "a1", "covers": ["CO-3"]}}),
    )
    client = MipitiClient()
    result = await client.bind_assertion("tm-001", "CTRL-01", "a1", ["CO-3"])
    assert route.called
    assert json.loads(route.calls.last.request.content) == {"covers": ["CO-3"]}
    assert result["assertion"]["covers"] == ["CO-3"]
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_inventory_completeness_reads_the_record(mock_env: None) -> None:
    route = respx.get(f"{_BASE}/api/models/tm-001/inventory-completeness").mock(
        return_value=httpx.Response(200, json={"model_id": "tm-001", "tier": "inferred"}),
    )
    client = MipitiClient()
    result = await client.get_inventory_completeness("tm-001")
    assert route.called and route.calls.last.request.method == "GET"
    assert result["tier"] == "inferred"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_submit_attestation_carries_covers_only_when_given(mock_env: None) -> None:
    route = respx.post(f"{_BASE}/api/models/tm-001/assumptions/AS1/attest").mock(
        return_value=httpx.Response(200, json={"id": "att-1"}),
    )
    client = MipitiClient()
    await client.submit_attestation("tm-001", "AS1", attested_by="a", covers=["CO-2"])
    assert json.loads(route.calls.last.request.content) == {"attested_by": "a", "covers": ["CO-2"]}
    await client.submit_attestation("tm-001", "AS1", attested_by="a")
    assert "covers" not in json.loads(route.calls.last.request.content)
    await client.close()

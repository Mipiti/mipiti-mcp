"""HTTP contract of the attestation call.

An attestation body carries only the fields the attestation record has. A
declaration of which clause the evidence stands for is not one of them: it is
declared on the assertion, where the record keeps it.
"""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient

_BASE = "https://test.api.mipiti.io"


@pytest.mark.asyncio
@respx.mock
async def test_submit_attestation_sends_only_attestation_fields(mock_env: None) -> None:
    route = respx.post(f"{_BASE}/api/models/tm-001/assumptions/AS1/attest").mock(
        return_value=httpx.Response(200, json={"id": "att-1"}),
    )
    client = MipitiClient()
    await client.submit_attestation(
        "tm-001", "AS1", attested_by="a", statement="holds",
        expires_at="2027-01-01T00:00:00Z", evidence_url="https://example.test/e",
    )
    assert json.loads(route.calls.last.request.content) == {
        "attested_by": "a",
        "statement": "holds",
        "expires_at": "2027-01-01T00:00:00Z",
        "evidence_url": "https://example.test/e",
    }
    await client.close()


def test_the_client_takes_no_binding_declaration_on_an_attestation() -> None:
    import inspect

    assert "covers" not in inspect.signature(MipitiClient.submit_attestation).parameters

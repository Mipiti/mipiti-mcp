"""Unit tests for MipitiClient."""

import json

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient

from .conftest import SAMPLE_CONTROLS, SAMPLE_MODELS_LIST, SAMPLE_THREAT_MODEL


# ------------------------------------------------------------------
# Constructor tests
# ------------------------------------------------------------------


def test_missing_api_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIPITI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="MIPITI_API_KEY is required"):
        MipitiClient(api_key="", api_url="https://test.api")


def test_explicit_api_key() -> None:
    client = MipitiClient(api_key="my-key", api_url="https://test.api")
    assert client.api_key == "my-key"
    assert client.api_url == "https://test.api"


def test_env_var_config(mock_env: None) -> None:
    client = MipitiClient()
    assert client.api_key == "test-key-123"
    assert client.api_url == "https://test.api.mipiti.io"


def test_trailing_slash_stripped() -> None:
    client = MipitiClient(api_key="k", api_url="https://api.example.com/")
    assert client.api_url == "https://api.example.com"


def test_auth_headers_bypass_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIPITI_API_KEY", raising=False)
    client = MipitiClient(
        api_url="https://test.api",
        auth_headers={"Authorization": "Bearer tok"},
    )
    assert client.api_key == ""
    http = client._get_client()
    assert http.headers["Authorization"] == "Bearer tok"


# ------------------------------------------------------------------
# REST endpoint tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_models(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models").mock(
        return_value=httpx.Response(200, json=SAMPLE_MODELS_LIST)
    )
    client = MipitiClient()
    models = await client.list_models()
    assert len(models) == 2
    assert models[0].id == "tm-001"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_model_latest(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models/tm-001").mock(
        return_value=httpx.Response(200, json=SAMPLE_THREAT_MODEL)
    )
    client = MipitiClient()
    model = await client.get_model("tm-001")
    assert model.id == "tm-001"
    assert len(model.assets) == 2
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_model_specific_version(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models/tm-001/versions/2").mock(
        return_value=httpx.Response(200, json=SAMPLE_THREAT_MODEL)
    )
    client = MipitiClient()
    model = await client.get_model("tm-001", version=2)
    assert model.id == "tm-001"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_rename_model(mock_env: None) -> None:
    respx.patch("https://test.api.mipiti.io/api/models/tm-001").mock(
        return_value=httpx.Response(200, json={"id": "tm-001", "title": "New Name"})
    )
    client = MipitiClient()
    result = await client.rename_model("tm-001", "New Name")
    assert result.title == "New Name"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_delete_model(mock_env: None) -> None:
    respx.delete("https://test.api.mipiti.io/api/models/tm-001").mock(
        return_value=httpx.Response(204)
    )
    client = MipitiClient()
    result = await client.delete_model("tm-001")
    assert result is None
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_controls(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models/tm-001/controls").mock(
        return_value=httpx.Response(200, json=SAMPLE_CONTROLS)
    )
    client = MipitiClient()
    data = await client.get_controls("tm-001")
    assert len(data.controls) == 2
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_update_control_status(mock_env: None) -> None:
    respx.patch("https://test.api.mipiti.io/api/controls/CTRL-01").mock(
        return_value=httpx.Response(200, json={"id": "CTRL-01", "status": "implemented"})
    )
    client = MipitiClient()
    result = await client.update_control_status("tm-001", "CTRL-01", "implemented")
    assert result.id == "CTRL-01"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_add_evidence(mock_env: None) -> None:
    respx.post("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/evidence").mock(
        return_value=httpx.Response(201, json={"control_id": "CTRL-01", "evidence_count": 2})
    )
    client = MipitiClient()
    result = await client.add_evidence("tm-001", "CTRL-01", "code", "bcrypt usage", "auth.py:42")
    assert result.evidence_count == 2
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_remove_evidence(mock_env: None) -> None:
    respx.delete("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/evidence/0").mock(
        return_value=httpx.Response(200, json={"control_id": "CTRL-01", "evidence_count": 0})
    )
    client = MipitiClient()
    result = await client.remove_evidence("tm-001", "CTRL-01", 0)
    assert result.evidence_count == 0
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_add_asset(mock_env: None) -> None:
    respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(
        return_value=httpx.Response(200, json={"id": "A3", "name": "Session Store"})
    )
    client = MipitiClient()
    result = await client.add_asset("tm-001", name="Session Store")
    assert result.id == "A3"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_submit_assertions(mock_env: None) -> None:
    respx.post("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/assertions").mock(
        return_value=httpx.Response(200, json={"count": 1})
    )
    client = MipitiClient()
    result = await client.submit_assertions("tm-001", "CTRL-01", [{"type": "file_exists"}])
    assert result.count == 1
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_workspaces(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/workspaces").mock(
        return_value=httpx.Response(200, json={"workspaces": [{"id": "ws-1"}]})
    )
    client = MipitiClient()
    result = await client.list_workspaces()
    assert len(result) == 1
    assert result[0].id == "ws-1"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_export_csv(mock_env: None) -> None:
    csv_content = b"AssetID,Name\nA1,OAuth Tokens\n"
    respx.get("https://test.api.mipiti.io/api/models/tm-001/export").mock(
        return_value=httpx.Response(200, content=csv_content)
    )
    client = MipitiClient()
    result = await client.export_model("tm-001", "csv")
    assert result == csv_content
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_http_401_raises(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models").mock(
        return_value=httpx.Response(401, json={"detail": "Invalid API key"})
    )
    client = MipitiClient()
    with pytest.raises(httpx.HTTPStatusError):
        await client.list_models()
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_http_404_raises(mock_env: None) -> None:
    respx.get("https://test.api.mipiti.io/api/models/missing").mock(
        return_value=httpx.Response(404, json={"detail": "Not found"})
    )
    client = MipitiClient()
    with pytest.raises(httpx.HTTPStatusError):
        await client.get_model("missing")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_delete_returns_none_on_204(mock_env: None) -> None:
    respx.delete(
        "https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/assertions/a1"
    ).mock(return_value=httpx.Response(204))
    client = MipitiClient()
    result = await client.delete_assertion("tm-001", "CTRL-01", "a1")
    assert result is None
    await client.close()


# ------------------------------------------------------------------
# SSE stream tests
# ------------------------------------------------------------------


def _build_sse_bytes(events: list[tuple[str, dict]]) -> bytes:
    """Build raw SSE byte payload from (event_type, data_dict) tuples."""
    parts: list[str] = []
    for event_type, data in events:
        parts.append(f"event: {event_type}\ndata: {json.dumps(data)}\n\n")
    return "".join(parts).encode()


@pytest.mark.asyncio
@respx.mock
async def test_stream_generate(mock_env: None) -> None:
    sse_payload = _build_sse_bytes([
        ("intent", {"type": "intent", "intent": "generate", "session_id": "s1"}),
        ("step_start", {"type": "step_start", "step": 1, "title": "Generating initial assets", "total_steps": 5}),
        ("result", {"type": "result", "markdown": "# Model", "csv": "", "threat_model": SAMPLE_THREAT_MODEL, "model_id": "tm-001", "version": 1}),
    ])
    respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )

    progress_calls: list[tuple[int, int, str]] = []

    async def on_progress(step: int, total: int, title: str) -> None:
        progress_calls.append((step, total, title))

    client = MipitiClient()
    result = await client.generate_threat_model(
        "User login with OAuth", on_progress=on_progress
    )
    assert result.threat_model.id == "tm-001"
    assert len(progress_calls) == 1
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_stream_chat_response(mock_env: None) -> None:
    sse_payload = _build_sse_bytes([
        ("intent", {"type": "intent", "intent": "query"}),
        ("chat_response", {"type": "chat_response", "content": "The model covers SQL injection via T1."}),
    ])
    respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )
    client = MipitiClient()
    answer = await client.query_threat_model("tm-001", "Does it cover SQL injection?")
    assert "SQL injection" in answer.content
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_stream_error_event(mock_env: None) -> None:
    sse_payload = _build_sse_bytes([
        ("error", {"type": "error", "message": "LLM rate limit exceeded"}),
    ])
    respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )
    client = MipitiClient()
    with pytest.raises(RuntimeError, match="LLM rate limit exceeded"):
        await client.generate_threat_model("test")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_stream_empty_raises(mock_env: None) -> None:
    sse_payload = _build_sse_bytes([
        ("intent", {"type": "intent", "intent": "generate"}),
    ])
    respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )
    client = MipitiClient()
    with pytest.raises(RuntimeError, match="Stream ended without"):
        await client.generate_threat_model("test")
    await client.close()

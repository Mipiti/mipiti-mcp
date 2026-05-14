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
    # API returns a wrapper envelope: {"model": ..., "controls_carried": ...}.
    # Rejection / auto-restore responses are covered in the tool-level
    # tests in test_tools.py; here we just exercise the client's
    # happy-path pass-through.
    respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(
        return_value=httpx.Response(200, json={
            "model": {"id": "tm-001", "assets": [{"id": "A3", "name": "Session Store"}]},
            "controls_carried": 0,
            "controls_dropped": 0,
        })
    )
    client = MipitiClient()
    result = await client.add_asset("tm-001", name="Session Store")
    assert result["model"]["assets"][0]["id"] == "A3"
    assert result["controls_carried"] == 0
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_submit_assertions(mock_env: None) -> None:
    respx.post("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/assertions").mock(
        return_value=httpx.Response(200, json={"assertions": [{"id": "a1"}]})
    )
    client = MipitiClient()
    result = await client.submit_assertions(
        "tm-001", [{"type": "file_exists"}], control_id="CTRL-01",
    )
    assert len(result.assertions) == 1
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_reevaluate_factors_no_change_reason(mock_env: None) -> None:
    """Default call posts an empty body — the backend falls back to
    its own default change_reason for the audit trail."""
    captured: dict[str, dict] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={
            "model_id": "tm-001",
            "assets_reevaluated": 0,
            "attackers_reevaluated": 0,
            "deltas": {"assets": [], "attackers": []},
        })

    respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/factors/reevaluate",
    ).mock(side_effect=_capture)

    client = MipitiClient()
    result = await client.reevaluate_factors("tm-001")
    assert result["model_id"] == "tm-001"
    assert captured["body"] == {}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_reevaluate_factors_with_change_reason(mock_env: None) -> None:
    """When change_reason is supplied, it is threaded through to the
    body so the backend records it on every rating revision."""
    captured: dict[str, dict] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={
            "model_id": "tm-001",
            "assets_reevaluated": 1,
            "attackers_reevaluated": 1,
            "deltas": {"assets": [], "attackers": []},
        })

    respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/factors/reevaluate",
    ).mock(side_effect=_capture)

    client = MipitiClient()
    await client.reevaluate_factors(
        "tm-001", change_reason="Re-eval after bug fix",
    )
    assert captured["body"] == {"change_reason": "Re-eval after bug fix"}
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
    """The export endpoint returns ``{job_id}`` and bytes are fetched
    from ``/api/operations/{job_id}/result`` per the async-job pattern.
    """
    csv_content = b"AssetID,Name\nA1,OAuth Tokens\n"
    respx.get("https://test.api.mipiti.io/api/models/tm-001/export").mock(
        return_value=httpx.Response(200, json={"job_id": "job_csv_1"})
    )
    respx.get("https://test.api.mipiti.io/api/operations/job_csv_1/result").mock(
        return_value=httpx.Response(200, content=csv_content)
    )
    client = MipitiClient()
    job_id = await client.start_export_model("tm-001", "csv")
    assert job_id == "job_csv_1"
    result = await client.fetch_operation_result(job_id)
    assert result == csv_content
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_export_full(mock_env: None) -> None:
    """``/api/models/{id}/export/full`` follows the same async-job
    pattern: returns ``{job_id}``, archive bytes come from /result."""
    archive_content = b'{"format_version": 1}'
    respx.get("https://test.api.mipiti.io/api/models/tm-001/export/full").mock(
        return_value=httpx.Response(200, json={"job_id": "job_full_1"})
    )
    respx.get("https://test.api.mipiti.io/api/operations/job_full_1/result").mock(
        return_value=httpx.Response(200, content=archive_content)
    )
    client = MipitiClient()
    job_id = await client.start_export_model_full("tm-001")
    assert job_id == "job_full_1"
    result = await client.fetch_operation_result(job_id)
    assert result == archive_content
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
    result = await client.delete_assertion("tm-001", "a1", control_id="CTRL-01")
    assert result is None
    await client.close()


# ------------------------------------------------------------------
# Findings / Risk aggregates
# ------------------------------------------------------------------


_SAMPLE_FINDINGS_RISKS = {
    "workspace_id": "ws-1",
    "evaluated_at": "2026-05-13T00:00:00Z",
    "models": [
        {"id": "tm-001", "title": "Login Service"},
        {"id": "tm-002", "title": "Payments Service"},
    ],
    "findings": [
        {
            "id": "F-1", "model_id": "tm-001", "model_title": "Login Service",
            "control_id": "CTRL-01", "severity": "high", "status": "discovered",
            "title": "Missing rate limit", "created_at": "2026-05-01T00:00:00Z",
            "risk_tier": "high",
        },
    ],
    "risk_acceptances": [
        {
            "id": "RA-1", "model_id": "tm-001", "model_title": "Login Service",
            "control_objective_id": "CO1",
            "owner": "Platform Team",
            "justification": "Mitigated by upstream WAF; revisit in Q4.",
            "status": "active",
            "accepted_at": "2026-03-01T00:00:00Z",
            "review_by": "2026-09-01T00:00:00Z",
            "risk_tier": "medium",
        },
    ],
    "at_risk_cos": [
        {
            "model_id": "tm-002", "model_title": "Payments Service",
            "co_id": "CO9", "statement": "Protect cardholder data at rest",
            "asset_name": "Card Token Store",
            "attacker_capability": "Insider with DB access",
            "impact": "H", "likelihood": "M", "risk_tier": "high",
            "total_controls": 4, "implemented_controls": 2, "verified_controls": 1,
            "missing_controls": ["CTRL-09", "CTRL-10"],
            "risk_reason": "missing_controls",
        },
    ],
    "summary": {
        "open_findings": 1, "total_findings": 1,
        "active_risk_acceptances": 1, "total_risk_acceptances": 1,
        "at_risk_cos": 1,
    },
}


_SAMPLE_MODEL_RISK_VIEW = {
    "model_id": "tm-001",
    "model_title": "Login Service",
    "total": 1,
    "rows": [
        {
            "co_id": "CO1", "co_statement": "Protect session tokens",
            "asset_id": "A1", "asset_name": "Session Token",
            "attacker_id": "T1", "attacker_capability": "Network adversary",
            "impact": "H", "likelihood": "M", "risk_tier": "high",
            "total_controls": 3, "implemented_controls": 2,
            "verified_controls": 1, "open_findings": 1,
            "coverage_ratio": 0.66,
        },
    ],
}


_SAMPLE_SYSTEM_RISK_VIEW = {
    "system_id": "sys-1",
    "system_name": "Customer Platform",
    "models": [
        {"id": "tm-001", "title": "Login Service"},
        {"id": "tm-002", "title": "Payments Service"},
    ],
    "total": 2,
    "rows": [
        {
            "model_id": "tm-001", "model_title": "Login Service",
            "co_id": "CO1", "co_statement": "Protect session tokens",
            "asset_id": "A1", "asset_name": "Session Token",
            "attacker_id": "T1", "attacker_capability": "Network adversary",
            "impact": "H", "likelihood": "M", "risk_tier": "high",
            "total_controls": 3, "implemented_controls": 2,
            "verified_controls": 1, "open_findings": 1,
            "coverage_ratio": 0.66,
        },
        {
            "model_id": "tm-002", "model_title": "Payments Service",
            "co_id": "CO9", "co_statement": "Protect cardholder data at rest",
            "asset_id": "A4", "asset_name": "Card Token Store",
            "attacker_id": "T3", "attacker_capability": "Insider",
            "impact": "H", "likelihood": "M", "risk_tier": "high",
            "total_controls": 4, "implemented_controls": 2,
            "verified_controls": 1, "open_findings": 0,
            "coverage_ratio": 0.5,
        },
    ],
}


_SAMPLE_RISK_ACCEPTANCES = [
    {
        "id": "RA-1", "model_id": "tm-001",
        "control_objective_id": "CO1",
        "owner": "Platform Team",
        "justification": "Mitigated by upstream WAF; revisit in Q4.",
        "status": "active",
        "accepted_at": "2026-03-01T00:00:00Z",
        "review_by": "2026-09-01T00:00:00Z",
    },
    {
        "id": "RA-2", "model_id": "tm-001",
        "control_objective_id": "CO4",
        "owner": "Infra Team",
        "justification": "Compensating control in network layer.",
        "status": "expired",
        "accepted_at": "2025-09-01T00:00:00Z",
        "review_by": "2026-03-01T00:00:00Z",
    },
]


@pytest.mark.asyncio
@respx.mock
async def test_get_findings_risks(mock_env: None) -> None:
    route = respx.get("https://test.api.mipiti.io/api/findings-risks").mock(
        return_value=httpx.Response(200, json=_SAMPLE_FINDINGS_RISKS)
    )
    client = MipitiClient()
    report = await client.get_findings_risks()
    assert route.called
    assert report.workspace_id == "ws-1"
    assert report.summary["open_findings"] == 1
    assert len(report.findings) == 1
    assert len(report.risk_acceptances) == 1
    assert len(report.at_risk_cos) == 1
    assert report.at_risk_cos[0]["risk_tier"] == "high"
    # API-key header threaded through.
    assert route.calls.last.request.headers["X-API-Key"] == "test-key-123"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_model_risk_view(mock_env: None) -> None:
    route = respx.get(
        "https://test.api.mipiti.io/api/models/tm-001/risk-view"
    ).mock(return_value=httpx.Response(200, json=_SAMPLE_MODEL_RISK_VIEW))
    client = MipitiClient()
    view = await client.get_model_risk_view("tm-001")
    assert route.called
    assert view.model_id == "tm-001"
    assert view.total == 1
    assert view.rows[0]["co_id"] == "CO1"
    assert view.rows[0]["coverage_ratio"] == 0.66
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_get_system_risk_view(mock_env: None) -> None:
    route = respx.get(
        "https://test.api.mipiti.io/api/systems/sys-1/risk-view"
    ).mock(return_value=httpx.Response(200, json=_SAMPLE_SYSTEM_RISK_VIEW))
    client = MipitiClient()
    view = await client.get_system_risk_view("sys-1")
    assert route.called
    assert view.system_id == "sys-1"
    assert view.total == 2
    # Every row carries model context.
    assert all("model_id" in r and "model_title" in r for r in view.rows)
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_risk_acceptances(mock_env: None) -> None:
    route = respx.get(
        "https://test.api.mipiti.io/api/models/tm-001/risk-acceptances"
    ).mock(return_value=httpx.Response(200, json=_SAMPLE_RISK_ACCEPTANCES))
    client = MipitiClient()
    items = await client.list_risk_acceptances("tm-001")
    assert route.called
    assert isinstance(items, list)
    assert len(items) == 2
    assert items[0]["id"] == "RA-1"
    assert items[1]["status"] == "expired"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_risk_acceptances_empty(mock_env: None) -> None:
    respx.get(
        "https://test.api.mipiti.io/api/models/tm-001/risk-acceptances"
    ).mock(return_value=httpx.Response(200, json=[]))
    client = MipitiClient()
    items = await client.list_risk_acceptances("tm-001")
    assert items == []
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


# ------------------------------------------------------------------
# delete_control tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_delete_control_sends_reason_as_query_param(mock_env: None) -> None:
    route = respx.delete("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01").mock(
        return_value=httpx.Response(200, json={"deleted": True, "control_id": "CTRL-01"})
    )
    client = MipitiClient()
    result = await client.delete_control("tm-001", "CTRL-01", reason="Duplicate")
    assert result.deleted is True
    assert result.control_id == "CTRL-01"
    req = route.calls[0].request
    assert req.url.params["reason"] == "Duplicate"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_delete_control_empty_reason(mock_env: None) -> None:
    route = respx.delete("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01").mock(
        return_value=httpx.Response(200, json={"deleted": True, "control_id": "CTRL-01"})
    )
    client = MipitiClient()
    result = await client.delete_control("tm-001", "CTRL-01")
    assert result.deleted is True
    # No query params when reason is empty
    req = route.calls[0].request
    assert req.url.params.multi_items() == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_delete_control_409_raises(mock_env: None) -> None:
    respx.delete("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01").mock(
        return_value=httpx.Response(409, json={
            "detail": "Cannot delete CTRL-01 — it is the only control covering: CO1."
        })
    )
    client = MipitiClient()
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await client.delete_control("tm-001", "CTRL-01", reason="test")
    assert exc_info.value.response.status_code == 409
    assert "CO1" in exc_info.value.response.json()["detail"]
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_delete_control_404_raises(mock_env: None) -> None:
    respx.delete("https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-99").mock(
        return_value=httpx.Response(404, json={
            "detail": "Control not found or already deleted."
        })
    )
    client = MipitiClient()
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await client.delete_control("tm-001", "CTRL-99", reason="test")
    assert exc_info.value.response.status_code == 404
    await client.close()


# ------------------------------------------------------------------
# submit_assertions URL routing tests
# ------------------------------------------------------------------


class TestSubmitAssertionsClient:
    """Verify submit_assertions routes to the correct endpoint based on
    control_id vs assumption_id."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_routes_to_assumption_endpoint(self, mock_env: None) -> None:
        route = respx.post(
            "https://test.api.mipiti.io/api/models/tm-001/assumptions/AS1/assertions"
        ).mock(
            return_value=httpx.Response(
                200, json={"assertions": [{"id": "a1"}]},
            )
        )
        client = MipitiClient()
        result = await client.submit_assertions(
            "tm-001",
            [{"type": "file_exists", "params": {"path": "auth.py"}}],
            assumption_id="AS1",
        )
        assert len(result.assertions) == 1
        assert route.called
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_routes_to_control_endpoint(self, mock_env: None) -> None:
        route = respx.post(
            "https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/assertions"
        ).mock(
            return_value=httpx.Response(
                200, json={"assertions": [{"id": "a2"}]},
            )
        )
        client = MipitiClient()
        result = await client.submit_assertions(
            "tm-001",
            [{"type": "test_passes", "params": {"command": "pytest"}}],
            control_id="CTRL-01",
        )
        assert len(result.assertions) == 1
        assert route.called
        await client.close()

    @pytest.mark.asyncio
    async def test_rejects_both_ids(self, mock_env: None) -> None:
        client = MipitiClient()
        with pytest.raises(ValueError, match="not both"):
            await client.submit_assertions(
                "tm-001",
                [{"type": "file_exists"}],
                control_id="CTRL-01",
                assumption_id="AS1",
            )
        await client.close()

    @pytest.mark.asyncio
    async def test_rejects_neither_id(self, mock_env: None) -> None:
        client = MipitiClient()
        with pytest.raises(ValueError, match="required"):
            await client.submit_assertions(
                "tm-001",
                [{"type": "file_exists"}],
            )
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_response_wrapped(self, mock_env: None) -> None:
        """When the API returns a raw list, it should be wrapped into
        SubmitAssertionsResult.assertions."""
        respx.post(
            "https://test.api.mipiti.io/api/models/tm-001/controls/CTRL-01/assertions"
        ).mock(
            return_value=httpx.Response(
                200, json=[{"id": "a1", "type": "file_exists"}],
            )
        )
        client = MipitiClient()
        result = await client.submit_assertions(
            "tm-001",
            [{"type": "file_exists"}],
            control_id="CTRL-01",
        )
        assert len(result.assertions) == 1
        await client.close()


# ------------------------------------------------------------------
# Idempotency-Key + retry tests
# ------------------------------------------------------------------


class TestIdempotencyKey:
    @pytest.mark.asyncio
    @respx.mock
    async def test_post_includes_fresh_key(self, mock_env: None) -> None:
        """Each _post call generates a fresh Idempotency-Key UUID."""
        captured_keys: list[str] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_keys.append(request.headers.get("Idempotency-Key", ""))
            return httpx.Response(200, json={"id": "A1", "name": "ok"})

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(side_effect=_capture)

        client = MipitiClient()
        await client.add_asset("tm-001", name="One")
        await client.add_asset("tm-001", name="Two")
        await client.close()

        assert len(captured_keys) == 2
        assert all(k for k in captured_keys), f"missing keys: {captured_keys}"
        assert captured_keys[0] != captured_keys[1], "each call should get a fresh UUID"

    @pytest.mark.asyncio
    @respx.mock
    async def test_patch_includes_key(self, mock_env: None) -> None:
        captured: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured["key"] = request.headers.get("Idempotency-Key", "")
            return httpx.Response(200, json={"ok": True})

        respx.patch("https://test.api.mipiti.io/api/models/tm-001").mock(side_effect=_capture)

        client = MipitiClient()
        await client.rename_model("tm-001", "New Name")
        await client.close()
        assert captured["key"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_put_includes_key(self, mock_env: None) -> None:
        captured: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured["key"] = request.headers.get("Idempotency-Key", "")
            return httpx.Response(200, json={"id": "A1", "name": "edited"})

        respx.put("https://test.api.mipiti.io/api/models/tm-001/assets/A1").mock(side_effect=_capture)

        client = MipitiClient()
        await client.edit_asset("tm-001", "A1", name="edited")
        await client.close()
        assert captured["key"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_delete_includes_key(self, mock_env: None) -> None:
        captured: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured["key"] = request.headers.get("Idempotency-Key", "")
            return httpx.Response(200, json={"deleted": True})

        respx.delete("https://test.api.mipiti.io/api/models/tm-001/assets/A1").mock(side_effect=_capture)

        client = MipitiClient()
        await client.remove_asset("tm-001", "A1")
        await client.close()
        assert captured["key"]


class TestTransientRetry:
    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_connect_error(self, mock_env: None, monkeypatch) -> None:
        """ConnectError on first attempt → retry → success on second attempt."""
        # Skip the actual sleep delays to keep tests fast
        async def _no_sleep(_): pass
        monkeypatch.setattr("mipiti_mcp.client.asyncio.sleep", _no_sleep)

        captured_keys: list[str] = []
        attempts = {"n": 0}

        def _flaky(request: httpx.Request) -> httpx.Response:
            captured_keys.append(request.headers.get("Idempotency-Key", ""))
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise httpx.ConnectError("network blip")
            return httpx.Response(200, json={
                "model": {"id": "tm-001", "assets": [{"id": "A1", "name": "after retry"}]},
                "controls_carried": 0, "controls_dropped": 0,
            })

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(side_effect=_flaky)

        client = MipitiClient()
        result = await client.add_asset("tm-001", name="x")
        await client.close()

        assert result["model"]["assets"][0]["name"] == "after retry"
        assert attempts["n"] == 2
        # Both attempts must use the SAME key so the server cache deduplicates
        assert len(captured_keys) == 2
        assert captured_keys[0] == captured_keys[1]
        assert captured_keys[0]  # non-empty

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_503(self, mock_env: None, monkeypatch) -> None:
        """503 status → retry → success."""
        async def _no_sleep(_): pass
        monkeypatch.setattr("mipiti_mcp.client.asyncio.sleep", _no_sleep)

        captured_keys: list[str] = []
        attempts = {"n": 0}

        def _flaky(request: httpx.Request) -> httpx.Response:
            captured_keys.append(request.headers.get("Idempotency-Key", ""))
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(503, text="Service Unavailable")
            return httpx.Response(200, json={"id": "A1", "name": "ok"})

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(side_effect=_flaky)

        client = MipitiClient()
        await client.add_asset("tm-001", name="x")
        await client.close()
        assert attempts["n"] == 2
        assert captured_keys[0] == captured_keys[1]

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_retry_on_4xx(self, mock_env: None, monkeypatch) -> None:
        """4xx response is NOT retried — fails immediately."""
        async def _no_sleep(_): pass
        monkeypatch.setattr("mipiti_mcp.client.asyncio.sleep", _no_sleep)

        attempts = {"n": 0}

        def _bad_request(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(400, json={"detail": "bad input"})

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(side_effect=_bad_request)

        client = MipitiClient()
        with pytest.raises(httpx.HTTPStatusError):
            await client.add_asset("tm-001", name="x")
        await client.close()
        assert attempts["n"] == 1  # no retry

    @pytest.mark.asyncio
    @respx.mock
    async def test_retries_exhausted_raises(self, mock_env: None, monkeypatch) -> None:
        """Persistent ConnectError exhausts retries and raises."""
        async def _no_sleep(_): pass
        monkeypatch.setattr("mipiti_mcp.client.asyncio.sleep", _no_sleep)

        attempts = {"n": 0}

        def _always_fail(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            raise httpx.ConnectError("permanent")

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets").mock(side_effect=_always_fail)

        client = MipitiClient()
        with pytest.raises(httpx.ConnectError, match="permanent"):
            await client.add_asset("tm-001", name="x")
        await client.close()
        # Initial attempt + 3 retries = 4 total attempts
        assert attempts["n"] == 4


# ------------------------------------------------------------------
# list_findings query-param forwarding tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_findings_defaults_no_query_params(mock_env: None) -> None:
    """Backwards compatibility: bare call sends no query params."""
    route = respx.get("https://test.api.mipiti.io/api/models/tm-001/findings").mock(
        return_value=httpx.Response(200, json=[]),
    )
    client = MipitiClient()
    result = await client.list_findings("tm-001")
    assert result == []
    assert route.calls[0].request.url.params.multi_items() == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_findings_forwards_new_params(mock_env: None) -> None:
    """All four new params (kind, summary_only, limit, offset) must be
    sent as query params with the names locked by the REST contract."""
    wrapped = {
        "findings": [],
        "total": 0,
        "returned": 0,
        "summary_only": True,
    }
    route = respx.get("https://test.api.mipiti.io/api/models/tm-001/findings").mock(
        return_value=httpx.Response(200, json=wrapped),
    )
    client = MipitiClient()
    result = await client.list_findings(
        "tm-001",
        control_id="CTRL-01",
        status="discovered",
        kind="structural_duplicate_controls",
        summary_only=True,
        limit=50,
        offset=100,
    )
    # Wrapped envelope passes through unchanged when not a list.
    assert result == wrapped
    params = route.calls[0].request.url.params
    assert params["control_id"] == "CTRL-01"
    assert params["status"] == "discovered"
    assert params["kind"] == "structural_duplicate_controls"
    assert params["summary_only"] == "true"
    assert params["limit"] == "50"
    assert params["offset"] == "100"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_findings_summary_only_false_omitted(mock_env: None) -> None:
    """summary_only=False (default) must NOT appear in the query string —
    keeps the legacy URL stable for callers that don't opt in."""
    route = respx.get("https://test.api.mipiti.io/api/models/tm-001/findings").mock(
        return_value=httpx.Response(200, json=[]),
    )
    client = MipitiClient()
    await client.list_findings("tm-001", summary_only=False)
    params = route.calls[0].request.url.params
    assert "summary_only" not in params
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_findings_limit_offset_zero_omitted(mock_env: None) -> None:
    """limit=0 / offset=0 (defaults) must NOT appear in the query string."""
    route = respx.get("https://test.api.mipiti.io/api/models/tm-001/findings").mock(
        return_value=httpx.Response(200, json=[]),
    )
    client = MipitiClient()
    await client.list_findings("tm-001", limit=0, offset=0)
    params = route.calls[0].request.url.params
    assert "limit" not in params
    assert "offset" not in params
    await client.close()

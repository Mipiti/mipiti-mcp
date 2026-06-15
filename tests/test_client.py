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
    # The add now runs as a background job: the client POSTs the -job
    # endpoint and gets back a {"job_id": ...} handle to poll. Rejection /
    # auto-restore responses are delivered as the job result and covered in
    # the tool-level tests in test_tools.py; here we just exercise the
    # client's happy-path pass-through of the job handle.
    respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(
        return_value=httpx.Response(200, json={"job_id": "job-add-asset"})
    )
    client = MipitiClient()
    result = await client.start_add_asset("tm-001", name="Session Store")
    assert result["job_id"] == "job-add-asset"
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
async def test_start_reevaluate_factors_no_change_reason(mock_env: None) -> None:
    """Default call posts an empty body to the job endpoint and returns a
    job_id; the backend falls back to its own default change_reason."""
    captured: dict[str, dict] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"job_id": "job-reeval"})

    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/factors/reevaluate-job",
    ).mock(side_effect=_capture)

    client = MipitiClient()
    result = await client.start_reevaluate_factors("tm-001")
    assert route.called
    assert result["job_id"] == "job-reeval"
    assert captured["body"] == {}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_start_reevaluate_factors_with_change_reason(mock_env: None) -> None:
    """change_reason is threaded through to the job-endpoint body."""
    captured: dict[str, dict] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"job_id": "job-reeval"})

    respx.post(
        "https://test.api.mipiti.io/api/models/tm-001/factors/reevaluate-job",
    ).mock(side_effect=_capture)

    client = MipitiClient()
    await client.start_reevaluate_factors(
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
async def test_list_findings_flat_list(mock_env: None) -> None:
    """Legacy/flat response shape: a bare list of findings."""
    respx.get("https://test.api.mipiti.io/api/models/m1/findings").mock(
        return_value=httpx.Response(200, json=[
            {"id": "find_001", "control_id": "CTRL-1", "title": "Gap"},
        ])
    )
    client = MipitiClient()
    findings = await client.list_findings("m1")
    assert [f.id for f in findings] == ["find_001"]
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_findings_wrapper_shape(mock_env: None) -> None:
    """Wrapper response (own + inherited arms) is flattened into the flat-list
    contract; inherited rows keep their additive ``origin`` key via extra-allow."""
    respx.get("https://test.api.mipiti.io/api/models/m1/findings").mock(
        return_value=httpx.Response(200, json={
            "own": [{"id": "find_own", "control_id": "CTRL-1", "title": "Own gap"}],
            "inherited": [{
                "id": "find_inh", "control_id": "CTRL-2", "title": "Inherited gap",
                "origin": "inherited", "inherited_from_model_id": "parent-1",
            }],
        })
    )
    client = MipitiClient()
    findings = await client.list_findings("m1")
    assert [f.id for f in findings] == ["find_own", "find_inh"]
    # Additive inheritance metadata survives (extra="allow").
    assert findings[1].origin == "inherited"
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
async def test_stream_generate_forwards_parent_id(mock_env: None) -> None:
    """parent_id reaches the /api/model/stream body so the backend wires
    the new model under the parent on the composition tree."""
    sse_payload = _build_sse_bytes([
        ("result", {"type": "result", "markdown": "# Model", "csv": "", "threat_model": SAMPLE_THREAT_MODEL, "model_id": "tm-001", "version": 1}),
    ])
    route = respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )
    client = MipitiClient()
    result = await client.generate_threat_model(
        "Child service", parent_id="tm-parent",
    )
    assert result.threat_model.id == "tm-001"
    body = json.loads(route.calls.last.request.content)
    assert body["parent_id"] == "tm-parent"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_stream_generate_omits_parent_id_when_absent(mock_env: None) -> None:
    """Without parent_id the body carries no parent_id key (flat model)."""
    sse_payload = _build_sse_bytes([
        ("result", {"type": "result", "markdown": "# Model", "csv": "", "threat_model": SAMPLE_THREAT_MODEL, "model_id": "tm-001", "version": 1}),
    ])
    route = respx.post("https://test.api.mipiti.io/api/model/stream").mock(
        return_value=httpx.Response(
            200, content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )
    )
    client = MipitiClient()
    await client.generate_threat_model("Flat service")
    body = json.loads(route.calls.last.request.content)
    assert "parent_id" not in body
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

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(side_effect=_capture)

        client = MipitiClient()
        await client.start_add_asset("tm-001", name="One")
        await client.start_add_asset("tm-001", name="Two")
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

        respx.put("https://test.api.mipiti.io/api/models/tm-001/components/CMP1").mock(side_effect=_capture)

        client = MipitiClient()
        await client.edit_component("tm-001", "CMP1", name="edited")
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
            return httpx.Response(200, json={"job_id": "job-add-asset"})

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(side_effect=_flaky)

        client = MipitiClient()
        result = await client.start_add_asset("tm-001", name="x")
        await client.close()

        assert result["job_id"] == "job-add-asset"
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
            return httpx.Response(200, json={"job_id": "job-add-asset"})

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(side_effect=_flaky)

        client = MipitiClient()
        await client.start_add_asset("tm-001", name="x")
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

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(side_effect=_bad_request)

        client = MipitiClient()
        with pytest.raises(httpx.HTTPStatusError):
            await client.start_add_asset("tm-001", name="x")
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

        respx.post("https://test.api.mipiti.io/api/models/tm-001/assets/add-job").mock(side_effect=_always_fail)

        client = MipitiClient()
        with pytest.raises(httpx.ConnectError, match="permanent"):
            await client.start_add_asset("tm-001", name="x")
        await client.close()
        # Initial attempt + 3 retries = 4 total attempts
        assert attempts["n"] == 4


# ------------------------------------------------------------------
# Composition (recursive-tree effective model) — client URL contracts.
#
# The MCP tool wrappers in tests/test_tools.py mock at the client level;
# the assertions below pin the actual HTTP paths to the routes the
# backend exposes (see backend/app/routes/composition.py). If a path
# drifts, these tests catch it before a tool starts returning
# unexpected 404s in production.
# ------------------------------------------------------------------


_BASE = "https://test.api.mipiti.io"


@pytest.mark.asyncio
@respx.mock
async def test_composition_index(mock_env: None) -> None:
    payload = {"model_id": "tm-001", "flag_enabled": True}
    respx.get(f"{_BASE}/api/models/tm-001/composition").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_index("tm-001")
    assert out["flag_enabled"] is True
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_entities(mock_env: None) -> None:
    payload = {"model_id": "tm-001", "flag_enabled": True,
               "kinds": {"assets": []}}
    respx.get(f"{_BASE}/api/models/tm-001/composition/entities").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_entities("tm-001")
    assert "kinds" in out
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_control_objectives(mock_env: None) -> None:
    payload = {"model_id": "tm-001", "flag_enabled": True,
               "control_objectives": []}
    respx.get(
        f"{_BASE}/api/models/tm-001/composition/control-objectives",
    ).mock(return_value=httpx.Response(200, json=payload))
    client = MipitiClient()
    out = await client.composition_control_objectives("tm-001")
    assert out["control_objectives"] == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_coverage(mock_env: None) -> None:
    payload = {"model_id": "tm-001", "flag_enabled": True, "coverage": []}
    respx.get(f"{_BASE}/api/models/tm-001/composition/coverage").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_coverage("tm-001")
    assert out["coverage"] == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_reachability(mock_env: None) -> None:
    payload = {"model_id": "tm-001", "flag_enabled": True, "verdicts": []}
    respx.get(f"{_BASE}/api/models/tm-001/composition/reachability").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_reachability("tm-001")
    assert out["verdicts"] == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_attack_paths(mock_env: None) -> None:
    payload = {
        "model_id": "tm-001", "flag_enabled": True,
        "effective_paths": [],
        "lattice_positions": 0, "authored_paths": 0,
        "suggestions": {"missing_path": [], "dangling_path": []},
    }
    respx.get(f"{_BASE}/api/models/tm-001/composition/attack-paths").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_attack_paths("tm-001")
    assert out["effective_paths"] == []
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_reconciliation_forwards_pagination(
    mock_env: None,
) -> None:
    payload = {
        "model_id": "tm-001", "flag_enabled": True, "total": 0,
        "tiers": {"certain": 0, "heuristic": 0},
        "page": 2, "page_size": 25, "candidates": [],
    }
    route = respx.get(
        f"{_BASE}/api/models/tm-001/composition/reconciliation",
    ).mock(return_value=httpx.Response(200, json=payload))
    client = MipitiClient()
    out = await client.composition_reconciliation(
        "tm-001", page=2, page_size=25,
    )
    assert out["page"] == 2
    assert route.calls.last.request.url.params["page"] == "2"
    assert route.calls.last.request.url.params["page_size"] == "25"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_apply_certain_reconciliation_match_pins_path_and_body(
    mock_env: None,
) -> None:
    """Pin the literal POST path + body shape so a typo at the client
    layer surfaces as a test failure rather than a runtime 404."""
    envelope = {
        "model": {"id": "tm-001", "assets": []},
        "controls_carried": 2,
        "controls_orphaned": 1,
        "orphaned_control_ids": ["CTRL-09"],
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-001/composition/reconciliation/apply-match",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.apply_certain_reconciliation_match(
        "tm-001", "assets", "child:A1", "parent:A1",
    )
    assert out == envelope
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "assets",
        "own_qid": "child:A1",
        "inherited_qid": "parent:A1",
    }
    # Idempotency-Key header is always set on mutating requests so retry
    # safely deduplicates server-side.
    assert "Idempotency-Key" in route.calls.last.request.headers
    # Default path: confirm_heuristic is omitted entirely.
    assert "confirm_heuristic" not in body
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_apply_certain_reconciliation_match_forwards_confirm_heuristic(
    mock_env: None,
) -> None:
    """confirm_heuristic=True reaches the apply-match body so the backend
    applies a heuristic-tier candidate despite its structural divergence."""
    envelope = {
        "model": {"id": "tm-001", "assets": []},
        "controls_carried": 0,
        "controls_orphaned": 0,
        "orphaned_control_ids": [],
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-001/composition/reconciliation/apply-match",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    await client.apply_certain_reconciliation_match(
        "tm-001", "attackers", "child:T1", "parent:T1",
        confirm_heuristic=True,
    )
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "attackers",
        "own_qid": "child:T1",
        "inherited_qid": "parent:T1",
        "confirm_heuristic": True,
    }
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_reject_reconciliation_candidate_pins_path_and_body(
    mock_env: None,
) -> None:
    """Pin the literal POST path + body shape for the rejection route."""
    persisted = {
        "id": "rej-001",
        "model_id": "tm-001",
        "kind": "assets",
        "own_qid": "child:A1",
        "inherited_qid": "parent:A1",
        "rejected_by": "user-1",
        "rejected_at": "2026-05-27T00:00:00+00:00",
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-001/composition/reconciliation/reject",
    ).mock(return_value=httpx.Response(200, json=persisted))
    client = MipitiClient()
    out = await client.reject_reconciliation_candidate(
        "tm-001", "assets", "child:A1", "parent:A1",
    )
    assert out == persisted
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "assets",
        "own_qid": "child:A1",
        "inherited_qid": "parent:A1",
    }
    # Idempotency-Key carries over for the rejection POST too. The
    # natural-key idempotency on the server doesn't need it, but the
    # transient-retry path relies on it for safe deduplication.
    assert "Idempotency-Key" in route.calls.last.request.headers
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_unreject_reconciliation_candidate_pins_path(
    mock_env: None,
) -> None:
    """Pin the literal DELETE path so a typo at the client layer
    surfaces as a test failure rather than a runtime 404."""
    route = respx.delete(
        f"{_BASE}/api/models/tm-001/composition/reconciliation/reject/rej-001",
    ).mock(return_value=httpx.Response(200, json={"ok": True}))
    client = MipitiClient()
    out = await client.unreject_reconciliation_candidate("tm-001", "rej-001")
    assert out == {"ok": True}
    assert route.called
    # Idempotency-Key is set for DELETE too — the transient-retry
    # helper attaches it on every mutating request uniformly.
    assert "Idempotency-Key" in route.calls.last.request.headers
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_list_reconciliation_rejections_pins_path(
    mock_env: None,
) -> None:
    """Pin the literal GET path for the rejections list route."""
    payload = {
        "model_id": "tm-001",
        "flag_enabled": True,
        "rejections": [
            {
                "id": "rej-001",
                "model_id": "tm-001",
                "kind": "assets",
                "own_qid": "child:A1",
                "inherited_qid": "parent:A1",
                "rejected_by": "user-1",
                "rejected_at": "2026-05-27T00:00:00+00:00",
            },
        ],
    }
    route = respx.get(
        f"{_BASE}/api/models/tm-001/composition/reconciliation/rejections",
    ).mock(return_value=httpx.Response(200, json=payload))
    client = MipitiClient()
    out = await client.list_reconciliation_rejections("tm-001")
    assert out == payload
    assert route.called
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_lift_composition_entity_pins_path_and_body(
    mock_env: None,
) -> None:
    """Pin the literal POST path + minimal body shape for the lift
    route. Only the six required fields appear when the optional
    operator-confirmation knobs are omitted — that's what the backend
    treats as defaults (empty resolutions, server-computed descendant
    set, gate ON)."""
    envelope = {
        "lift_id": "lift-001",
        "lca_model": {"id": "tm-lca", "assets": [{"id": "A1"}]},
        "descendant_a_model": {"id": "tm-da", "assets": []},
        "descendant_b_model": {"id": "tm-db", "assets": []},
        "applied_migrations": [],
        "lift_event": {
            "lift_id": "lift-001",
            "kind": "assets",
            "source_model_ids": ["tm-da", "tm-db"],
            "source_entity_ids": ["A1", "A1"],
            "lca_model_id": "tm-lca",
            "new_entity_id": "A1",
        },
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-ctx/composition/lift",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.lift_composition_entity(
        "tm-ctx", "assets", "A1", "A1", "tm-da", "tm-db", "tm-lca",
    )
    assert out == envelope
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "assets",
        "local_id_a": "A1",
        "local_id_b": "A1",
        "descendant_a_id": "tm-da",
        "descendant_b_id": "tm-db",
        "lca_model_id": "tm-lca",
    }
    # Idempotency-Key carries on the mutating POST so retries
    # deduplicate server-side.
    assert "Idempotency-Key" in route.calls.last.request.headers
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_lift_composition_entity_forwards_operator_confirmations(
    mock_env: None,
) -> None:
    """When the agent supplies operator-confirmation knobs, every one
    appears in the body exactly once and unchanged. The server reads
    these to re-run conflict detection + the over-application gate."""
    envelope = {
        "lift_id": "lift-002",
        "lca_model": {"id": "tm-lca", "assets": []},
        "descendant_a_model": {"id": "tm-da", "assets": []},
        "descendant_b_model": {"id": "tm-db", "assets": []},
        "applied_migrations": [],
        "lift_event": {},
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-ctx/composition/lift",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    await client.lift_composition_entity(
        "tm-ctx", "components", "C1", "C1", "tm-da", "tm-db", "tm-lca",
        lca_descendant_ids=["tm-da", "tm-db", "tm-dc"],
        acknowledged_third_party_subtrees=["tm-dc"],
        field_resolutions={"description": "keep_both"},
        attached_state_resolutions={"state:assertions/AS1": "keep_b"},
        skip_overapplication_gate=True,
    )
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "components",
        "local_id_a": "C1",
        "local_id_b": "C1",
        "descendant_a_id": "tm-da",
        "descendant_b_id": "tm-db",
        "lca_model_id": "tm-lca",
        "lca_descendant_ids": ["tm-da", "tm-db", "tm-dc"],
        "acknowledged_third_party_subtrees": ["tm-dc"],
        "field_resolutions": {"description": "keep_both"},
        "attached_state_resolutions": {"state:assertions/AS1": "keep_b"},
        "skip_overapplication_gate": True,
    }
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_split_composition_entity_pins_path_and_body(
    mock_env: None,
) -> None:
    """Pin the literal POST path + body shape for the split route."""
    envelope = {
        "split_id": "split-001",
        "ancestor_model": {"id": "tm-anc", "assets": []},
        "descendant_models": [
            {"id": "tm-d1", "assets": [{"id": "A1"}]},
            {"id": "tm-d2", "assets": [{"id": "A1"}]},
        ],
        "applied_duplications": [],
        "split_event": {
            "split_id": "split-001",
            "kind": "assets",
            "ancestor_model_id": "tm-anc",
            "source_entity_id": "A1",
            "target_descendants": ["tm-d1", "tm-d2"],
            "new_entity_ids": {"tm-d1": "A1", "tm-d2": "A1"},
        },
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-anc/composition/split",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.split_composition_entity(
        "tm-anc", "assets", "A1", ["tm-d1", "tm-d2"],
    )
    assert out == envelope
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "kind": "assets",
        "ancestor_local_id": "A1",
        "target_descendants": ["tm-d1", "tm-d2"],
    }
    assert "Idempotency-Key" in route.calls.last.request.headers
    await client.close()


# ------------------------------------------------------------------
# Composition undo (lift / split) — URL contract pins
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_preview_lift_undo_pins_path(mock_env: None) -> None:
    """Pin the literal GET path for the lift-undo preview route. Read-only,
    so no Idempotency-Key contract; the body is just a passthrough of
    the backend's ``{plan, refusal}`` envelope."""
    envelope = {
        "plan": {
            "kind": "lift",
            "original_event_id": "lift-001",
            "state_ops": [],
        },
        "refusal": None,
    }
    route = respx.get(
        f"{_BASE}/api/models/tm-lca/composition/lift/lift-001/undo/preview",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.preview_lift_undo("tm-lca", "lift-001")
    assert out == envelope
    assert route.called
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_undo_lift_pins_path_and_idempotency_key(mock_env: None) -> None:
    """Pin the literal POST path for the lift-undo apply route. Mutating,
    so the Idempotency-Key header rides on every call so retries
    deduplicate server-side."""
    envelope = {
        "undone_event_id": "undo-001",
        "original_event_id": "lift-001",
        "applied_state_ops": [],
        "models": {
            "lca_model": {"id": "tm-lca", "assets": []},
            "source_descendant_models": [
                {"id": "tm-da", "assets": [{"id": "A1"}]},
                {"id": "tm-db", "assets": [{"id": "A1"}]},
            ],
        },
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-lca/composition/lift/lift-001/undo",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.undo_lift("tm-lca", "lift-001")
    assert out == envelope
    assert route.called
    assert "Idempotency-Key" in route.calls.last.request.headers
    # No body on the apply call — the event id in the URL is the only input.
    assert route.calls.last.request.content in (b"", b"null")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_preview_split_undo_pins_path(mock_env: None) -> None:
    """Pin the literal GET path for the split-undo preview route."""
    envelope = {
        "plan": {
            "kind": "split",
            "original_event_id": "split-001",
            "state_ops": [],
        },
        "refusal": None,
    }
    route = respx.get(
        f"{_BASE}/api/models/tm-anc/composition/split/split-001/undo/preview",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.preview_split_undo("tm-anc", "split-001")
    assert out == envelope
    assert route.called
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_undo_split_pins_path_and_idempotency_key(mock_env: None) -> None:
    """Pin the literal POST path for the split-undo apply route. Same
    Idempotency-Key contract as the lift-undo apply path."""
    envelope = {
        "undone_event_id": "undo-002",
        "original_event_id": "split-001",
        "applied_state_ops": [],
        "models": {
            "ancestor_model": {"id": "tm-anc", "assets": [{"id": "A1"}]},
            "descendant_models": [
                {"id": "tm-d1", "assets": []},
                {"id": "tm-d2", "assets": []},
            ],
        },
    }
    route = respx.post(
        f"{_BASE}/api/models/tm-anc/composition/split/split-001/undo",
    ).mock(return_value=httpx.Response(200, json=envelope))
    client = MipitiClient()
    out = await client.undo_split("tm-anc", "split-001")
    assert out == envelope
    assert route.called
    assert "Idempotency-Key" in route.calls.last.request.headers
    assert route.calls.last.request.content in (b"", b"null")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_set_parent_sets_id(mock_env: None) -> None:
    payload = dict(SAMPLE_THREAT_MODEL, version=2)
    route = respx.put(
        f"{_BASE}/api/models/tm-001/parent",
    ).mock(return_value=httpx.Response(200, json=payload))
    client = MipitiClient()
    out = await client.set_parent("tm-001", "tm-parent")
    assert out.id == "tm-001"
    assert out.version == 2
    assert route.called
    assert route.calls.last.request.method == "PUT"
    assert json.loads(route.calls.last.request.content) == {"parent_id": "tm-parent"}
    assert "Idempotency-Key" in route.calls.last.request.headers
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_set_parent_clears_with_none(mock_env: None) -> None:
    payload = dict(SAMPLE_THREAT_MODEL, version=3)
    route = respx.put(
        f"{_BASE}/api/models/tm-001/parent",
    ).mock(return_value=httpx.Response(200, json=payload))
    client = MipitiClient()
    out = await client.set_parent("tm-001", None)
    assert out.id == "tm-001"
    assert route.called
    assert route.calls.last.request.method == "PUT"
    assert json.loads(route.calls.last.request.content) == {"parent_id": None}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_create_reliance_posts_edge(mock_env: None) -> None:
    route = respx.post(f"{_BASE}/api/models/tm-001/reliance").mock(
        return_value=httpx.Response(201, json={"id": "rel_1", "status": "draft"}),
    )
    client = MipitiClient()
    out = await client.create_reliance(
        "tm-001", "prov", "CTRL-A", "delegated", source_objective_id="CO1",
    )
    assert out["id"] == "rel_1"
    body = json.loads(route.calls.last.request.content)
    assert body["provider_control_id"] == "CTRL-A"
    assert body["mode"] == "delegated"
    assert body["source_objective_id"] == "CO1"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_confirm_and_delete_reliance(mock_env: None) -> None:
    respx.post(f"{_BASE}/api/reliance/rel_1/confirm").mock(
        return_value=httpx.Response(200, json={"id": "rel_1", "status": "active"}),
    )
    respx.delete(f"{_BASE}/api/reliance/rel_1").mock(
        return_value=httpx.Response(200, json={"deleted": True}),
    )
    client = MipitiClient()
    confirmed = await client.confirm_reliance("rel_1")
    assert confirmed["status"] == "active"
    await client.delete_reliance("rel_1")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_declare_and_attach_foundation(mock_env: None) -> None:
    respx.put(f"{_BASE}/api/models/tm-001/foundation").mock(
        return_value=httpx.Response(200, json={"model_id": "tm-001"}),
    )
    respx.get(
        f"{_BASE}/api/models/tm-001/attach-foundation/prov/proposals",
    ).mock(return_value=httpx.Response(200, json={"proposals": []}))
    respx.post(f"{_BASE}/api/models/tm-001/attach-foundation").mock(
        return_value=httpx.Response(200, json={"created": [], "failed": []}),
    )
    client = MipitiClient()
    await client.declare_foundation("tm-001", [{"control_id": "CTRL-01"}])
    props = await client.propose_attach_foundation("tm-001", "prov")
    assert props == {"proposals": []}
    attached = await client.attach_foundation("tm-001", "prov", [])
    assert attached == {"created": [], "failed": []}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_entities_forwards_pagination_and_kind(
    mock_env: None,
) -> None:
    payload = {
        "model_id": "tm-001", "flag_enabled": True,
        "kinds": {"attackers": []},
        "total": 0, "page": 2, "page_size": 25,
    }
    route = respx.get(f"{_BASE}/api/models/tm-001/composition/entities").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    out = await client.composition_entities(
        "tm-001", page=2, page_size=25, kind="attackers",
    )
    assert out["page"] == 2
    assert route.called
    request = route.calls.last.request
    assert request.url.params.get("page") == "2"
    assert request.url.params.get("page_size") == "25"
    assert request.url.params.get("kind") == "attackers"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_coverage_forwards_pagination_and_origin(
    mock_env: None,
) -> None:
    payload = {
        "model_id": "tm-001", "flag_enabled": True, "coverage": [],
        "total": 0, "page": 1, "page_size": 50,
    }
    route = respx.get(f"{_BASE}/api/models/tm-001/composition/coverage").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    await client.composition_coverage(
        "tm-001", page=1, page_size=50, origin="inherited",
    )
    request = route.calls.last.request
    assert request.url.params.get("page") == "1"
    assert request.url.params.get("page_size") == "50"
    assert request.url.params.get("origin") == "inherited"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_composition_reachability_forwards_pagination_and_kind_filter(
    mock_env: None,
) -> None:
    payload = {
        "model_id": "tm-001", "flag_enabled": True, "verdicts": [],
        "total": 0, "page": 3, "page_size": 10,
    }
    route = respx.get(f"{_BASE}/api/models/tm-001/composition/reachability").mock(
        return_value=httpx.Response(200, json=payload),
    )
    client = MipitiClient()
    await client.composition_reachability(
        "tm-001", page=3, page_size=10, kind_filter="indeterminate",
    )
    request = route.calls.last.request
    assert request.url.params.get("page") == "3"
    assert request.url.params.get("page_size") == "10"
    assert request.url.params.get("kind_filter") == "indeterminate"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_tag_crud_and_membership(mock_env: None) -> None:
    respx.post(f"{_BASE}/api/tags").mock(
        return_value=httpx.Response(201, json={"id": "tag1", "name": "Scope"}),
    )
    respx.get(f"{_BASE}/api/tags").mock(
        return_value=httpx.Response(200, json={"tags": [{"id": "tag1"}]}),
    )
    respx.post(f"{_BASE}/api/tags/tag1/models").mock(
        return_value=httpx.Response(200, json={"id": "tag1", "model_ids": ["m1"]}),
    )
    respx.delete(f"{_BASE}/api/tags/tag1/models/m1").mock(
        return_value=httpx.Response(200, json={}),
    )
    respx.get(f"{_BASE}/api/tags/tag1/risk-view").mock(
        return_value=httpx.Response(200, json={"tag_id": "tag1", "rows": [], "total": 0}),
    )
    client = MipitiClient()
    created = await client.create_tag("Scope", model_ids=["m1"])
    assert created["id"] == "tag1"
    listed = await client.list_tags()
    assert len(listed["tags"]) == 1
    added = await client.add_model_to_tag("tag1", "m1")
    assert added["model_ids"] == ["m1"]
    await client.remove_model_from_tag("tag1", "m1")
    rv = await client.get_tag_risk_view("tag1")
    assert rv["tag_id"] == "tag1"
    await client.close()


# ------------------------------------------------------------------
# import_controls: preview-job + build + confirm
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_start_import_preview_posts_to_preview_job(mock_env: None) -> None:
    """The preview runs as a background job: parse the structured controls_json
    into the `controls` array and POST to the preview-job endpoint, returning a
    job_id to poll. (Avoids a 30s silent request the MCP transport would drop.)"""
    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-1/controls/import/preview-job",
    ).mock(return_value=httpx.Response(200, json={"job_id": "job-import-1"}))

    client = MipitiClient()
    out = await client.start_import_preview(
        "tm-1", controls_json='[{"description": "X", "co_ids": ["CO-1"]}]',
    )
    await client.close()

    body = json.loads(route.calls.last.request.read().decode("utf-8"))
    assert "controls_json" not in body
    assert body["controls"] == [{"description": "X", "co_ids": ["CO-1"]}]
    assert out["job_id"] == "job-import-1"


def test_build_import_controls_drops_duplicates_and_applies_mappings() -> None:
    """build_import_controls turns a preview into the confirm payload: applies
    auto-mapped co_ids/mitigation_group and drops controls flagged as duplicates."""
    preview = {
        "parsed": [
            {"description": "Sign webhooks", "co_ids": ["CO-1"], "framework_refs": ["ASVS 5.3.1"]},
            {"description": "Dup of existing", "co_ids": ["CO-2"]},
        ],
        "mappings": [{"control_idx": 0, "co_ids": ["CO-1"], "mitigation_group": 1}],
        "duplicates": [{"import_idx": 1, "existing_ctrl_id": "CTRL-9", "match_type": "exact"}],
    }
    controls = MipitiClient.build_import_controls(preview)
    assert [c["description"] for c in controls] == ["Sign webhooks"]  # dup dropped
    assert controls[0]["co_ids"] == ["CO-1"]
    assert controls[0]["mitigation_group"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_import_confirm_posts_controls_list(mock_env: None) -> None:
    """The stateless confirm step persists the controls list (not an import id)."""
    route = respx.post(
        "https://test.api.mipiti.io/api/models/tm-1/controls/import/confirm",
    ).mock(return_value=httpx.Response(200, json={"imported": 1, "controls": []}))

    client = MipitiClient()
    result = await client.import_confirm(
        "tm-1", [{"description": "Sign webhooks", "co_ids": ["CO-1"]}], source_label="recovered",
    )
    await client.close()

    body = json.loads(route.calls.last.request.read().decode("utf-8"))
    assert "import_id" not in body
    assert body["controls"][0]["description"] == "Sign webhooks"
    assert body["source_label"] == "recovered"
    assert result.imported == 1

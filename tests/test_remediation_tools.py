"""Unit tests for preview_finding_remediation and apply_finding_remediation tools."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import (
    apply_finding_remediation,
    build_instructions,
    preview_finding_remediation,
)


# ------------------------------------------------------------------
# Tool-level tests (mock the MipitiClient)
# ------------------------------------------------------------------


class TestPreviewFindingRemediation:
    @pytest.mark.asyncio
    async def test_calls_client_with_finding_id(self) -> None:
        """The tool must forward finding_id to the client and return
        the server envelope verbatim — the diff shape is server-driven
        and varies by finding kind."""
        diff = {
            "finding_id": "F-1",
            "kind": "structural_duplicate_controls",
            "model_id": "tm-001",
            "keep_control_id": "CTRL-01",
            "drop_control_ids": ["CTRL-07"],
            "merged_co_ids": ["CO1", "CO3"],
            "merged_framework_refs": ["soc2:CC6.1"],
        }
        client = AsyncMock()
        client.preview_finding_remediation = AsyncMock(return_value=diff)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await preview_finding_remediation(
                server_version="0", finding_id="F-1",
            )
        client.preview_finding_remediation.assert_awaited_once_with("F-1")
        assert result == diff

    @pytest.mark.asyncio
    async def test_404_wrapped_as_tool_error(self) -> None:
        """Non-existent finding surfaces as a clean ToolError, not a
        raw httpx exception — the agent surface stays uniform."""
        request = httpx.Request("GET", "http://x/api/findings/F-X/remediation/preview")
        response = httpx.Response(404, json={"detail": "Finding not found"}, request=request)
        client = AsyncMock()
        client.preview_finding_remediation = AsyncMock(
            side_effect=httpx.HTTPStatusError("not found", request=request, response=response),
        )
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="404"):
                await preview_finding_remediation(
                    server_version="0", finding_id="F-X",
                )


def _mock_ctx() -> AsyncMock:
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()
    return ctx


class TestApplyFindingRemediation:
    @pytest.mark.asyncio
    async def test_calls_client_with_justification(self) -> None:
        result_envelope = {
            "finding_id": "F-1",
            "applied": True,
            "kind": "structural_duplicate_controls",
            "kept_control_id": "CTRL-01",
            "dropped_control_ids": ["CTRL-07"],
        }
        client = AsyncMock()
        # Runs as a background job: start it, then poll to completion.
        client.start_apply_finding_remediation = AsyncMock(return_value={"job_id": "job-rem"})
        client.get_operation = AsyncMock(
            return_value={"status": "completed", "result": result_envelope},
        )
        ctx = _mock_ctx()
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await apply_finding_remediation(
                server_version="0",
                finding_id="F-1",
                justification="cleaning up pre-fix trigger duplicates",
                ctx=ctx,
            )
        client.start_apply_finding_remediation.assert_awaited_once_with(
            "F-1", "cleaning up pre-fix trigger duplicates",
        )
        assert result == result_envelope

    @pytest.mark.asyncio
    async def test_empty_justification_rejected_locally(self) -> None:
        """The tool rejects empty/whitespace justification before any
        HTTP call — the audit trail requires a real operator rationale,
        and refusing locally avoids a wasted round-trip on the obvious
        misuse."""
        client = AsyncMock()
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="justification is required"):
                await apply_finding_remediation(
                    server_version="0", finding_id="F-1", justification="", ctx=_mock_ctx(),
                )
            with pytest.raises(ToolError, match="justification is required"):
                await apply_finding_remediation(
                    server_version="0", finding_id="F-1", justification="   ", ctx=_mock_ctx(),
                )
        client.start_apply_finding_remediation.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_409_already_remediated_wrapped_as_tool_error(self) -> None:
        """Conflict (already remediated/dismissed) surfaces with the
        server's detail intact so the agent can react (e.g., reload
        list_findings)."""
        request = httpx.Request("POST", "http://x/api/findings/F-1/remediation/apply-job")
        response = httpx.Response(
            409, json={"detail": "Finding already remediated"}, request=request,
        )
        client = AsyncMock()
        client.start_apply_finding_remediation = AsyncMock(
            side_effect=httpx.HTTPStatusError("conflict", request=request, response=response),
        )
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="409"):
                await apply_finding_remediation(
                    server_version="0",
                    finding_id="F-1",
                    justification="retry after race",
                    ctx=_mock_ctx(),
                )


# ------------------------------------------------------------------
# Client-level HTTP wiring (verifies path + method)
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_client_preview_uses_get_on_preview_path(mock_env: None) -> None:
    """preview_finding_remediation must hit
    GET /api/findings/{id}/remediation/preview — no body, no idempotency
    key, no mutation."""
    route = respx.get(
        "https://test.api.mipiti.io/api/findings/F-1/remediation/preview",
    ).mock(return_value=httpx.Response(200, json={"finding_id": "F-1", "kind": "k"}))
    client = MipitiClient()
    data = await client.preview_finding_remediation("F-1")
    assert route.called
    assert data["finding_id"] == "F-1"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_client_apply_uses_post_with_justification_body(mock_env: None) -> None:
    """start_apply_finding_remediation must hit
    POST /api/findings/{id}/remediation/apply-job with the justification
    in the body, carry an Idempotency-Key (mutating call), and return the
    {job_id} envelope to poll."""
    route = respx.post(
        "https://test.api.mipiti.io/api/findings/F-1/remediation/apply-job",
    ).mock(return_value=httpx.Response(200, json={"job_id": "job-rem"}))
    client = MipitiClient()
    data = await client.start_apply_finding_remediation("F-1", "rationale here")
    assert route.called
    sent = route.calls.last.request
    body = sent.read().decode("utf-8")
    assert "rationale here" in body
    assert "justification" in body
    assert sent.headers.get("Idempotency-Key"), "mutating call must carry Idempotency-Key"
    assert data["job_id"] == "job-rem"
    await client.close()


# ------------------------------------------------------------------
# Instructions block presence
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("organization", "user"),
        ("enterprise", "user"),
        ("developer", "admin"),
        ("developer", "superadmin"),
        ("developer", "user"),
    ],
)
def test_remediation_section_present_for_every_tier(tier: str, role: str) -> None:
    """The remediation guidance lives in _INSTRUCTIONS_BASE so every
    tier/role combo (including the developer free tier that excludes
    compliance) gets it. Mirrors the constraint-flow visibility
    decision — structural-drift findings can fire for any tier and the
    preview-then-apply norm must travel with the tools."""
    text = build_instructions(tier=tier, role=role)
    assert "## Remediating findings (structural drift)" in text
    assert "preview_finding_remediation" in text
    assert "apply_finding_remediation" in text
    assert "Never apply remediation without preview" in text


def test_remediation_section_describes_preview_then_apply_flow() -> None:
    """The four-step flow must be discoverable inside the section
    itself (not buried in a tool docstring), so reading instructions
    alone tells the agent the norm."""
    text = build_instructions("pro", "user")
    section_start = text.index("## Remediating findings (structural drift)")
    section_end = text.index("## Project setup", section_start)
    section = text[section_start:section_end]

    assert "preview_finding_remediation(finding_id)" in section
    assert "SHOW THE OPERATOR THE DIFF" in section
    assert "one-line rationale" in section
    assert "apply_finding_remediation(finding_id, justification=" in section

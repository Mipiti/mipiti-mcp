"""Tool pass-throughs for the attacker surface extent."""

from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mipiti_mcp.server import (
    add_attacker,
    edit_attacker,
)


def _client(**overrides):
    client = AsyncMock()
    client.start_add_attacker = AsyncMock(return_value={"job_id": "job-add"})
    client.start_edit_attacker = AsyncMock(return_value={"job_id": "job-edit"})
    client.get_operation = AsyncMock(return_value={"status": "completed", "result": {
        "model": {"id": "tm-001", "attackers": [{"id": "T1"}]},
    }})
    for name, value in overrides.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


def _ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()
    return ctx


def _patch(client):
    return patch("mipiti_mcp.server._get_client", return_value=client)


class TestAddAttackerSurfaceExtent:
    async def test_forwards_a_declared_extent(self):
        client = _client()
        with _patch(client):
            await add_attacker(
                server_version="0", model_id="tm-001", capability="From the internet, can call any endpoint",
                surface_extent="whole", ctx=_ctx(),
            )
        assert client.start_add_attacker.await_args.kwargs["surface_extent"] == "whole"

    async def test_omitted_extent_is_not_sent(self):
        client = _client()
        with _patch(client):
            await add_attacker(server_version="0", model_id="tm-001", capability="c", ctx=_ctx())
        assert "surface_extent" not in client.start_add_attacker.await_args.kwargs

    async def test_an_unknown_extent_is_refused_before_sending(self):
        client = _client()
        with _patch(client):
            with pytest.raises(ToolError, match="surface_extent"):
                await add_attacker(
                    server_version="0", model_id="tm-001", capability="c",
                    surface_extent="everything", ctx=_ctx(),
                )
        client.start_add_attacker.assert_not_awaited()


class TestEditAttackerSurfaceExtent:
    async def test_extent_requires_a_change_reason(self):
        client = _client()
        with _patch(client):
            with pytest.raises(ToolError, match="change_reason"):
                await edit_attacker(
                    server_version="0", model_id="tm-001", attacker_id="T1",
                    surface_extent="point", ctx=_ctx(),
                )
            with pytest.raises(ToolError, match="change_reason"):
                await edit_attacker(
                    server_version="0", model_id="tm-001", attacker_id="T1",
                    attest_surface_extent=True, ctx=_ctx(),
                )
        client.start_edit_attacker.assert_not_awaited()

    async def test_forwards_extent_attestation_and_reason(self):
        client = _client()
        with _patch(client):
            await edit_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
                surface_extent="point", change_reason="Only the /health endpoint is reachable",
                ctx=_ctx(),
            )
        kwargs = client.start_edit_attacker.await_args.kwargs
        assert kwargs["surface_extent"] == "point"
        assert kwargs["change_reason"].startswith("Only")
        assert "attest_surface_extent" not in kwargs

    async def test_forwards_attest_without_a_value(self):
        client = _client()
        with _patch(client):
            await edit_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
                attest_surface_extent=True, change_reason="Confirmed the generated extent",
                ctx=_ctx(),
            )
        kwargs = client.start_edit_attacker.await_args.kwargs
        assert kwargs["attest_surface_extent"] is True
        assert "surface_extent" not in kwargs

    async def test_an_unknown_extent_is_refused(self):
        client = _client()
        with _patch(client):
            with pytest.raises(ToolError, match="surface_extent"):
                await edit_attacker(
                    server_version="0", model_id="tm-001", attacker_id="T1",
                    surface_extent="all", change_reason="reason enough", ctx=_ctx(),
                )
        client.start_edit_attacker.assert_not_awaited()

    async def test_identity_edits_still_need_no_reason(self):
        client = _client()
        with _patch(client):
            out = await edit_attacker(
                server_version="0", model_id="tm-001", attacker_id="T1",
                capability="Updated", ctx=_ctx(),
            )
        assert "model" in out

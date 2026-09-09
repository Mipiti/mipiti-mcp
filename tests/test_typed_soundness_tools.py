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
                surface_extent="whole", change_reason="Every endpoint is on the public listener",
                ctx=_ctx(),
            )
        kwargs = client.start_add_attacker.await_args.kwargs
        assert kwargs["surface_extent"] == "whole"
        assert kwargs["change_reason"].startswith("Every endpoint")

    async def test_a_declared_extent_needs_a_reason(self):
        """The extent decides whether the objectives this attacker anchors are
        for-all obligations, so the create records the declaration with its
        reason, exactly as an edit does. Without one the API refuses the
        create; refusing here spends no model version and says the same."""
        client = _client()
        with _patch(client):
            with pytest.raises(ToolError, match="change_reason"):
                await add_attacker(
                    server_version="0", model_id="tm-001", capability="c",
                    surface_extent="whole", ctx=_ctx(),
                )
        client.start_add_attacker.assert_not_awaited()

    async def test_a_narrowing_is_not_declarable_on_a_create(self):
        """``point`` is a statement about the objectives the attacker anchors,
        and a create has none: they are derived from the attacker afterwards.
        The narrowing belongs on the edit, where it is checked."""
        client = _client()
        with _patch(client):
            with pytest.raises(ToolError, match="edit_attacker"):
                await add_attacker(
                    server_version="0", model_id="tm-001", capability="c",
                    surface_extent="point", change_reason="Only /health is exposed",
                    ctx=_ctx(),
                )
        client.start_add_attacker.assert_not_awaited()

    async def test_a_reason_without_an_extent_still_creates(self):
        client = _client()
        with _patch(client):
            await add_attacker(
                server_version="0", model_id="tm-001", capability="c",
                change_reason="noted", ctx=_ctx(),
            )
        assert "surface_extent" not in client.start_add_attacker.await_args.kwargs

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

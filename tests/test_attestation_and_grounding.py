"""Attestations as judgments, the grounds an entity lacks, and the scope a
build start names: what the client sends and what the tools publish."""

import asyncio
import inspect
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient
from mipiti_mcp.types import ThreatModel

from .conftest import SAMPLE_THREAT_MODEL

BASE = "https://test.api.mipiti.io/api/models/tm-1"


def _patch_client(mock):
    return patch("mipiti_mcp.server._get_client", return_value=mock)


def _ctx() -> AsyncMock:
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _flat(text: str) -> str:
    return " ".join(text.split())


def _doc(name: str) -> str:
    fn = getattr(server, name)
    return _flat((getattr(fn, "__doc__", "") or "") + " " + (
        getattr(getattr(fn, "fn", None), "__doc__", "") or ""))


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_the_model_read_asks_for_the_completeness_record_only_when_named(
        mock_env: None) -> None:
    body = dict(SAMPLE_THREAT_MODEL, inventory_completeness={
        "bounded_by": ["T1"],
        "grounding_gaps": {"T1": [{"ground": "privileges", "detail": "d", "acts": []}]}})
    route = respx.get(BASE).mock(return_value=httpx.Response(200, json=body))
    client = MipitiClient()
    await client.get_model("tm-1")
    assert "include" not in route.calls.last.request.url.params
    model = await client.get_model("tm-1", include="inventory_completeness")
    assert route.calls.last.request.url.params["include"] == "inventory_completeness"
    assert model.model_dump()["inventory_completeness"]["grounding_gaps"]["T1"][0][
        "ground"] == "privileges"


@pytest.mark.asyncio
async def test_a_version_read_takes_no_include(mock_env: None) -> None:
    with pytest.raises(ValueError, match="latest version"):
        await MipitiClient().get_model("tm-1", 3, include="inventory_completeness")


@pytest.mark.asyncio
@respx.mock
async def test_a_start_sends_the_scope_only_when_named(mock_env: None) -> None:
    route = respx.post(f"{BASE}/controls/build").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "started": True, "job_id": "j-1"}))
    client = MipitiClient()
    await client.start_control_build("tm-1", model_version=4, set_revision=0,
                                     confirm_estimate=True)
    assert "scope_revision" not in json.loads(route.calls.last.request.content)
    await client.start_control_build("tm-1", model_version=4, set_revision=0,
                                     confirm_estimate=True, scope_revision="ab12")
    assert json.loads(route.calls.last.request.content) == {
        "confirm_estimate": True, "model_version": 4, "set_revision": 0,
        "scope_revision": "ab12"}


@pytest.mark.asyncio
@respx.mock
async def test_a_stale_scope_is_returned_as_data(mock_env: None) -> None:
    respx.post(f"{BASE}/controls/build").mock(return_value=httpx.Response(
        409, json={"detail": {"code": "review_stale", "scope_revision": "cd34"}}))
    out = await MipitiClient().start_control_build(
        "tm-1", model_version=4, set_revision=0, confirm_estimate=True,
        scope_revision="ab12")
    assert out == {"started": False, "http_status": 409, "code": "review_stale",
                   "scope_revision": "cd34"}


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_model_tool_inlines_the_record_when_asked() -> None:
    mock = AsyncMock()
    mock.get_model = AsyncMock(return_value=ThreatModel.model_validate(
        dict(SAMPLE_THREAT_MODEL, inventory_completeness={"grounding_gaps": {}})))
    with _patch_client(mock):
        out = await server.get_threat_model(
            server_version="0", model_id="tm-1", include_inventory_completeness=True)
    mock.get_model.assert_awaited_once_with("tm-1", None, include="inventory_completeness")
    assert out["inventory_completeness"] == {"grounding_gaps": {}}


@pytest.mark.asyncio
async def test_the_model_tool_refuses_a_version_with_the_record() -> None:
    mock = AsyncMock()
    with _patch_client(mock), pytest.raises(ToolError, match="latest version"):
        await server.get_threat_model(server_version="0", model_id="tm-1", version=2,
                                      include_inventory_completeness=True)
    mock.get_model.assert_not_awaited()


@pytest.mark.asyncio
async def test_attesting_privileges_is_sent_with_its_reason() -> None:
    mock = AsyncMock()
    mock.start_edit_attacker = AsyncMock(return_value={"job_id": "j"})
    mock.get_operation = AsyncMock(return_value={"status": "completed", "result": {
        "model": {"id": "tm-1"},
        "attestation": {"status": "escalated", "escalation_id": "p-1", "decisions": []}}})
    with _patch_client(mock):
        out = await server.edit_attacker(
            server_version="0", model_id="tm-1", attacker_id="T1", ctx=_ctx(),
            attest_privileges=True, change_reason="no login on this path")
    kwargs = mock.start_edit_attacker.await_args.kwargs
    assert kwargs["attest_privileges"] is True
    assert kwargs["change_reason"] == "no login on this path"
    assert out["attestation"]["escalation_id"] == "p-1"


@pytest.mark.asyncio
async def test_attesting_privileges_without_a_reason_is_refused_before_the_call() -> None:
    mock = AsyncMock()
    with _patch_client(mock), pytest.raises(ToolError, match="change_reason"):
        await server.edit_attacker(server_version="0", model_id="tm-1",
                                   attacker_id="T1", ctx=_ctx(), attest_privileges=True)
    mock.start_edit_attacker.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_start_tool_passes_the_scope_it_was_given() -> None:
    mock = AsyncMock()
    mock.start_control_build = AsyncMock(return_value={"started": True})
    with _patch_client(mock):
        await server.start_control_build(
            server_version="0", model_id="tm-1", ctx=_ctx(), model_version=3,
            set_revision=1, confirm_estimate=True, scope_revision="ab12")
    mock.start_control_build.assert_awaited_once_with(
        "tm-1", model_version=3, set_revision=1, confirm_estimate=True,
        scope_revision="ab12")


@pytest.mark.parametrize("decision", ["seal_attested", "position_attested",
                                      "privileges_attested", "extent_attested"])
def test_the_ledger_filter_takes_each_attestation(decision: str) -> None:
    mock = AsyncMock()
    mock.list_decisions = AsyncMock(return_value={"items": []})
    with _patch_client(mock):
        asyncio.run(server.list_decisions(server_version="0", model_id="tm-1",
                                          decision=decision))
    assert mock.list_decisions.await_args.kwargs["decision"] == decision


# ---------------------------------------------------------------------------
# What the published text says
# ---------------------------------------------------------------------------


def test_a_refused_attestation_is_published_as_landing_unattested() -> None:
    """A program refused an attestation keeps its edit and gets the
    escalation in the answer, never a 403. Text that says the edit attests
    would have it report a seal or a position that does not stand; text
    that says it is refused would have it retry, or route around."""
    for name in ("edit_attacker", "edit_trust_boundary"):
        doc = _doc(name)
        assert "never a 403" in doc, name
        assert "escalation_id" in doc, name
    flat = _flat(server.build_instructions("pro", "user"))
    assert "is not given a 403" in flat
    for decision in ("seal_attested", "position_attested", "privileges_attested",
                     "extent_attested"):
        assert decision in flat, decision


def test_no_published_text_says_an_edit_attests_whoever_makes_it() -> None:
    """Supplying an extent or setting a seal attests it only for a person or
    a delegated program."""
    source = _flat(inspect.getsource(server))
    for claim in ("Supplying it attests it", "Setting it records an operator attestation",
                  "Changing it operator-attests the position",
                  "Recorded as attested by this call"):
        assert claim not in source, claim


def test_the_grounding_gaps_are_published_with_their_acts() -> None:
    doc = _doc("get_threat_model")
    assert "grounding_gaps" in doc and "mcp_tool" in doc and "fields" in doc
    assert "include_inventory_completeness" in _flat(server.build_instructions("pro", "user"))


def test_the_start_names_three_values_wherever_it_is_explained() -> None:
    """A start that does not name the scope is not checked against it, so
    every text that tells an agent what a start names says all three."""
    for name in ("start_control_build", "get_control_generation_status",
                 "generate_threat_model", "regenerate_controls"):
        assert "scope_revision" in _doc(name), name
    assert "scope_revision" in _flat(server.build_instructions("pro", "user"))


def test_the_status_tool_names_every_state_of_the_diagnosis() -> None:
    doc = _doc("get_control_generation_status")
    for state in ("no_control", "awaiting_attestation", "mitigated_elsewhere",
                  "excluded_cos", "dispositioned_cos", "awaiting_judgement_cos",
                  "pending_attestations", "flagged_entities"):
        assert state in doc, state

"""A model read and a write's answer fit what a client takes, and say what
they left out.

Returned whole, every read and every entity write of a large model fills an
agent's context with a model it did not ask to read. So the read leaves out the answers to the model's questions
unless asked, cuts past a bound and names each cut with the read that serves
it, and a write answers with the model's name and the records it wrote.
"""

from __future__ import annotations

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

BASE = "https://test.api.mipiti.io/api/models/tm-1/inventory"


def _ctx() -> AsyncMock:
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _client(**methods: object) -> AsyncMock:
    client = AsyncMock()
    for name, value in methods.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


def _clarifications(n: int) -> list[dict]:
    return [{"question_id": f"q{i}", "answer": f"Answer {i}."} for i in range(n)]


def _large_model(assets: int, attackers: int, clarifications: int = 0) -> dict:
    """A synthetic model whose inventory is large enough to pass the bound."""
    filler = "x" * 1500
    return dict(
        SAMPLE_THREAT_MODEL,
        assets=[{"id": f"A-{i:03d}", "name": f"Asset {i}", "description": filler,
                 "security_properties": ["C"], "deleted": i == 0}
                for i in range(assets)],
        attackers=[{"id": f"T-{i:03d}", "capability": f"From zone {i}, the attacker can "
                    "read records.", "likelihood_rationale": filler}
                   for i in range(attackers)],
        control_objectives=[{"id": f"CO{i}", "asset_id": "A-001", "attacker_id": "T-001",
                             "statement": filler} for i in range(40)],
        clarifications=_clarifications(clarifications),
    )


async def _read(model: dict, **kwargs) -> dict:
    client = _client(get_model=ThreatModel.model_validate(model))
    with patch("mipiti_mcp.server._get_client", return_value=client):
        return await server.get_threat_model(server_version="0", model_id="tm-1", **kwargs)


# ------------------------------------------------------------------
# The model read
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_answers_to_the_questions_are_counted_and_left_out() -> None:
    out = await _read(dict(SAMPLE_THREAT_MODEL, clarifications=_clarifications(3)))
    assert out["clarification_count"] == 3
    assert "clarifications" not in out and "cuts" not in out


@pytest.mark.asyncio
async def test_the_answers_are_paged_when_asked() -> None:
    model = dict(SAMPLE_THREAT_MODEL, clarifications=_clarifications(120))
    first = await _read(model, include_clarifications=True)
    assert [c["question_id"] for c in first["clarifications"]][:2] == ["q0", "q1"]
    assert len(first["clarifications"]) == 50 and first["clarifications_next_offset"] == 50
    last = await _read(model, include_clarifications=True, clarifications_offset=100)
    assert len(last["clarifications"]) == 20 and last["clarifications_next_offset"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{"clarifications_offset": -1},
                                    {"clarifications_limit": 0},
                                    {"clarifications_limit": 201}])
async def test_a_page_outside_the_bounds_is_refused_before_the_call(kwargs) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="clarifications"):
            await server.get_threat_model(server_version="0", model_id="tm-1", **kwargs)
    client.get_model.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_read_within_the_bound_is_returned_whole() -> None:
    out = await _read(_large_model(assets=10, attackers=5), include_cos=True)
    assert len(out["control_objectives"]) == 40
    assert out["assets"][1]["description"] == "x" * 1500
    assert "cuts" not in out


@pytest.mark.asyncio
async def test_a_read_past_the_bound_cuts_in_order_and_says_so() -> None:
    """The collections are compacted before the page of answers asked for is
    dropped: an entity is read whole with get_entity, the answers by no other
    read."""
    out = await _read(_large_model(assets=150, attackers=40, clarifications=60),
                      include_cos=True, include_clarifications=True)
    assert len(json.dumps(out)) <= server._MODEL_READ_MAX_CHARS
    fields = [c["field"] for c in out["cuts"]]
    assert fields[:2] == ["control_objectives", "assets"]
    assert "control_objectives" not in out
    # Compacting was enough: the page of answers asked for is served.
    assert "clarifications" not in fields
    assert len(out["clarifications"]) == 50 and out["clarifications_next_offset"] == 50
    assert out["clarification_count"] == 60
    # Every asset is still named, its text read whole with get_entity.
    assert len(out["assets"]) == 150
    assert out["assets"][0] == {"id": "A-000", "name": "Asset 0",
                                "security_properties": ["C"], "deleted": True}
    assert out["assets"][1] == {"id": "A-001", "name": "Asset 1",
                                "security_properties": ["C"]}
    assets_cut = next(c for c in out["cuts"] if c["field"] == "assets")
    assert assets_cut["compacted"] == 150 and assets_cut["read_with"] == "get_entity"
    # Compacting the assets was enough: the attackers are as sent.
    assert out["attackers"][0]["likelihood_rationale"] == "x" * 1500


@pytest.mark.asyncio
async def test_the_largest_collection_is_compacted_first() -> None:
    out = await _read(_large_model(assets=20, attackers=160))
    assert [c["field"] for c in out["cuts"]] == ["attackers"]
    assert out["attackers"][5] == {"id": "T-005",
                                   "capability": "From zone 5, the attacker can read records."}
    assert out["assets"][1]["description"] == "x" * 1500


def test_the_answers_are_dropped_only_when_compacting_is_not_enough() -> None:
    long_answer = "y" * 4000
    read = {"id": "m",
            "assets": [{"id": f"A{i}", "name": "n", "description": "d" * 3000}
                       for i in range(20)],
            "clarifications": [{"question_id": f"q{i}", "answer": long_answer}
                               for i in range(60)],
            "clarifications_next_offset": 60}
    cut = server._bounded_model(read)
    assert [c["field"] for c in cut["cuts"]] == ["assets", "clarifications"]
    assert "clarifications" not in cut and "clarifications_next_offset" not in cut
    assert next(c for c in cut["cuts"] if c["field"] == "clarifications")["omitted"] == 60


def test_the_bound_is_measured_on_what_it_returns() -> None:
    """The reader must see a read past the bound, or a test above passes on a
    read it never measured."""
    small = {"id": "m", "assets": [{"id": "A1", "name": "n", "description": "d"}]}
    assert server._bounded_model(small) is small
    big = {"id": "m", "assets": [{"id": f"A{i}", "name": "n", "description": "d" * 3000}
                                 for i in range(100)]}
    cut = server._bounded_model(big)
    assert cut["cuts"][0]["field"] == "assets"
    assert all(set(a) == {"id", "name"} for a in cut["assets"])


# ------------------------------------------------------------------
# A write's answer
# ------------------------------------------------------------------


def _envelope(**extra) -> dict:
    """The entity write's answer as the API sends it: the whole model, the
    carry, and ``added`` naming what the write created."""
    model = dict(SAMPLE_THREAT_MODEL, version=2, assets=[
        *SAMPLE_THREAT_MODEL["assets"],
        {"id": "A-03", "name": "API Keys", "security_properties": ["C"]}])
    return {"model": model, "controls_carried": 3, "controls_orphaned": 0,
            "orphaned_control_ids": [], **extra}


@pytest.mark.asyncio
async def test_an_add_answers_with_the_model_named_and_the_entity_it_created() -> None:
    client = _client(start_add_asset={"job_id": "j"},
                     get_operation={"status": "completed",
                                    "result": _envelope(added={"assets": ["A-03"]})})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.add_asset(server_version="0", model_id="tm-1",
                                     name="API Keys", ctx=_ctx())
    assert out["model"] == {"id": "tm-001", "version": 2, "title": "User Login OAuth"}
    assert out["entities"] == {"assets": [
        {"id": "A-03", "name": "API Keys", "security_properties": ["C"]}]}
    assert (out["controls_carried"], out["added"]) == (3, {"assets": ["A-03"]})


@pytest.mark.asyncio
async def test_an_edit_answers_with_the_entity_it_named() -> None:
    client = _client(start_edit_attacker={"job_id": "j"},
                     get_operation={"status": "completed", "result": _envelope(
                         attestation={"status": "escalated", "escalation_id": "E-1"})})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.edit_attacker(server_version="0", model_id="tm-1",
                                         attacker_id="T1", capability="c", ctx=_ctx())
    assert [t["id"] for t in out["entities"]["attackers"]] == ["T1"]
    assert out["attestation"]["escalation_id"] == "E-1"
    assert set(out["model"]) == {"id", "version", "title"}


@pytest.mark.asyncio
async def test_an_add_that_restored_names_the_entity_it_restored() -> None:
    client = _client(start_add_asset={"job_id": "j"},
                     get_operation={"status": "completed", "result": _envelope(
                         auto_restored=True, restored_asset_id="A2")})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.add_asset(server_version="0", model_id="tm-1",
                                     name="Credentials", ctx=_ctx())
    assert [a["id"] for a in out["entities"]["assets"]] == ["A2"]
    assert out["auto_restored"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("entity_type,entity_id,collection", [
    ("asset", "A1", "assets"), ("attacker", "T1", "attackers"),
    ("trust_boundary", "TB1", "trust_boundaries"), ("assumption", "AS1", "assumptions")])
async def test_a_removal_and_a_restore_answer_with_the_entity(
        entity_type: str, entity_id: str, collection: str) -> None:
    restorer = {"asset": "restore_asset", "attacker": "restore_attacker",
                "trust_boundary": "restore_trust_boundary",
                "assumption": "restore_assumption"}[entity_type]
    client = _client(start_remove_entity={"job_id": "j"},
                     get_operation={"status": "completed", "result": _envelope()},
                     **{restorer: _envelope()})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        removed = await server.remove_entity(server_version="0", model_id="tm-1",
                                             entity_type=entity_type, entity_id=entity_id,
                                             ctx=_ctx())
        restored = await server.restore_entity(server_version="0", model_id="tm-1",
                                               entity_type=entity_type, entity_id=entity_id)
    for out in (removed, restored):
        assert [e["id"] for e in out["entities"][collection]] == [entity_id]
        assert "assets" not in out["model"]


@pytest.mark.asyncio
async def test_a_component_boundary_and_assumption_write_answer_alike() -> None:
    model = dict(SAMPLE_THREAT_MODEL, components=[{"id": "CMP-01", "name": "api"}])
    answer = {"model": model, "controls_carried": 0, "added": {"components": ["CMP-01"]}}
    client = _client(add_component=answer, add_trust_boundary=_envelope(),
                     edit_assumption=_envelope())
    with patch("mipiti_mcp.server._get_client", return_value=client):
        component = await server.add_component(server_version="0", model_id="tm-1",
                                               name="api")
        boundary = await server.add_trust_boundary(server_version="0", model_id="tm-1",
                                                   description="d")
        assumption = await server.edit_assumption(server_version="0", model_id="tm-1",
                                                  assumption_id="AS1", description="d")
    assert component["entities"] == {"components": [{"id": "CMP-01", "name": "api"}]}
    assert boundary["entities"] == {} and boundary["model"]["id"] == "tm-001"
    assert [a["id"] for a in assumption["entities"]["assumptions"]] == ["AS1"]


@pytest.mark.asyncio
async def test_an_answer_with_no_model_is_returned_as_sent() -> None:
    rejection = {"accepted": False, "classification": "similar",
                 "candidate_restore_id": "A-04"}
    client = _client(start_add_asset={"job_id": "j"},
                     get_operation={"status": "completed", "result": rejection})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.add_asset(server_version="0", model_id="tm-1", name="x",
                                     ctx=_ctx())
    assert out == rejection


def test_every_write_that_carries_a_model_names_it_instead() -> None:
    """The reduction is applied by every tool whose answer embeds a model; a
    tool left out would fill a context the others keep small."""
    import inspect

    def body(name: str) -> str:
        tool = getattr(server, name)
        return inspect.getsource(getattr(tool, "fn", tool))
    for tool in ("add_asset", "edit_asset", "add_attacker", "edit_attacker",
                 "remove_entity", "restore_entity", "add_component", "edit_component",
                 "add_trust_boundary", "edit_trust_boundary", "add_assumption",
                 "edit_assumption", "assign_to_components"):
        assert "_entity_change(" in body(tool), tool
    for tool in ("decide_reconciliation_candidate", "lift_composition_entity",
                 "split_composition_entity", "undo_composition_event",
                 "revalidate_entity_quality"):
        assert "_without_models(" in body(tool), tool


# ------------------------------------------------------------------
# Inventory judgements
# ------------------------------------------------------------------


def _body(route) -> dict:
    return json.loads(route.calls.last.request.content)


@pytest.mark.asyncio
@respx.mock
async def test_the_inventory_tools_reach_their_routes(mock_env: None) -> None:
    client = MipitiClient()
    read = respx.get(BASE + "/judgements").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "duplicates": {}, "tags": {}}))
    assert (await client.get_inventory_judgements("tm-1"))["model_id"] == "tm-1"
    assert read.called
    request = respx.post(BASE + "/judgements/request").mock(return_value=httpx.Response(
        200, json={"queued": {"duplicate": 2}}))
    await client.request_inventory_checks("tm-1")
    assert request.called
    pair = respx.post(BASE + "/pairs").mock(return_value=httpx.Response(
        200, json={"verdict": "same"}))
    await client.decide_inventory_pair("tm-1", "asset", "A-1", "A-2", "same", "One store.")
    assert _body(pair) == {"entity_kind": "asset", "a": "A-1", "b": "A-2",
                           "verdict": "same", "rationale": "One store."}
    tags = respx.post(BASE + "/tags").mock(return_value=httpx.Response(
        200, json={"tags": []}))
    await client.declare_inventory_tags("tm-1", "attacker", "T-4",
                                        [{"primitive": "p", "implied_type": "t"}])
    assert _body(tags) == {"entity_kind": "attacker", "entity_id": "T-4",
                           "tags": [{"primitive": "p", "implied_type": "t"}],
                           "rationale": ""}


@pytest.mark.asyncio
async def test_the_inventory_tools_forward_what_they_were_given() -> None:
    client = _client(get_inventory_judgements={"duplicates": {}},
                     request_inventory_checks={"queued": {}},
                     decide_inventory_pair={"verdict": "different"},
                     declare_inventory_tags={"tags": []})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.get_inventory_judgements(server_version="0", model_id="tm-1")
        await server.request_inventory_checks(server_version="0", model_id="tm-1")
        await server.decide_inventory_pair(server_version="0", model_id="tm-1",
                                           entity_kind="asset", a=" A-1 ", b="A-2",
                                           verdict="different", rationale="Two stores.")
        await server.declare_inventory_tags(
            server_version="0", model_id="tm-1", entity_kind="asset", entity_id=" A-1 ",
            tags='[{"primitive": "p", "implied_type": "t"}]')
    client.get_inventory_judgements.assert_awaited_once_with("tm-1")
    client.request_inventory_checks.assert_awaited_once_with("tm-1")
    client.decide_inventory_pair.assert_awaited_once_with(
        "tm-1", "asset", "A-1", "A-2", "different", rationale="Two stores.")
    client.declare_inventory_tags.assert_awaited_once_with(
        "tm-1", "asset", "A-1", [{"primitive": "p", "implied_type": "t"}], rationale="")


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,kwargs", [
    ("decide_inventory_pair", {"entity_kind": "component", "a": "A", "b": "B",
                               "verdict": "same"}),
    ("decide_inventory_pair", {"entity_kind": "asset", "a": "A", "b": "B",
                               "verdict": "maybe"}),
    ("decide_inventory_pair", {"entity_kind": "asset", "a": " ", "b": "B",
                               "verdict": "same"}),
    ("decide_inventory_pair", {"entity_kind": "asset", "a": "A", "b": "B",
                               "verdict": "same", "rationale": "x" * 2001}),
    ("declare_inventory_tags", {"entity_kind": "asset", "entity_id": "A",
                                "tags": "nope"}),
    ("declare_inventory_tags", {"entity_kind": "asset", "entity_id": "A",
                                "tags": '[{"primitive": "p"}]'}),
    ("declare_inventory_tags", {"entity_kind": "asset", "entity_id": " ", "tags": "[]"}),
])
async def test_an_inventory_act_the_api_would_refuse_is_refused_before_the_call(
        tool: str, kwargs: dict) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await getattr(server, tool)(server_version="0", model_id="tm-1", **kwargs)
    client.decide_inventory_pair.assert_not_awaited()
    client.declare_inventory_tags.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_programs_refused_decision_names_its_escalation() -> None:
    request = httpx.Request("POST", "http://x/pairs")
    refusal = httpx.HTTPStatusError("refused", request=request, response=httpx.Response(
        403, json={"detail": {"code": "delegation_required", "escalation_id": "E-7"}},
        request=request))
    client = AsyncMock()
    client.decide_inventory_pair = AsyncMock(side_effect=refusal)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="403.*E-7"):
            await server.decide_inventory_pair(
                server_version="0", model_id="tm-1", entity_kind="asset", a="A-1",
                b="A-2", verdict="same")


def test_the_inventory_tools_are_published_with_their_rules() -> None:
    import asyncio
    tools = {t.name: t.description or "" for t in asyncio.run(server.mcp.list_tools())}
    for code in ("``two_elements``", "``inventory_pair_decided``", "nothing is merged"):
        assert code in " ".join(tools["decide_inventory_pair"].split()), code
    assert "``inadmissible_tag``" in tools["declare_inventory_tags"]
    assert "its own request" in " ".join(tools["request_inventory_checks"].split())
    instructions = server.build_instructions("pro", "user")
    for name in ("get_inventory_judgements", "request_inventory_checks",
                 "decide_inventory_pair", "declare_inventory_tags"):
        assert f"`{name}`" in instructions, name

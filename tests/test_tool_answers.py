"""Tools report what the platform did, and name only tools that exist.

A refine that could not apply, or a question the platform handled as a change,
is reported as that, never as a model with no id or an empty answer. A tool
the instructions point an agent at must be one the server registers: an agent
told to call a name that is not there has no way to do what it was told.
"""

from __future__ import annotations

import asyncio
import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from mipiti_mcp import server
from mipiti_mcp.types import ChatResponse, GenerateResult, ThreatModel

from .conftest import SAMPLE_THREAT_MODEL


class _Ctx:
    async def report_progress(self, *a, **k):
        return None


def _client(monkeypatch, **methods):
    mock = MagicMock()
    for name, value in methods.items():
        setattr(mock, name, AsyncMock(return_value=value))
    monkeypatch.setattr(server, "_get_client", lambda: mock)
    return mock


@pytest.mark.asyncio
async def test_a_refine_that_cannot_apply_says_so(monkeypatch) -> None:
    _client(monkeypatch, refine_threat_model=ChatResponse(
        content="Asset 'A9' not found in the model."))
    out = await server.refine_threat_model("v", "tm-001", "Edit A9", _Ctx())
    assert out == {"model_id": "tm-001", "changed": False,
                   "message": "Asset 'A9' not found in the model."}


@pytest.mark.asyncio
async def test_a_question_handled_as_a_change_is_reported_as_one(monkeypatch) -> None:
    _client(monkeypatch, query_threat_model=GenerateResult(
        threat_model=ThreatModel.model_validate(SAMPLE_THREAT_MODEL),
        model_id="tm-001", version=3))
    out = await server.query_threat_model("v", "tm-001", "Q?", _Ctx())
    assert out["answer"] is None and out["changed"] is True and out["version"] == 3


@pytest.mark.asyncio
async def test_a_question_is_answered(monkeypatch) -> None:
    _client(monkeypatch, query_threat_model=ChatResponse(content="It protects keys."))
    out = await server.query_threat_model("v", "tm-001", "Q?", _Ctx())
    assert out == {"model_id": "tm-001", "answer": "It protects keys."}


@pytest.mark.asyncio
async def test_a_generation_answered_in_prose_wrote_nothing(monkeypatch) -> None:
    _client(monkeypatch, generate_threat_model=ChatResponse(content="Hello."))
    out = await server.generate_threat_model("v", "A service", _Ctx())
    assert out == {"generated": False, "message": "Hello."}


@pytest.mark.asyncio
@pytest.mark.parametrize("include_cos", [False, True])
async def test_get_threat_model_includes_objectives_only_when_asked(
        monkeypatch, include_cos) -> None:
    _client(monkeypatch, get_model=ThreatModel.model_validate(SAMPLE_THREAT_MODEL))
    out = await server.get_threat_model("v", "tm-001", include_cos=include_cos)
    assert ("control_objectives" in out) is include_cos
    assert out["id"] == "tm-001"


# ------------------------------------------------------------------
# Every tool the instructions name is a registered tool
# ------------------------------------------------------------------

_NAMED = (
    re.compile(r"^\s*(?:-|\d+\.)\s+`([a-z][a-z0-9_]*)`", re.M),  # list heads
    re.compile(r"`([a-z][a-z0-9_]*)\("),                          # `tool(…)`
    re.compile(r"`([a-z][a-z0-9_]*)` /"),                         # `a` / `b`
    re.compile(r"/ `([a-z][a-z0-9_]*)`"),
)


def _named_tools(text: str) -> set[str]:
    return {m for pattern in _NAMED for m in pattern.findall(text)}


#: Names the instructions put where a tool name goes that are not tools: values
#: and fields listed the same way. Every other name there must be registered.
NOT_TOOLS = {
    # reconciliation tiers
    "certain", "heuristic",
    # assumption types
    "external", "non_applicability",
    # risk reasons and the assessment fields that carry them
    "coverage_gap", "insufficient_by_design", "risk_reason",
    "pending_assumption_ids", "expired_assumption_ids",
    # per-component grade fields
    "target_sl", "eal", "fips_level",
    # activity events a composition undo emits
    "lift_undone", "split_undone",
}


def test_every_tool_the_instructions_name_exists() -> None:
    registered = {t.name for t in asyncio.run(server.mcp.list_tools())}
    text = server.build_instructions("enterprise", "superadmin")
    named = _named_tools(text)
    assert len(named) > 50, "the reader found too few names to be reading the list"
    missing = sorted(named - registered - NOT_TOOLS)
    assert not missing, f"the instructions name tools the server does not register: {missing}"
    stale = sorted(NOT_TOOLS - named)
    assert not stale, f"NOT_TOOLS lists names the instructions no longer use: {stale}"
    assert not (NOT_TOOLS & registered), "a registered tool is listed as not a tool"


def test_every_tool_the_readme_lists_exists() -> None:
    """Every name in the first column of the README's tool tables is a
    registered tool: the README is how a reader finds them."""
    from pathlib import Path
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    registered = {t.name for t in asyncio.run(server.mcp.list_tools())}
    listed = set()
    for line in readme.splitlines():
        if line.startswith("| `"):
            first_cell = line.split("|")[1]
            listed |= set(re.findall(r"`([a-z][a-z0-9_]*)[` (]", first_cell))
    assert len(listed) > 100, "the reader found too few names to be reading the tables"
    missing = sorted(listed - registered - {
        # the soundness-class table's first column
        "presence", "under_approximating_scan", "existential_witness",
        "sound_over_approximation", "by_construction",
    })
    assert not missing, f"the README lists tools the server does not register: {missing}"


def test_the_name_reader_refuses_a_tool_that_is_not_there() -> None:
    text = "- `get_controls` — x\n- `composition_entities` — y\n`restore_entity(entity_type=…)`"
    assert _named_tools(text) == {"get_controls", "composition_entities", "restore_entity"}

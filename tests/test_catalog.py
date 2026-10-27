"""The tool catalog and which calls run across catalogs (catalog.py).

The rule's three properties: NoStaleContractRuns (a call that runs, runs
under the contract its session pinned for that tool), UnchangedToolRuns (a
call to a tool whose contract is the one its session pinned, under a recorded
catalog, runs) and NoticeWhenStale (a call that runs under an older catalog is
told). These tests drive the shipped ``compatible`` over every recorded
catalog and tool, and the middleware end to end.
"""

import itertools
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp import Client

from mipiti_mcp import catalog, server


def test_the_shipped_catalog_is_recorded() -> None:
    """Every catalog the package ships is in its history, recorded by the
    commit that ships it (HistoryComplete)."""
    history = catalog.load_history()
    assert history.get(server.CATALOG_VERSION) == server.CATALOG, (
        "the current catalog is not recorded: run python -m mipiti_mcp.record_catalog")


def test_importing_the_package_reads_no_history() -> None:
    """Only a call naming an older version reads the history: a process that
    imports the package, or serves current calls, opens no file of it."""
    import subprocess
    import sys
    code = ("import builtins; opened = []; real = builtins.open\n"
            "def spy(f, *a, **k):\n"
            "    opened.append(str(f)); return real(f, *a, **k)\n"
            "builtins.open = spy\n"
            "from mipiti_mcp import server\n"
            "assert not [f for f in opened if f.endswith('catalog_history.json')], opened\n"
            "from mipiti_mcp import catalog\n"
            "assert catalog.compatible(server._SERVER_VERSION, 'get_entity', "
            "server._SERVER_VERSION, server.CATALOG, server._CATALOG_HISTORY) == 'run'\n"
            "assert not [f for f in opened if f.endswith('catalog_history.json')]\n"
            "assert catalog.compatible('older', 'get_entity', server._SERVER_VERSION, "
            "server.CATALOG, server._CATALOG_HISTORY) == 'refuse'\n"
            "assert [f for f in opened if f.endswith('catalog_history.json')]\n")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_the_version_names_the_catalog_by_content() -> None:
    assert server.CATALOG_VERSION == catalog.version_of(server.CATALOG)
    assert len(server.CATALOG_VERSION) == catalog.VERSION_DIGITS
    assert set(server.CATALOG["tools"]) == {
        t.name for t in catalog._list_tools(server.mcp)}


def test_a_tool_contract_covers_its_description_and_schemas() -> None:
    tool = catalog._list_tools(server.mcp)[0]
    base = catalog._digest(catalog.tool_contract(tool))
    for field, value in (("description", "changed"),
                         ("parameters", {"type": "object"}),
                         ("output_schema", {"type": "string"})):
        changed = tool.model_copy(update={field: value})
        assert catalog._digest(catalog.tool_contract(changed)) != base, field


def _catalogs() -> dict:
    """Every recorded catalog, and synthetic ones covering a changed tool, a
    removed tool, an added tool and changed instructions."""
    out = dict(catalog.load_history())
    cur = server.CATALOG
    tools = sorted(cur["tools"])
    first, second = tools[0], tools[1]
    changed = {"tools": {**cur["tools"], first: "0" * 64}, "instructions": cur["instructions"]}
    removed = {"tools": {k: v for k, v in cur["tools"].items() if k != second},
               "instructions": cur["instructions"]}
    added = {"tools": {**cur["tools"], "a_tool_since_removed": "1" * 64},
             "instructions": cur["instructions"]}
    instr = {"tools": dict(cur["tools"]), "instructions": "2" * 64}
    for c in (changed, removed, added, instr):
        out[catalog.version_of(c)] = c
    return out


def test_the_rule_over_every_pair_of_catalogs_and_every_tool() -> None:
    """For each recorded catalog as the session's and each as the current
    one, and each tool either names: the decision is the modelled rule."""
    catalogs = _catalogs()
    tools = sorted(set(itertools.chain.from_iterable(c["tools"] for c in catalogs.values())))
    for (pv, pinned), (cv, cur) in itertools.product(catalogs.items(), repeat=2):
        for tool in tools:
            d = catalog.compatible(pv, tool, cv, cur, catalogs)
            same = (tool in pinned["tools"]
                    and pinned["tools"][tool] == cur["tools"].get(tool))
            if pv == cv:
                assert d == "run"
            # NoStaleContractRuns: a call runs only under its pinned contract.
            elif d != "refuse":
                assert same and d == "notice", (pv, cv, tool)  # NoticeWhenStale
            # UnchangedToolRuns: an unchanged tool under a recorded catalog runs.
            if same:
                assert d in ("run", "notice"), (pv, cv, tool)


@pytest.mark.parametrize("named", ["", "unknown", "b1b0a74f76f34213b937d5c4d6fe786704fff5d5"])
def test_a_missing_or_unrecorded_version_is_refused(named) -> None:
    tool = sorted(server.CATALOG["tools"])[0]
    assert catalog.compatible(named, tool, "current", server.CATALOG,
                              catalog.load_history()) == "refuse"


@pytest.fixture
def two_catalogs(monkeypatch):
    """The current catalog, and a recorded older one in which
    ``list_threat_models`` is unchanged and ``get_entity`` differs."""
    cur = server.CATALOG
    older = {"tools": {**cur["tools"], "get_entity": "0" * 64}, "instructions": "1" * 64}
    monkeypatch.setattr(server, "_SERVER_VERSION", "current")
    monkeypatch.setattr(server, "_CATALOG_HISTORY", {"older": older, "current": cur})
    return older


async def _call(tool: str, version: str, **args):
    client = AsyncMock()
    client.list_models.return_value = []
    client.get_entity.return_value = {}
    with patch("mipiti_mcp.server._get_client", return_value=client):
        async with Client(server.mcp) as c:
            return await c.call_tool(tool, {"server_version": version, **args},
                                     raise_on_error=False)


async def test_the_current_version_runs_untold(two_catalogs) -> None:
    result = await _call("list_threat_models", "current")
    assert not result.is_error
    assert all("instructions_updated" not in getattr(b, "text", "") for b in result.content)


async def test_an_older_catalog_runs_an_unchanged_tool_and_is_told(two_catalogs) -> None:
    result = await _call("list_threat_models", "older")
    assert not result.is_error, result
    notices = [json.loads(b.text) for b in result.content
               if "instructions_updated" in getattr(b, "text", "")]
    assert notices == [{"instructions_updated": server._INSTRUCTIONS_UPDATE_MESSAGE}]
    # The tool's own answer is untouched beside the notice.
    assert json.loads(result.content[0].text) == result.structured_content
    assert result.meta["instructions_updated"] == server._INSTRUCTIONS_UPDATE_MESSAGE


async def test_an_older_catalog_never_runs_a_changed_tool(two_catalogs) -> None:
    result = await _call("get_entity", "older", model_id="m", entity_type="asset",
                         entity_id="A-1")
    assert result.is_error
    assert "updated since your session started" in result.content[0].text


@pytest.mark.parametrize("version", ["", "never-recorded"])
async def test_a_missing_or_unknown_version_runs_nothing(two_catalogs, version) -> None:
    with patch("mipiti_mcp.server._get_client") as get_client:
        async with Client(server.mcp) as c:
            result = await c.call_tool("list_threat_models", {"server_version": version},
                                       raise_on_error=False)
    assert result.is_error
    get_client.assert_not_called()


def test_the_instructions_name_the_version() -> None:
    assert f"`{server._SERVER_VERSION}`" in server.build_instructions("pro")
    assert server._VERSION_MARKER not in server.build_instructions("developer")

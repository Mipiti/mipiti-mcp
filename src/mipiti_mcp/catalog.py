"""The tool catalog a client pins, and which calls run across catalogs.

A client reads the server's instructions and its tools' descriptions and
input schemas when its session starts, and keeps them for the session. The
catalog is what it kept: each tool's contract (its name, description, input
schema and output schema) and the instructions. The server's version names
the catalog by content, so it changes exactly when a contract or the
instructions change.

``catalog_history.json`` records every catalog the package has shipped, by
version. A call naming the current version runs. A call naming a recorded
version runs when the tool it calls has the contract there that it has now,
and is told the instructions were updated. Every other call is refused: an
unknown version, a missing one, or a tool whose contract changed since the
session started. No call runs under a contract other than the one its
session pinned. The contract is the tool's description and schemas, not its
code: a change to what a tool does that a caller must know about changes its
description too.

``python -m mipiti_mcp.record_catalog`` adds the current catalog to the
history; the package's tests fail while it is missing.
"""

import asyncio
import concurrent.futures
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Literal

HISTORY_PATH = Path(__file__).with_name("catalog_history.json")

#: How many hex digits of the catalog's digest name its version.
VERSION_DIGITS = 16

Decision = Literal["run", "notice", "refuse"]


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_contract(tool: Any) -> dict:
    """What a client pins of one tool."""
    return {
        "name": tool.name,
        "description": tool.description or "",
        "parameters": tool.parameters or {},
        "output_schema": tool.output_schema,
    }


def _list_tools(server: Any) -> list:
    """The server's tools, read on a loop of its own so that an import inside
    a running loop reads them as well as one outside it."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, server.list_tools()).result()


def current(server: Any, instructions: list[str]) -> dict:
    """The catalog the server ships: each tool's contract digest and the
    digest of the instructions' text (every tier's parts, before the version
    is written into them)."""
    return {
        "tools": {t.name: _digest(tool_contract(t)) for t in _list_tools(server)},
        "instructions": _digest(instructions),
    }


def version_of(catalog: dict) -> str:
    return _digest(catalog)[:VERSION_DIGITS]


def load_history(path: Path = HISTORY_PATH) -> dict:
    """Every recorded catalog, by version."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


_HISTORY: dict = {}


def shipped_history() -> dict:
    """The history shipped with the package, read the first time a call names
    a version other than the current one, then kept: importing the package
    reads no file of it but its modules."""
    if not _HISTORY:
        _HISTORY.update(load_history())
    return _HISTORY


def compatible(named: str, tool: str, current_version: str, current_catalog: dict,
               history) -> Decision:
    """How a call naming ``named`` to ``tool`` is answered: ``run``,
    ``notice`` (it runs, and is told the instructions were updated) or
    ``refuse``. ``history`` is the recorded catalogs, or a function returning
    them, called only when ``named`` is not the current version."""
    if named and named == current_version:
        return "run"
    if callable(history):
        history = history()
    pinned = history.get(named) if named else None
    if pinned is None:
        return "refuse"
    then = pinned.get("tools", {}).get(tool)
    if then is None or then != current_catalog["tools"].get(tool):
        return "refuse"
    return "notice"


def record(path: Path = HISTORY_PATH) -> str:
    """Add the current catalog to the history; returns its version."""
    from . import server

    history = load_history(path)
    history[server.CATALOG_VERSION] = server.CATALOG
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return server.CATALOG_VERSION


def main(argv: list[str]) -> int:
    """``python -m mipiti_mcp.record_catalog``: run from a module of its own,
    since this one is imported by the package before ``-m`` would run it."""
    if argv[1:]:
        print("usage: python -m mipiti_mcp.record_catalog", file=sys.stderr)
        return 2
    print(record())
    return 0

"""Every tool description fits the length a client renders.

A client was observed to cut a tool description at 2048 characters. A cut
description is not shorter, it is wrong: the sentences after the cut — the
refusals, the modes, the rule that makes a field safe to read — are the ones
an agent then plans without. So a description that does not fit is a
defect, refused here rather than discovered by an agent acting on half of it.
"""

import asyncio

from mipiti_mcp import server

#: The length a client was observed to cut a description at.
DESCRIPTION_LIMIT = 2048


def _overlong(tools) -> list[tuple[str, int]]:
    return sorted(
        (tool.name, len(tool.description or ""))
        for tool in tools
        if len(tool.description or "") > DESCRIPTION_LIMIT
    )


def test_every_tool_description_fits_the_rendered_length() -> None:
    tools = asyncio.run(server.mcp.list_tools())
    assert len(tools) > 100, "the reader found too few tools to be reading the catalogue"
    overlong = _overlong(tools)
    assert not overlong, (
        f"tool descriptions longer than {DESCRIPTION_LIMIT} characters, which a "
        f"client cuts: {overlong}"
    )


def test_the_check_refuses_an_overlong_description() -> None:
    """The reader must see a description past the limit, or the check above
    passes on a catalogue it never measured."""

    class _Tool:
        def __init__(self, name: str, description: str) -> None:
            self.name = name
            self.description = description

    tools = [_Tool("fits", "x" * DESCRIPTION_LIMIT),
             _Tool("cut", "x" * (DESCRIPTION_LIMIT + 1))]
    assert _overlong(tools) == [("cut", DESCRIPTION_LIMIT + 1)]

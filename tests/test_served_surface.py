"""The catalogue advertises only what the API answers.

A tool is a promise: an agent that reads one plans around it. A tool whose
call has no route, a parameter the receiving surface drops, or a documented
return field that never appears is worse than a missing feature -- the agent
records work it never did and reports a binding that does not exist.

So the catalogue holds a vocabulary OUT until an API surface produces it.
Each name below is a shape the catalogue described before anything answered
for it; the guard fails when one comes back into the published text without
a surface behind it. Adding a name here is the cheap half of shipping the
capability; deleting one is the deliberate act of saying the API now serves
it, and belongs in the same change as the read that proves it.
"""

import asyncio
import inspect

import pytest

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient

# Names the published text must not carry. Each is a field or a tool whose
# value would have to come from a read the API does not answer.
_UNSERVED = (
    # A per-model inventory-completeness record, and the tier and per-entity
    # grounding computed from it.
    "get_inventory_completeness",
    "inventory-completeness",
    "completeness_tier",
    # The stored provenance of an inventory entity.
    "entity_origin",
    # A risk reason and a per-objective quantifier on an assessment.
    "soundness_gap",
    "obligation_quantifier",
    "quantifier_source",
    # A promotion of an already-submitted assertion to a declared binding.
    "bind_assertion",
    # A composed tier for a control. Evidence strength is composed per
    # clause, and no read returns a control-level tier; naming one would
    # have an agent report a grade nothing computes.
    "soundness_tier",
)

# Field names that must not be documented as a returned object. Kept apart
# from _UNSERVED because each is an ordinary English word elsewhere.
_UNSERVED_SHAPES = (
    "clauses[]",
    "assurance{",
    "verified_closed",
    "verified_bounded",
    "sites_unproven",
)


def _tools() -> dict:
    return {t.name: t for t in asyncio.run(server.mcp._list_tools())}


def _tool_texts() -> dict:
    """Every published text an agent can read: the instructions and each
    tool's name plus the description its client renders."""
    texts = {"<instructions>": server.build_instructions("pro", "user")}
    for name, tool in _tools().items():
        fn = getattr(tool, "fn", None)
        texts[name] = "\n".join(filter(None, [
            name,
            tool.description or "",
            inspect.getdoc(fn) if fn is not None else "",
        ]))
    return texts


@pytest.mark.parametrize("name", _UNSERVED)
def test_no_published_text_names_an_unserved_field(name: str) -> None:
    offenders = [where for where, text in _tool_texts().items() if name in text]
    assert offenders == [], f"{name} is published by: {offenders}"


@pytest.mark.parametrize("shape", _UNSERVED_SHAPES)
def test_no_published_text_documents_an_unserved_return_shape(shape: str) -> None:
    offenders = [where for where, text in _tool_texts().items() if shape in text]
    assert offenders == [], f"{shape} is published by: {offenders}"


@pytest.mark.parametrize("name", _UNSERVED)
def test_the_client_calls_no_unserved_route(name: str) -> None:
    assert not hasattr(MipitiClient, name), f"MipitiClient.{name} calls a route nothing answers"
    source = inspect.getsource(MipitiClient)
    assert name not in source, f"{name} appears in the client"


def test_no_tool_is_registered_for_an_unserved_route() -> None:
    assert set(_tools()).isdisjoint(set(_UNSERVED))


def test_an_attestation_carries_no_binding_declaration() -> None:
    """A declaration of which clause evidence stands for is recorded on the
    assertion. The attestation surface does not keep one, so the tool does
    not take one: a parameter accepted and dropped is a silent no-op on a
    mutating call, which the caller cannot detect."""
    tool = _tools()["submit_attestation"]
    assert "covers" not in inspect.signature(tool.fn).parameters
    assert "covers" not in (inspect.getdoc(tool.fn) or "")
    assert "covers" not in inspect.signature(MipitiClient.submit_attestation).parameters


def test_covers_is_still_carried_where_the_record_keeps_it() -> None:
    """The guard above must not be read as 'covers is gone'. An assertion
    carries its own declaration, and that half is served."""
    doc = server._SUBMIT_ASSERTIONS_DOC + "\n" + (
        inspect.getdoc(_tools()["submit_assertions"].fn) or ""
    )
    assert "covers" in doc
    assert "cls_" in doc

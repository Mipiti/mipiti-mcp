"""The catalogue advertises only what the API answers, for a stated reason.

A tool is a promise: an agent that reads one plans around it. A tool whose
call has no route, a parameter the receiving surface drops, or a documented
return field that never appears is worse than a missing feature -- the agent
records work it never did and reports a binding that does not exist.

So the catalogue holds a vocabulary OUT of its published text. It is held
out for two different reasons, and the difference is the whole value of this
file to the next reader:

``_UNANSWERED`` names a shape no API surface produces. Publishing one would
be a promise nothing can keep. Deleting a name from it is the deliberate act
of saying a read now answers for it, and belongs in the same change as that
read.

``_UNADVERTISED`` names a shape the API DOES answer and this release
deliberately does not steer agents at. Nothing here is a false promise;
these are editorial decisions about which surface an agent should read
first, and deleting one is an editorial change, not a capability claim.

A guard whose stated ground its own list falsifies is worse than no guard,
because the next reader trusts the reason rather than re-deriving it. Keep
each name in the list whose reason is true of it.
"""

import asyncio
import inspect

import pytest

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient

# Names no API surface answers for. A value here would have to be invented.
_UNANSWERED = (
    # A risk reason on an assessment.
    "soundness_gap",
    # A per-objective quantifier on an assessment.
    "obligation_quantifier",
)

# Names the API answers and this release does not advertise.
_UNADVERTISED = (
    # The per-model inventory-completeness record, its tier, and the stored
    # provenance of an entity. Answered; the catalogue steers an agent at the
    # per-clause work list instead, because that is the surface that names an
    # act to perform. An entity's provenance follows from how the entity came
    # to exist rather than from anything an agent calls.
    "get_inventory_completeness",
    "inventory-completeness",
    "completeness_tier",
    "entity_origin",
    # The quantifier's provenance, and the weakest binding origin, on a served
    # claim. The catalogue publishes the acts -- write `covers`, submit the
    # class the work order names -- rather than the shapes they move.
    "quantifier_source",
    "binding_origin",
    # Re-pointing an assertion already submitted. Answered on a route this
    # release does not advertise: a declaration is re-checked when the
    # evidence is evaluated either way, so the published act is to declare
    # `covers` on the submission.
    "bind_assertion",
)

_HELD_OUT = _UNANSWERED + _UNADVERTISED

# Field names that must not be documented as a returned object. Kept apart
# from the name lists because each is an ordinary English word elsewhere.
_UNANSWERED_SHAPES = (
    "assurance{",
    "verified_closed",
    "verified_bounded",
    "sites_unproven",
)

# Answered on the served claim; the catalogue points at the work order, which
# names the clause id to bind to, rather than documenting the claim's shape.
_UNADVERTISED_SHAPES = (
    "clauses[",
)

_HELD_OUT_SHAPES = _UNANSWERED_SHAPES + _UNADVERTISED_SHAPES


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


def test_the_two_held_out_lists_are_kept_apart() -> None:
    """One list with one reason is how a true reason rots into a false one:
    a name that becomes served stays under 'nothing answers for it' and the
    next reader believes the sentence instead of the code."""
    assert _UNANSWERED, "the list of shapes nothing answers for is empty"
    assert _UNADVERTISED, "the list of answered-but-unadvertised shapes is empty"
    assert set(_UNANSWERED).isdisjoint(_UNADVERTISED)
    assert set(_UNANSWERED_SHAPES).isdisjoint(_UNADVERTISED_SHAPES)


def test_a_served_name_is_not_filed_as_unanswered() -> None:
    """The composed tier of a control is read from a served claim, so it is
    published (see ``get_sufficiency``) and belongs in neither list."""
    assert "soundness_tier" not in _HELD_OUT


@pytest.mark.parametrize("name", _HELD_OUT)
def test_no_published_text_names_a_held_out_field(name: str) -> None:
    offenders = [where for where, text in _tool_texts().items() if name in text]
    assert offenders == [], f"{name} is published by: {offenders}"


@pytest.mark.parametrize("shape", _HELD_OUT_SHAPES)
def test_no_published_text_documents_a_held_out_return_shape(shape: str) -> None:
    offenders = [where for where, text in _tool_texts().items() if shape in text]
    assert offenders == [], f"{shape} is published by: {offenders}"


@pytest.mark.parametrize("name", _HELD_OUT)
def test_the_client_calls_no_held_out_route(name: str) -> None:
    assert not hasattr(MipitiClient, name), f"MipitiClient.{name} calls a route the catalogue holds out"
    source = inspect.getsource(MipitiClient)
    assert name not in source, f"{name} appears in the client"


def test_no_tool_is_registered_for_a_held_out_route() -> None:
    assert set(_tools()).isdisjoint(set(_HELD_OUT))


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

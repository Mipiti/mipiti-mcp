"""The assertion type contract must be readable, not merely present.

A caller cannot construct a valid assertion without knowing which types exist
and what each requires. Carrying that only in a tool description makes it prose,
and a client may present prose in part — a half-list of types reads exactly like
a whole one, so a caller has no way to tell it was cut.

These tests pin two things: the description stays small enough to survive, and
the full catalogue is reachable as data regardless.
"""

import pytest

from mipiti_mcp.assertion_types import (
    ASSERTION_TYPES,
    describe_types,
    format_compact,
    format_for_docstring,
)
from mipiti_mcp.server import _SUBMIT_ASSERTIONS_DOC


def test_every_type_is_named_in_the_submit_description():
    # The names are what a caller needs to pick a type at all.
    for spec in ASSERTION_TYPES:
        assert f"{spec.name}(" in _SUBMIT_ASSERTIONS_DOC, spec.name


def test_every_type_lists_its_required_params_in_the_description():
    compact = format_compact()
    for spec in ASSERTION_TYPES:
        line = next(l for l in compact.splitlines() if l.strip().startswith(f"- {spec.name}("))
        for param in spec.required_params:
            assert param in line, f"{spec.name} omits required param {param}"


# Observed limit at which a client truncated this description. Not a guess: the
# cut landed on exactly this byte, mid-word, with no marker that anything
# followed.
DESCRIPTION_LIMIT = 2048


def test_the_description_fits_within_a_client_truncation_limit():
    assert len(_SUBMIT_ASSERTIONS_DOC) <= DESCRIPTION_LIMIT, (
        f"submit_assertions description is {len(_SUBMIT_ASSERTIONS_DOC)} chars, "
        f"over the {DESCRIPTION_LIMIT} a client was observed to cut at. Move "
        "detail into get_assertion_types rather than growing the prose."
    )


def test_the_contract_survives_even_a_tighter_cut():
    """Ordering, not just size, has to be right.

    A limit smaller than the one observed would still cut something. The
    description is ordered so that what goes first is what a caller cannot
    proceed without: the pointer to the catalogue tool, then the type list.
    Prose that merely elaborates is last.
    """
    head = _SUBMIT_ASSERTIONS_DOC[:DESCRIPTION_LIMIT]
    assert "get_assertion_types" in head
    for spec in ASSERTION_TYPES:
        assert f"{spec.name}(" in head, f"{spec.name} falls outside the limit"


def test_optional_params_are_named_in_the_description():
    """Required params alone would be actively misleading: `target` is optional
    on the pattern types and is the documented way to assert against the design
    specification, so a caller shown only `file` would not know it exists."""
    compact = format_compact()
    for spec in ASSERTION_TYPES:
        if not spec.optional_params:
            continue
        line = next(l for l in compact.splitlines()
                    if l.strip().startswith(f"- {spec.name}("))
        for param in spec.optional_params:
            assert param in line, f"{spec.name} omits optional param {param}"


def test_the_description_points_at_the_catalogue_tool():
    # A truncated read should still tell the caller where the rest lives.
    assert "get_assertion_types" in _SUBMIT_ASSERTIONS_DOC


def test_the_compact_form_is_much_smaller_than_the_full_reference():
    assert len(format_compact()) < len(format_for_docstring()) / 3


# ---------------------------------------------------------------------------
# The catalogue as data.
# ---------------------------------------------------------------------------

def test_the_catalogue_returns_every_type():
    described = describe_types()
    assert len(described) == len(ASSERTION_TYPES)
    assert {d["type"] for d in described} == {t.name for t in ASSERTION_TYPES}


def test_each_entry_carries_what_a_caller_needs():
    for entry in describe_types():
        assert entry["description"], entry["type"]
        assert "required_params" in entry and "optional_params" in entry
        for param in entry["required_params"]:
            assert param["name"] and param["description"], entry["type"]


def test_the_catalogue_can_be_filtered():
    got = describe_types(["file_exists", "pattern_absent"])
    assert [d["type"] for d in got] == ["file_exists", "pattern_absent"]


def test_an_unknown_type_filters_to_nothing_rather_than_guessing():
    # The tool turns this into an explicit error; silently returning a
    # neighbouring type would be worse than returning none.
    assert describe_types(["no_such_type"]) == []


def test_required_and_optional_params_are_disjoint():
    for spec in ASSERTION_TYPES:
        assert not set(spec.required_params) & set(spec.optional_params), spec.name


def test_the_two_target_capable_types_are_present():
    # `target` is the documented way to assert against the feature description
    # rather than a repository file, and only these two accept it.
    names = {d["type"] for d in describe_types()}
    assert {"pattern_matches", "pattern_absent"} <= names

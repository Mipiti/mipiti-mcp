"""Declared parameter formats: one definition, applied before a submission leaves."""

import json
import re

import pytest

from mipiti_mcp.assertion_types import (
    ASSERTION_TYPES,
    MECHANISM_KINDS,
    MECHANISM_PATTERN,
    SAFE_FORMS,
    SCOPE_ENTRY_PATTERN,
    SINK_KINDS,
    describe_types,
    missing_required_params,
    validate_param_formats,
)


GOOD = [
    "app/auth.py::require_token",
    "app/auth.py::Auth.require_token",
    "rtl/alu.sv::module:alu",
    "rtl/fsm.sv::always:seq_logic",
    "hdl/ctl.vhd::process:p_ctl",
    "src/lib.rs::impl:Limiter",
    "pkg/x.go::Limiter.Allow",
    "src/lib.rs::struct:Limiter",
    "rtl/bus_if.sv::interface:axi_if",
    "rtl/pkg.sv::package:types_pkg",
    "my dir/auth.py::require_token",
]
BAD = [
    "require_token",
    "app/auth.py",
    "app/auth.py::",
    "app/auth.py::module:",
    "app/auth.py::widget:thing",
    "../app/auth.py::require_token",
    "app/auth.py::require token",
    "app/auth.py::a.b.c",
    " app/auth.py::f",
    "app/auth.py ::f",
    "app/auth.py::Widget:f",
]


@pytest.mark.parametrize("value", GOOD)
def test_accepted_mechanism_forms(value):
    assert re.match(MECHANISM_PATTERN, value)
    assert validate_param_formats("test_attested", {"test": "t", "mechanism": value}) == []


@pytest.mark.parametrize("value", BAD)
def test_refused_mechanism_forms(value):
    assert not re.match(MECHANISM_PATTERN, value)
    errors = validate_param_formats("test_attested", {"test": "t", "mechanism": value})
    assert len(errors) == 1 and "mechanism" in errors[0] and "e.g." in errors[0]


def test_absent_or_unknown_params_are_not_judged():
    assert validate_param_formats("test_attested", {"test": "t"}) == []
    assert validate_param_formats("no_such_type", {"mechanism": "x"}) == []


def test_every_declared_pattern_matches_its_own_example():
    for t in ASSERTION_TYPES:
        for p in t.params:
            if p.pattern and p.example:
                assert re.match(p.pattern, p.example), (t.name, p.name)


async def test_submit_refuses_before_sending(monkeypatch):
    from fastmcp.exceptions import ToolError

    from mipiti_mcp import server

    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    body = json.dumps([{"type": "test_attested", "params": {"test": "t", "mechanism": "nope"}, "repo": "o/r"}])
    with pytest.raises(ToolError, match="mechanism"):
        await server.submit_assertions(server_version="x", model_id="m", assertions_json=body, control_id="c")
    with pytest.raises(ToolError, match="mechanism"):
        await server.submit_functional_test_assertions(
            server_version="x", model_id="m", functional_test_id="f", assertions_json=body,
        )
    assert called == []


@pytest.mark.parametrize("kind", MECHANISM_KINDS)
def test_every_kind_is_accepted(kind):
    assert re.match(MECHANISM_PATTERN, f"src/a.sv::{kind}:name_1")


def test_kinds_are_distinct_lowercase_identifiers():
    assert len(set(MECHANISM_KINDS)) == len(MECHANISM_KINDS)
    assert all(k == k.lower() and k.isidentifier() for k in MECHANISM_KINDS)


# ---------------------------------------------------------------------------
# Array-valued params carry an item schema; both sides apply it.
# ---------------------------------------------------------------------------

_SDD = {
    "scope": ["src/db/**/*.py", "rtl/bus.sv"],
    "sinks": [{"callee": "execute", "positions": [0]}, {"callee": "data_q", "kind": "assign"}],
    "safe_forms": ["parameter_binding", "literal"],
    "property": "Every SQL statement reaches the driver with data bound as parameters.",
}
_TB = {
    "scope": ["src/"],
    "sinks": [{"callee": "execute"}],
    "boundary_type": "sql.Identifier",
    "constructors": ["sql.Identifier", "SafeSql.literal"],
    "property": "Every identifier reaching the driver was built through the boundary type.",
}


def test_well_formed_witnesses_pass():
    assert validate_param_formats("sink_default_deny", _SDD) == []
    assert validate_param_formats("typed_boundary", _TB) == []


def _one(type_name, override):
    base = dict(_SDD if type_name == "sink_default_deny" else _TB)
    base.update(override)
    errors = validate_param_formats(type_name, base)
    assert len(errors) == 1, errors
    return errors[0]


@pytest.mark.parametrize("entry", ["src/**", "rtl/top.v", "my dir/x.py", "..foo/x", "a/.../b"])
def test_scope_entries_accepted(entry):
    assert re.match(SCOPE_ENTRY_PATTERN, entry)


@pytest.mark.parametrize("entry", ["../x", "a/../b", "/abs/x", " src", "src ", "", "a/..", "..", "x\ny"])
def test_scope_entries_refused(entry):
    assert not re.match(SCOPE_ENTRY_PATTERN, entry)
    assert "'scope'" in _one("sink_default_deny", {"scope": [entry]})


def test_scope_must_be_a_non_empty_array():
    assert "expected a JSON array" in _one("sink_default_deny", {"scope": "src/"})
    assert "at least 1" in _one("sink_default_deny", {"scope": []})


def test_sinks_need_a_callee_and_a_known_kind():
    assert "lacks 'callee'" in _one("sink_default_deny", {"sinks": [{"kind": "call"}]})
    assert "is not an object" in _one("sink_default_deny", {"sinks": ["execute"]})
    assert "'kind' is not one of" in _one("sink_default_deny", {"sinks": [{"callee": "x", "kind": "store"}]})
    for kind in SINK_KINDS:
        assert validate_param_formats("sink_default_deny", {**_SDD, "sinks": [{"callee": "x", "kind": kind}]}) == []


def test_safe_forms_is_a_non_empty_subset_without_repeats():
    assert SAFE_FORMS == ("literal", "named_constant", "literal_concat", "parameter_binding")
    assert "at least 1" in _one("sink_default_deny", {"safe_forms": []})
    assert "is not one of" in _one("sink_default_deny", {"safe_forms": ["tainted"]})
    assert "repeats" in _one("sink_default_deny", {"safe_forms": ["literal", "literal"]})
    assert validate_param_formats("sink_default_deny", {**_SDD, "safe_forms": list(SAFE_FORMS)}) == []


def test_allowlist_entries_carry_a_reviewed_reason():
    entry = {"file": "src/db/admin.py", "site": "42", "callee": "execute",
             "reason": "table name from a fixed enum", "reviewed_by": "a.reviewer"}
    assert validate_param_formats("sink_default_deny", {**_SDD, "allowlist": [entry]}) == []
    for missing in ("file", "site", "callee", "reason", "reviewed_by"):
        bad = {k: v for k, v in entry.items() if k != missing}
        assert f"lacks '{missing}'" in _one("sink_default_deny", {"allowlist": [bad]})
    assert "lacks 'reason'" in _one("sink_default_deny", {"allowlist": [{**entry, "reason": "  "}]})


def test_wrappers_and_constructors_are_names():
    assert validate_param_formats("sink_default_deny", {**_SDD, "wrappers": ["run_query", "db::run", "$readmemh"]}) == []
    assert "item 0" in _one("sink_default_deny", {"wrappers": ["run query"]})
    assert "item 1" in _one("typed_boundary", {"constructors": ["ok", "not ok"]})
    assert "at least 1" in _one("typed_boundary", {"constructors": []})


def test_boundary_type_and_property_are_scalars_with_a_form():
    assert "'boundary_type'" in _one("typed_boundary", {"boundary_type": "Safe Sql"})
    assert validate_param_formats("typed_boundary", {**_TB, "boundary_type": "pkg::safe_addr_t"}) == []
    assert "'property'" in _one("typed_boundary", {"property": "short"})
    assert "'property'" in _one("typed_boundary", {"property": "one line\nand another line of text"})
    assert "not a string" in _one("typed_boundary", {"property": ["a", "b"]})


def test_string_pattern_params_are_unchanged_by_the_array_branch():
    assert validate_param_formats("test_attested", {"test": "t", "mechanism": "app/a.py::f"}) == []
    errors = validate_param_formats("test_attested", {"test": "t", "mechanism": ["app/a.py::f"]})
    assert len(errors) == 1 and "not a string" in errors[0]


def test_every_array_example_validates_against_its_own_schema():
    for t in ASSERTION_TYPES:
        for p in t.params:
            if p.structure == "array":
                assert validate_param_formats(t.name, {p.name: json.loads(p.example)}) == [], (t.name, p.name)


def test_the_item_schema_is_exposed_as_data():
    (entry,) = describe_types(["sink_default_deny"])
    params = {p["name"]: p for p in entry["required_params"] + entry["optional_params"]}
    assert params["safe_forms"]["item_schema"] == {"min_items": 1, "enum": list(SAFE_FORMS)}
    assert params["sinks"]["item_schema"]["required_keys"] == ["callee"]
    assert params["sinks"]["item_schema"]["key_enums"] == {"kind": list(SINK_KINDS)}
    assert params["scope"]["item_schema"]["item_pattern"] == SCOPE_ENTRY_PATTERN
    assert params["property"]["pattern"]
    assert "structure" not in params["property"]


# ---------------------------------------------------------------------------
# Required params: a submission that omits one is refused before it is sent.
# ---------------------------------------------------------------------------


def test_a_complete_submission_requires_nothing_more():
    assert missing_required_params("sink_default_deny", _SDD) == []
    assert missing_required_params("typed_boundary", _TB) == []
    assert missing_required_params("file_exists", {"file": "a.py"}) == []


def test_the_absent_required_params_are_named_one_by_one():
    """A template that names one type and fills another type's parameter set
    is well-formed in every value it carries, so only the absence check sees
    it. Each missing key is named, in the words the API uses on arrival."""
    template = {k: v for k, v in _SDD.items()}
    errors = missing_required_params("typed_boundary", template)
    assert errors == [
        "Missing required param 'boundary_type' for type 'typed_boundary'",
        "Missing required param 'constructors' for type 'typed_boundary'",
    ]
    assert validate_param_formats("typed_boundary", template) == []


def test_an_optional_param_is_never_required():
    assert missing_required_params("sink_default_deny", {**_SDD, "allowlist": []}) == []
    without_optional = {k: v for k, v in _SDD.items()}
    assert "wrappers" not in without_optional
    assert missing_required_params("sink_default_deny", without_optional) == []


def test_a_platform_target_stands_in_for_a_file():
    """``target`` replaces ``file`` on the types that declare it, so a
    submission carrying one is not asked for the other."""
    assert missing_required_params("pattern_matches", {"pattern": "x"}) == [
        "Missing required param 'file' for type 'pattern_matches'"
    ]
    assert missing_required_params(
        "pattern_matches", {"pattern": "x", "target": "feature_description"}) == []


def test_an_unpublished_type_requires_nothing():
    assert missing_required_params("no_such_type", {}) == []
    assert missing_required_params("file_exists", None) == [
        "Missing required param 'file' for type 'file_exists'"
    ]


async def test_submit_refuses_an_incomplete_submission_before_sending(monkeypatch):
    from fastmcp.exceptions import ToolError

    from mipiti_mcp import server

    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    body = json.dumps([{"type": "typed_boundary", "params": dict(_SDD), "repo": "o/r"}])
    with pytest.raises(ToolError, match="boundary_type"):
        await server.submit_assertions(
            server_version="x", model_id="m", assertions_json=body, control_id="c")
    assert called == []


def test_the_binding_form_is_read_from_the_value_not_the_position():
    """``parameter_binding`` is recorded from the shape of the value at the
    site, and what it establishes is that the statement is fixed. The
    published text has to say both, or an author admits it for a sink that
    reads one of the bound entries as the statement."""
    spec = next(t for t in ASSERTION_TYPES if t.name == "sink_default_deny")
    forms = next(p for p in spec.params if p.name == "safe_forms").description
    assert "read from the value's own shape, never from the position it occupies" in forms
    assert "takes the structure as data" in forms
    assert "a literal at the position with the data in a separate" not in forms


# --- an unfilled blank is refused, whatever format the param declares -------

def test_a_param_left_as_the_blank_is_refused_even_with_no_declared_format():
    """The guidance offers a skeleton whose values are questions. A param that
    declares a pattern refuses its own blank as a format error; a param that
    declares none would otherwise accept the question as an answer, and a
    submission that passes while saying nothing about the caller's code is
    recorded as a claim until some later check catches it."""
    errors = validate_param_formats("test_attested", {
        "test": "<test id that fails without the control>",
        "mechanism": "<file>::<symbol of the guard>",
    })
    assert any("'test'" in e for e in errors), errors
    assert any("'mechanism'" in e for e in errors), errors


def test_a_filled_submission_of_the_same_shape_passes():
    """So the refusal above is about the blank, not about the type."""
    assert validate_param_formats("test_attested", {
        "test": "tests/test_auth.py::test_rejects_expired_token",
        "mechanism": "app/auth.py::require_token",
    }) == []


def test_a_blank_inside_an_array_is_refused_and_named():
    errors = validate_param_formats("sink_default_deny", {
        "scope": ["<path of each component on the path>"],
        "sinks": [{"callee": "execute", "positions": [0]}],
        "safe_forms": ["parameter_binding"],
        "property": "Every statement reaches the driver with data bound as parameters.",
    })
    assert [e for e in errors if "'scope'" in e], errors
    assert not [e for e in errors if "'sinks'" in e or "'safe_forms'" in e], errors


@pytest.mark.parametrize("value", [
    "count < limit",
    "the handler rejects a token issued <before> the rotation",
    "a<b",
    "<",
    "<>",
])
def test_a_value_that_merely_carries_an_angle_bracket_is_not_a_blank(value):
    """A property sentence is prose, and prose contains comparisons. Only a
    whole value of the form ``<...>`` is the question copied across."""
    errors = validate_param_formats("sink_default_deny", {"property": value})
    assert not [e for e in errors if "blank" in e], errors


def test_a_blank_nested_in_an_object_is_refused_and_placed():
    """A param declaring an array of objects carries its questions one level
    further in than a plain array does. A check reading only the top of the
    value accepts the skeleton exactly where it is least filled."""
    errors = validate_param_formats("sink_default_deny", {
        "scope": ["services/api"],
        "sinks": [{"callee": "<the call that realises this clause>"}],
        "safe_forms": ["literal"],
        "property": "Every statement reaches the driver with data bound as parameters.",
    })
    sinks = [e for e in errors if "'sinks'" in e]
    assert sinks, errors
    assert "item 0.callee" in sinks[0], sinks[0]
    assert not [e for e in errors if "'scope'" in e or "'property'" in e], errors


def test_the_same_submission_with_the_blank_answered_passes():
    assert validate_param_formats("sink_default_deny", {
        "scope": ["services/api"],
        "sinks": [{"callee": "execute", "positions": [0]}],
        "safe_forms": ["literal"],
        "property": "Every statement reaches the driver with data bound as parameters.",
    }) == []

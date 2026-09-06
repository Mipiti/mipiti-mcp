"""Declared parameter formats: one definition, applied before a submission leaves."""

import json
import re

import pytest

from mipiti_mcp.assertion_types import (
    ASSERTION_TYPES,
    MECHANISM_PATTERN,
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

"""``test_attested`` names the mechanism its evidence is bound to."""

from mipiti_mcp.assertion_types import (
    ASSERTION_PARAM_SCHEMAS,
    ASSERTION_TYPES,
    describe_types,
    format_compact,
)

_SPEC = next(t for t in ASSERTION_TYPES if t.name == "test_attested")


def test_mechanism_is_an_optional_param_with_an_anchor_example():
    param = next(p for p in _SPEC.params if p.name == "mechanism")
    assert param.required is False
    assert param.example == "app/auth.py::require_token"
    assert "::" in param.description
    assert "function_exists" in param.description


def test_mechanism_is_never_required():
    assert "mechanism" not in ASSERTION_PARAM_SCHEMAS["test_attested"]
    assert _SPEC.required_params == ["test"]
    assert _SPEC.optional_params == ["env", "mechanism"]


def test_description_binds_evidence_to_the_mechanism():
    assert "`mechanism`" in _SPEC.description
    assert "attest-tests --coverage" in _SPEC.description
    assert "attest-dependence" in _SPEC.description


def test_mechanism_reaches_the_derived_surfaces():
    line = next(
        l for l in format_compact().splitlines() if l.strip().startswith("- test_attested(")
    )
    assert "mechanism" in line
    (described,) = describe_types(["test_attested"])
    assert "mechanism" in [p["name"] for p in described["optional_params"]]

"""Target support is derived from the schema, not maintained separately."""

from mipiti_mcp.assertion_types import (
    ASSERTION_PARAM_SCHEMAS,
    ASSERTION_TARGETS,
    ASSERTION_TYPES,
    TARGET_CAPABLE_TYPES,
)

_EXPECTED = frozenset({
    "function_exists", "class_exists", "decorator_present", "function_calls",
    "import_present", "pattern_matches", "pattern_absent",
    "no_plaintext_secret", "env_var_referenced", "parameter_validated",
    "error_handled", "middleware_registered", "http_header_set",
})


def test_target_values():
    assert ASSERTION_TARGETS == ("feature_description",)


def test_target_capable_types_match_schema():
    assert TARGET_CAPABLE_TYPES == _EXPECTED


def test_target_only_where_it_replaces_a_required_file():
    # A target substitutes for ``file``; it is meaningless on a type that
    # does not require one.
    for name in TARGET_CAPABLE_TYPES:
        assert "file" in ASSERTION_PARAM_SCHEMAS[name], name


def test_target_is_optional_and_never_required():
    for t in ASSERTION_TYPES:
        for p in t.params:
            if p.name == "target":
                assert p.required is False, t.name
    for name, required in ASSERTION_PARAM_SCHEMAS.items():
        assert "target" not in required, name

"""Target support is derived from the schema, not maintained separately."""

from mipiti_mcp.assertion_types import (
    ASSERTION_PARAM_SCHEMAS,
    ASSERTION_TARGETS,
    ASSERTION_TYPES,
    TARGET_CAPABLE_TYPES,
)

# Pinned by intent, not by derivation. A type may carry ``target`` only when
# BOTH conjuncts hold:
#   (1) its tier-1 predicate is a caller-supplied regex evaluated over
#       arbitrary text, with no source-language structure; and
#   (2) its tier-2 criterion and schema description are defined over the
#       matched text itself, not over the role the scanned artifact plays in
#       the running system.
# Code-syntax types fail (1): their criterion is stated about code — a
# definition, a call, a decorator, an import — and their tier-2 template
# asks an implementation question, so a design specification is not a
# subject they are defined over.
# ``no_plaintext_secret`` is regex-over-text but fails (2): its schema text
# and its tier-2 criterion both bind its subject to a file. Excluding it
# costs no capability, since "the design states no credentials" is
# ``pattern_absent`` with a target.
# Widening this set therefore requires arguing both conjuncts for the new
# type, not merely re-deriving it from the schema.
_EXPECTED = frozenset({"pattern_matches", "pattern_absent"})


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

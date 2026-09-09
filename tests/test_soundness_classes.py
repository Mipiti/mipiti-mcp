"""One soundness class per type, declared by the fact reported, read everywhere.

The class is data the platform composes over and the verifier holds its own
registry equal to; nothing infers strength from a type's name, a param, or a
file path. These tests pin the vocabulary, the table, and every surface that
shows it.
"""

import pytest

from mipiti_mcp import assertion_types as at
from mipiti_mcp.assertion_types import (
    ASSERTION_TYPES,
    SOUND_CLASSES,
    SOUND_TYPES,
    SOUNDNESS_BY_TYPE,
    SOUNDNESS_CLASSES,
    SOUNDNESS_MEANING,
    SOUNDNESS_RANK,
    TARGET_CAPABLE_TYPES,
    AssertionTypeSpec,
    describe_soundness_classes,
    describe_types,
    format_compact,
    format_for_docstring,
    soundness_of,
    soundness_rank_of,
)
from mipiti_mcp.server import _SUBMIT_ASSERTIONS_DOC

# The table, pinned by intent: a type moves between classes only by an
# argument about the fact its verdict rests on, never by re-deriving it.
EXPECTED = {
    "presence": {
        "function_exists", "class_exists", "decorator_present", "function_calls",
        "import_present", "file_exists", "file_hash", "config_key_exists",
        "config_value_matches", "env_var_referenced", "dependency_exists",
        "dependency_version", "parameter_validated", "error_handled",
        "middleware_registered", "http_header_set", "test_exists", "module_exists",
        "module_instantiated", "port_exists", "parameter_defined", "signal_exists",
        "sva_assertion_present", "register_reset",
    },
    "under_approximating_scan": {"pattern_matches", "pattern_absent", "no_plaintext_secret"},
    "existential_witness": {"test_attested"},
    "sound_over_approximation": {"sink_default_deny"},
    "by_construction": {"typed_boundary"},
}


def test_vocabulary_is_closed_and_ordered_weakest_to_strongest():
    assert SOUNDNESS_CLASSES == (
        "presence",
        "under_approximating_scan",
        "existential_witness",
        "sound_over_approximation",
        "by_construction",
    )
    assert [SOUNDNESS_RANK[c] for c in SOUNDNESS_CLASSES] == [0, 1, 2, 3, 4]
    assert SOUND_CLASSES == SOUNDNESS_CLASSES[-2:]
    assert set(SOUNDNESS_MEANING) == set(SOUNDNESS_CLASSES)
    for meaning in SOUNDNESS_MEANING.values():
        assert meaning and "mipiti" not in meaning.lower()


def test_every_type_declares_exactly_one_class():
    names = {t.name for t in ASSERTION_TYPES}
    assert names == set().union(*EXPECTED.values())
    assert len(ASSERTION_TYPES) == 30
    for t in ASSERTION_TYPES:
        assert t.soundness in SOUNDNESS_CLASSES, t.name
        assert SOUNDNESS_BY_TYPE[t.name] == t.soundness


@pytest.mark.parametrize("cls", sorted(EXPECTED))
def test_class_table(cls):
    assert {t.name for t in ASSERTION_TYPES if t.soundness == cls} == EXPECTED[cls]


def test_lookups():
    assert soundness_of("test_exists") == "presence"
    assert soundness_of("test_attested") == "existential_witness"
    assert soundness_rank_of("typed_boundary") == 4
    assert soundness_rank_of("sink_default_deny") == 3
    with pytest.raises(KeyError):
        soundness_of("test_passes")
    assert SOUND_TYPES == ("typed_boundary", "sink_default_deny")


def test_a_type_without_a_class_cannot_be_declared():
    with pytest.raises(TypeError):
        AssertionTypeSpec(name="x", description="y")  # type: ignore[call-arg]


def test_an_unknown_class_is_refused_at_import(monkeypatch):
    bad = AssertionTypeSpec(name="x", description="y", soundness="behavioral")
    monkeypatch.setattr(at, "ASSERTION_TYPES", ASSERTION_TYPES + (bad,))
    with pytest.raises(ValueError, match="behavioral"):
        at._check_catalogue()


def test_a_duplicate_type_is_refused_at_import(monkeypatch):
    monkeypatch.setattr(at, "ASSERTION_TYPES", ASSERTION_TYPES + (ASSERTION_TYPES[0],))
    with pytest.raises(ValueError, match="twice"):
        at._check_catalogue()


def test_sound_witnesses_range_over_a_scope_never_a_file_or_a_target(monkeypatch):
    for name in SOUND_TYPES:
        spec = next(t for t in ASSERTION_TYPES if t.name == name)
        params = {p.name for p in spec.params}
        assert not ({"file", "target"} & params), name
        assert "scope" in spec.required_params and "sinks" in spec.required_params
        assert name not in TARGET_CAPABLE_TYPES
    bad = AssertionTypeSpec(
        name="x", description="y", soundness="by_construction",
        params=(at._FILE,),
    )
    monkeypatch.setattr(at, "ASSERTION_TYPES", ASSERTION_TYPES + (bad,))
    with pytest.raises(ValueError, match="file or target"):
        at._check_catalogue()


def test_the_catalogue_as_data_carries_the_class():
    for entry in describe_types():
        assert entry["soundness"] == SOUNDNESS_BY_TYPE[entry["type"]]
    classes = describe_soundness_classes()
    assert [c["name"] for c in classes] == list(SOUNDNESS_CLASSES)
    assert [c["rank"] for c in classes] == [0, 1, 2, 3, 4]
    assert [c["credits_for_all"] for c in classes] == [False, False, False, True, True]
    assert all(c["meaning"] for c in classes)


def test_the_full_reference_shows_the_class_per_type():
    text = format_for_docstring()
    for t in ASSERTION_TYPES:
        assert f"- {t.name} [{t.soundness}]:" in text, t.name


def test_the_compact_form_groups_by_class_strongest_first():
    lines = format_compact().splitlines()
    headings = [l.strip()[1:-1] for l in lines if l.strip().startswith("[")]
    assert headings == list(reversed(SOUNDNESS_CLASSES))
    current = None
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            current = s[1:-1]
            continue
        name = s[2:].split("(", 1)[0]
        assert SOUNDNESS_BY_TYPE[name] == current, name


def test_the_submit_description_lists_the_sound_types_first_and_names_covers():
    doc = _SUBMIT_ASSERTIONS_DOC
    assert doc.index("typed_boundary(") < doc.index("sink_default_deny(") < doc.index("test_attested(")
    assert "covers" in doc
    assert "for-all" in doc
    assert "get_assertion_types" in doc
    # No tool of the verifier is named as the contract of a type.
    for cls in SOUNDNESS_CLASSES:
        assert f"[{cls}]" in doc


def test_test_exists_is_presence_and_says_nothing_ran():
    spec = next(t for t in ASSERTION_TYPES if t.name == "test_exists")
    assert spec.soundness == "presence"
    assert "nothing ran" in spec.description.lower()


@pytest.mark.parametrize("name", sorted(EXPECTED["under_approximating_scan"]))
def test_scan_types_state_what_a_clean_result_cannot_prove(name):
    spec = next(t for t in ASSERTION_TYPES if t.name == name)
    d = spec.description.lower()
    assert "syntactic scan" in d
    assert "only" in d


@pytest.mark.parametrize("name", ["function_exists", "class_exists"])
def test_a_test_file_target_is_presence_and_never_an_anchor(name):
    """A test file's definition existing establishes existence, the same as
    any other definition; the earlier promotion of such a target to
    behavioral evidence is gone, and with it the param that carried it."""
    spec = next(t for t in ASSERTION_TYPES if t.name == name)
    assert spec.soundness == "presence"
    assert "mechanism" not in [p.name for p in spec.params]
    assert "never anchors" in spec.description


def test_the_existential_witness_states_its_bound():
    spec = next(t for t in ASSERTION_TYPES if t.name == "test_attested")
    assert spec.soundness == "existential_witness"
    d = spec.description
    assert "the path it drove" in d
    assert "typed_boundary" in d and "sink_default_deny" in d
    assert "claim" in d  # unsigned / unattested runs are labelled honestly


@pytest.mark.parametrize("name", list(SOUND_TYPES))
def test_the_sound_types_describe_the_fact_and_the_residual(name):
    spec = next(t for t in ASSERTION_TYPES if t.name == name)
    d = spec.description
    assert "scope" in d and "allowlist" in d.lower()
    assert "proves nothing" in d          # vacuous scope
    assert "hardware" in d.lower()        # HDL is first-class
    assert "covers" in d
    assert "mipiti-verify" not in d       # the fact, not a tool


def test_by_construction_is_stated_first_and_states_its_residual():
    tb = next(t for t in ASSERTION_TYPES if t.name == "typed_boundary")
    assert ASSERTION_TYPES[0] is tb
    assert "by name" in tb.description
    sdd = next(t for t in ASSERTION_TYPES if t.name == "sink_default_deny")
    assert "modulo the sink list" in sdd.description
    assert "prefer typed_boundary" in sdd.description


async def test_get_assertion_types_returns_the_vocabulary():
    from mipiti_mcp import server

    out = await server.get_assertion_types(server_version="x")
    assert out["count"] == 30
    assert [c["name"] for c in out["soundness_classes"]] == list(SOUNDNESS_CLASSES)
    assert out["sound_classes"] == list(SOUND_CLASSES)
    assert out["covers"] == {"pattern": at.COVERS_PATTERN, "max": at.COVERS_MAX}
    by_type = {e["type"]: e for e in out["assertion_types"]}
    assert by_type["typed_boundary"]["soundness"] == "by_construction"
    scope = next(p for p in by_type["typed_boundary"]["required_params"] if p["name"] == "scope")
    assert scope["structure"] == "array" and scope["item_schema"]["min_items"] == 1

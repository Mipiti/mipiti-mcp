"""What the published text may claim about the platform it talks to.

Every sentence here is read by an agent that cannot check it. A sentence
that over-reads the API is not a documentation defect: it is a plan the
agent will act on, and the act either fails late or records something that
was never true. These hold the published text to what the API does.
"""

import inspect

import pytest

from mipiti_mcp import server
from mipiti_mcp.assertion_types import describe_types


def _tool_texts() -> dict:
    """Every published text an agent can read: the instructions and each
    tool's name plus the description its client renders."""
    import asyncio

    texts = {"<instructions>": server.build_instructions("pro", "user")}
    for tool in asyncio.run(server.mcp._list_tools()):
        fn = getattr(tool, "fn", None)
        texts[tool.name] = "\n".join(filter(None, [
            tool.description or "",
            inspect.getdoc(fn) if fn is not None else "",
        ]))
    return texts


def _flat(text: str) -> str:
    return " ".join(text.split())


def _doc(name: str) -> str:
    fn = getattr(server, name)
    return _flat((getattr(fn, "__doc__", "") or "") + " " + (
        getattr(getattr(fn, "fn", None), "__doc__", "") or ""))


# ---------------------------------------------------------------------------
# An import arrives unverified.
# ---------------------------------------------------------------------------

def test_an_import_is_published_as_arriving_unverified() -> None:
    """An archive is a record of what its origin claimed, and the importing
    workspace cannot tell a genuine one from a crafted one. So a restored
    model earns its verdicts here by running verification, and the text says
    so where the caller reads the tool -- otherwise an agent restores a model
    and reports it verified on the strength of numbers it carried in."""
    doc = _doc("import_threat_model_archive")
    assert "UNVERIFIED" in doc or "unverified" in doc
    assert "not credited" in doc or "never credited" in doc
    assert "running" in doc and "verification" in doc


def test_the_archive_export_says_whose_record_its_verdicts_are() -> None:
    """The archive carries the origin's verdicts so a third party can check
    what was claimed. Read without that sentence, the same list reads as a
    promise that the verdicts travel to whoever imports it."""
    text = _tool_texts()["export_report"] + "\n" + server.build_instructions("pro", "user")
    flat = _flat(text)
    assert "the origin's record" in flat
    assert "import_threat_model_archive" in flat


def test_the_instructions_state_the_state_a_restored_model_arrives_in() -> None:
    flat = _flat(server.build_instructions("pro", "user"))
    start = flat.index("`import_threat_model_archive`")
    bullet = flat[start:start + 700]
    assert "unverified" in bullet.lower()


# ---------------------------------------------------------------------------
# A parameter skeleton is a fill-in, not a submission.
# ---------------------------------------------------------------------------

def test_no_published_text_calls_a_suggested_submission_prefilled() -> None:
    """The skeleton's placeholders are refused by the same format rule that
    runs on arrival, by design: a placeholder that validated would be a false
    declaration about the caller's code, recorded as evidence. Calling it
    prefilled invites the caller to send it as it stands."""
    offenders = [w for w, t in _tool_texts().items() if "prefilled" in t.lower()]
    assert offenders == [], f"a suggested submission is called prefilled by: {offenders}"


def test_the_work_order_text_says_the_placeholders_are_replaced() -> None:
    for name in ("get_control_work_order", "get_sufficiency"):
        doc = _doc(name)
        assert "skeleton" in doc, name
        assert "replace" in doc, name


def test_the_skeleton_is_described_as_checked_by_the_same_rule_at_both_ends() -> None:
    """The client refuses an unfilled placeholder before the submission
    leaves, with the rule the platform applies on arrival. Saying so is what
    makes 'fill it in' an instruction rather than a suggestion."""
    doc = _doc("get_control_work_order")
    assert "refused" in doc


# ---------------------------------------------------------------------------
# The per-clause work list is stated in observable terms.
# ---------------------------------------------------------------------------

def test_required_evidence_is_published_conditionally() -> None:
    """``required_evidence`` carries an entry where the order names a
    required class for a clause. Published as an unconditional promise, an
    agent that reads an order without one concludes the read is broken."""
    for name in ("get_control_work_order", "get_sufficiency"):
        doc = _doc(name)
        assert "where the order names a required class" in doc.lower() or (
            "where it names a required class" in doc.lower()
        ), name
    flat = _flat(server.build_instructions("pro", "user"))
    assert "where the order names a required class" in flat.lower()


def test_behavioral_is_published_only_as_a_compatibility_field() -> None:
    """``soundness`` is the class of the fact a type reports. ``behavioral``
    is carried for readers written before it, and equating the two would have
    an agent branch on the compatibility field instead."""
    doc = _doc("get_control_work_order")
    assert "compatibility" in doc
    assert 'equals ``soundness' not in doc
    assert 'soundness ==' not in doc


# ---------------------------------------------------------------------------
# The credit path for a for-all clause is what the platform offers.
# ---------------------------------------------------------------------------

def test_the_for_all_credit_path_is_stated_as_what_the_catalogue_returns() -> None:
    """Naming two types unconditionally reads as 'these are always available'.
    The classes are the rule; which types carry them is a read."""
    flat = _flat(server.build_instructions("pro", "user"))
    start = flat.index("A for-all clause needs a sound witness")
    section = flat[start:start + 2600]
    assert "get_assertion_types" in section
    assert "sound_types" in section


def test_the_for_all_rule_names_an_act_when_no_sound_type_is_offered() -> None:
    """An obligation stated with nothing that discharges it reads as 'find
    the right type', and the loop never terminates. The exits that exist are
    named beside the rule."""
    flat = _flat(server.build_instructions("pro", "user"))
    start = flat.index("A for-all clause needs a sound witness")
    section = flat[start:start + 2600]
    assert "risk acceptance" in section
    assert "not-applicable" in section or "not applicable" in section


# ---------------------------------------------------------------------------
# The attacker surface extent is an operator declaration.
# ---------------------------------------------------------------------------

_DERIVATION_PHRASES = (
    "the model derives the reach",
    "a generated suggestion",
    "confirm a generated",
    "extents are generated",
    "suggested`` / ``attested",
    "`suggested`",
)


@pytest.mark.parametrize("phrase", _DERIVATION_PHRASES)
def test_no_published_text_says_the_platform_derives_an_extent(phrase: str) -> None:
    """The published effect of ``surface_extent`` is the attested one: a
    person supplies it with a reason and the objectives that attacker anchors
    carry a for-all obligation. Text describing a derived or suggested extent
    promises an obligation an operator did not ask for and cannot see."""
    offenders = [
        where for where, text in _tool_texts().items()
        if phrase in _flat(text).lower()
    ]
    assert offenders == [], f"{phrase!r} is published by: {offenders}"


def test_an_asset_home_is_published_as_a_refusal_and_not_as_an_obligation() -> None:
    """Where an asset on the objectives an attacker anchors is implemented by
    several components and is not split-knowledge, a narrowing to one named
    entry is refused -- a write-path guard that refuses more and credits
    nothing. Published as an obligation instead ("the property is owed at
    every one"), it would promise an operator a for-all clause that no act of
    theirs raised."""
    doc = _doc("edit_attacker")
    assert "REFUSED" in doc
    offenders = [
        where for where, text in _tool_texts().items()
        if "owed at every" in _flat(text)
    ]
    assert offenders == [], f"an asset's homes are published as raising an obligation by: {offenders}"


def test_the_refusal_messages_do_not_describe_a_derived_extent() -> None:
    """A refusal is read as carefully as a docstring, and these two are the
    sentences a caller meets when the call fails."""
    source = inspect.getsource(server)
    assert "the reach the model derives" not in source
    assert "Factors and extents are generated" not in source


def test_the_attested_effect_is_what_the_instructions_publish() -> None:
    flat = _flat(server.build_instructions("pro", "user"))
    assert "an attested `whole` makes the objectives" in flat.lower()


# ---------------------------------------------------------------------------
# A scope is the region a for-all witness has to range over.
# ---------------------------------------------------------------------------

def test_the_scope_param_says_what_a_for_all_witness_must_cover() -> None:
    """A witness scoped to test or vendored sources enumerates those sources.
    The scope a for-all clause needs is the region holding the components the
    control defends, and the caller writing the scope is the one who knows
    which region that is."""
    spec = {t["type"]: t for t in describe_types(["sink_default_deny", "typed_boundary"])}
    for name in ("sink_default_deny", "typed_boundary"):
        params = spec[name]["required_params"] + spec[name]["optional_params"]
        scope = [q for q in params if q["name"] == "scope"][0]
        text = _flat(scope["description"]).lower()
        assert "components the control defends" in text, name


# ---------------------------------------------------------------------------
# The composed tier of a control.
# ---------------------------------------------------------------------------

def test_the_control_tier_is_published_as_the_weakest_clause() -> None:
    """The read exists, so the catalogue names it -- and names it with the
    rule that makes it safe to read: a claim never reports stronger than the
    thinnest clause it rests on."""
    doc = _doc("get_sufficiency")
    assert "soundness_tier" in doc
    assert "weakest clause" in doc


def test_the_control_tier_is_not_published_as_a_credit() -> None:
    """It reports what was composed. Nothing reads it for coverage, posture
    or a badge, so no text may offer it as a way to make a control count."""
    doc = _doc("get_sufficiency")
    for claim in ("counts as mitigated", "marks the control verified", "earns credit"):
        assert claim not in doc


# ---------------------------------------------------------------------------
# The README is published text too.
# ---------------------------------------------------------------------------

def _readme() -> str:
    import pathlib

    return pathlib.Path(__file__).resolve().parent.parent.joinpath("README.md").read_text()


def test_the_readme_holds_to_the_same_claims_as_the_tools() -> None:
    """A reader who never calls a tool still plans from this file, so it
    carries the same three facts: an import arrives unverified, a suggested
    submission is a skeleton to fill in, and which sound types a platform
    takes is a read rather than a fixed pair of names."""
    text = _flat(_readme())
    assert "prefilled" not in text.lower()
    assert "arrives unverified" in text
    assert "sound_types" in text

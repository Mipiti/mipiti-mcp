"""Tests for build_instructions tier/role logic and content presence."""

import pytest

from mipiti_mcp.server import _SERVER_VERSION, build_instructions


@pytest.mark.parametrize("tier,role", [("pro", "user"), ("developer", "user")])
def test_server_version_is_interpolated(tier: str, role: str) -> None:
    """The instructions must carry the real server_version, not the literal
    ``{_SERVER_VERSION}`` placeholder.

    _INSTRUCTIONS_BASE is a plain string, so the version has to be spliced in
    explicitly. A prior refactor flattened the concatenation into a bare
    ``{_SERVER_VERSION}`` token, which then reached clients verbatim; every
    tool call echoed the placeholder and the version-check middleware rejected
    all of them. Guard both directions: the real value present, the
    placeholder absent.
    """
    text = build_instructions(tier=tier, role=role)
    assert "{_SERVER_VERSION}" not in text
    assert f"`{_SERVER_VERSION}`" in text


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("organization", "user"),
        ("enterprise", "user"),
        ("developer", "admin"),
        ("developer", "superadmin"),
        ("developer", "user"),
    ],
)
def test_constraint_flow_section_present(tier: str, role: str) -> None:
    """The constraint-flow guidance must reach every tier/role combo.

    The section lives in _INSTRUCTIONS_BASE so it should appear in both
    the full instructions (pro+ / admin / superadmin) AND the developer
    tier (which only excludes the compliance block).
    """
    text = build_instructions(tier=tier, role=role)
    assert "When you hit an implementation constraint mid-coding" in text


def test_constraint_flow_section_describes_three_steps() -> None:
    """All three load-bearing tools must be referenced in the section."""
    text = build_instructions("pro", "user")
    # Anchor on the section header so the assertions below exercise the
    # right block and not some unrelated mention elsewhere.
    section_start = text.index("When you hit an implementation constraint mid-coding")
    section_end = text.index("## Assurance posture", section_start)
    section = text[section_start:section_end]

    assert "import_controls" in section
    assert "set_mitigation_groups" in section
    assert "add_assumption" in section
    # Forward reference to parent-repo finding behavior must be discoverable.
    assert "framework_binding_asymmetry" in section


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("developer", "user"),
    ],
)
def test_delegation_section_present(tier: str, role: str) -> None:
    """The cross-model delegation guidance lives in _INSTRUCTIONS_BASE, so it
    must reach every tier (it is not gated behind the compliance block)."""
    text = build_instructions(tier=tier, role=role)
    assert "Cross-model dependencies (delegation)" in text
    for tool in (
        "declare_foundation",
        "create_reliance",
        "confirm_reliance",
        "attach_foundation",
        "list_reliance",
    ):
        assert tool in text


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("developer", "user"),
    ],
)
def test_tags_section_present(tier: str, role: str) -> None:
    """The Tags (grouping) guidance lives in _INSTRUCTIONS_BASE, so it must
    reach every tier."""
    text = build_instructions(tier=tier, role=role)
    assert "## Tags (grouping)" in text
    for tool in (
        "create_group",
        "add_model_to_group",
        "list_groups",
        "get_risk_view",
        "select_compliance_frameworks",
        "get_compliance_report",
        "export_report",
    ):
        assert tool in text


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("developer", "user"),
    ],
)
def test_functional_conformance_section_present(tier: str, role: str) -> None:
    """Functional-conformance guidance (generate + import flows) lives in
    _INSTRUCTIONS_BASE, so it must reach every tier."""
    text = build_instructions(tier=tier, role=role)
    assert "## Functional conformance" in text
    for tool in (
        "generate_functional_objectives",
        "get_scan_prompt",
        "add_functional_test",
        "import_functional_tests",
        "suggest_functional_test_mappings",
        "associate_functional_test",
        "get_functional_coverage",
        "set_functional_satisfaction_groups",
        "get_functional_test_sufficiency",
    ):
        assert tool in text


@pytest.mark.parametrize(
    "tier,role",
    [
        ("pro", "user"),
        ("organization", "user"),
        ("enterprise", "user"),
        ("developer", "admin"),
        ("developer", "superadmin"),
        ("developer", "user"),
    ],
)
def test_verification_diagnostic_path_present(tier: str, role: str) -> None:
    """The "implemented but not verified" triage order must reach every tier.

    Without it an agent reading a control's ``partially_verified`` state has
    no stated order to check in, and the tool whose name reads most like the
    fix (``recompute_verdicts``) is both the wrong surface and the metered
    one.
    """
    text = build_instructions(tier=tier, role=role)
    assert 'Diagnosing "implemented but not verified"' in text


def test_verification_diagnostic_path_orders_free_reads_before_recompute() -> None:
    """Sufficiency must be offered before the metered recompute, and the
    recompute must carry its own scope disclaimer."""
    text = build_instructions("pro", "user")
    section_start = text.index('Diagnosing "implemented but not verified"')
    section_end = text.index("## When you hit an implementation constraint", section_start)
    section = text[section_start:section_end]

    # Free diagnostic reads come first; the metered write comes last.
    assert section.index("get_sufficiency") < section.index("recompute_verdicts")
    assert "dry_run=True" in section
    # coherence_status must be labelled advisory so "pending" is not read as
    # a missing verdict that needs recomputing.
    assert "coherence_status" in section
    assert "advisory" in section
    # A clause that cannot be closed points at the description, not at
    # manufactured evidence.
    assert "refine_control" in section


@pytest.mark.parametrize(
    "tier,role",
    [("pro", "user"), ("organization", "user"), ("developer", "user")],
)
def test_required_vs_defense_in_depth_guidance_present(tier: str, role: str) -> None:
    """An objective whose controls are ALL defense-in-depth cannot leave
    at-risk, and the risk_reason routing alone would send an agent to generate
    or prove controls forever. The routing must say to check the group
    structure first."""
    text = build_instructions(tier=tier, role=role)
    assert "actually REQUIRED for the objective" in text
    section_start = text.index("actually REQUIRED for the objective")
    section = text[section_start:section_start + 900]
    assert "defense_in_depth" in section
    assert "set_mitigation_groups" in section
    # It must name this as a modelling gap, so the agent stops writing evidence.
    assert "not an evidence gap" in section


def test_group_guidance_precedes_the_risk_reason_routing() -> None:
    """The check has to come BEFORE the per-reason actions, or an agent follows
    the first instruction it reads and never reaches the caveat."""
    text = build_instructions("pro", "user")
    assert text.index("actually REQUIRED for the objective") < text.index(
        "**Action routing by risk_reason**"
    )


def _tool_doc(name: str) -> str:
    """The rendered description an agent actually reads for one tool."""
    import mipiti_mcp.server as srv

    fn = getattr(srv, name)
    return (getattr(fn, "__doc__", "") or "") + (
        getattr(getattr(fn, "fn", None), "__doc__", "") or "")


def _flat_doc(name: str) -> str:
    """A tool's rendered description with line wrapping collapsed, so a
    phrase check does not depend on where the docstring breaks a line."""
    return " ".join(_tool_doc(name).split())


def test_auto_resolved_is_filterable():
    """An agent triaging findings has to be able to select the ones the
    platform closed, or it cannot tell them from the ones still open."""
    assert "auto_resolved" in _tool_doc("list_findings")


def test_auto_resolved_is_documented_as_distinct_from_the_human_closures():
    """'The gap is gone' and 'the gap does not matter' are opposite statements
    about residual risk. A reader who conflates them misreads the posture."""
    doc = _tool_doc("list_findings")
    assert "dismissed" in doc and "auto_resolved" in doc
    assert "not worth fixing" in doc or "does not matter" in doc


def test_auto_resolved_is_not_offered_as_a_manual_transition():
    """It asserts a condition is no longer reproduced — a claim only the
    platform can make from its own re-evaluation. Offering it as a manual
    status would invite an agent to forge that claim."""
    doc = _tool_doc("update_finding")
    settable = doc.split("New lifecycle status, one of", 1)[1].split(".", 1)[0]
    assert "auto_resolved" not in settable, (
        "auto_resolved is listed among the manually settable statuses"
    )
    assert "NOT settable" in doc or "not settable" in doc


# ---------------------------------------------------------------------------
# The typed soundness model: what the instructions and tool texts assert.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier,role", [("pro", "user"), ("developer", "user")])
def test_no_phantom_entity_status_fields(tier: str, role: str) -> None:
    """Assets and attackers carry no status field, and the assessment reports
    no asset_status / attacker_status and no asset_absent /
    attacker_irrelevant risk reasons; guidance must not name them."""
    text = build_instructions(tier=tier, role=role)
    for phantom in ("asset_status", "attacker_status", "asset_absent", "attacker_irrelevant",
                    "`status` field", "`confirmed`", "`absent`"):
        assert phantom not in text, phantom



def test_surface_extent_and_the_for_all_rule_are_stated() -> None:
    text = build_instructions("pro", "user")
    assert "surface_extent" in text
    assert "A for-all clause needs a sound witness" in text
    section_start = text.index("A for-all clause needs a sound witness")
    section = text[section_start:section_start + 2000]
    for cls in ("presence", "under_approximating_scan", "existential_witness",
                "sound_over_approximation", "by_construction"):
        assert cls in section, cls
    assert section.index("typed_boundary") < section.index("sink_default_deny")
    assert "never a proof over every site" in section
    assert "required_evidence" in section and "suggested_submission" in section
    assert "covers" in text


def test_components_are_added_after_generation() -> None:
    """The routing is: model first, components after. The reason given for it
    has to be one that holds -- a component is created against a model -- and
    not a claim about what the generation pipeline reads, which this
    repository cannot see and does not decide."""
    text = build_instructions("pro", "user")
    assert "BEFORE `generate_threat_model`" not in text
    assert "a component is created against a model" in text
    assert "generation prompt" not in text
    assert "generation reads no components" not in text


def test_the_create_side_extent_contract_is_published() -> None:
    """An extent supplied on a create is an attested declaration and is
    recorded with its reason; a narrowing is not declarable there at all.
    Both are stated where the caller reads the tool, so a plan is not built
    around a call that is refused."""
    doc = _flat_doc("add_attacker")
    assert "change_reason" in doc
    assert "Only ``whole`` is declarable on a create" in doc
    assert "edit_attacker" in doc
    text = build_instructions("pro", "user")
    assert "only `whole` is declarable" in text


def test_a_resubmission_is_documented_as_an_in_place_re_pointing() -> None:
    """The row an agent already submitted keeps its id and its verdicts when
    the declaration changes. Calling that a supersession would have the agent
    look for a new row and a superseded count that never come back."""
    doc = _flat_doc("submit_assertions")
    assert "adopted onto the row that is already there" in doc
    assert "supersedes the earlier row" not in doc


def test_the_submission_surface_states_the_bound_and_not_the_grade() -> None:
    """Evidence strength is composed per clause, and the composed grade is
    read from the claim (``get_sufficiency``), not returned by a submission.
    So the submit text states the consequence -- the weakest clause bounds
    the control -- and leaves the field name to the read that answers it."""
    doc = _flat_doc("submit_assertions")
    assert "no more strongly than its weakest clause" in doc
    assert "soundness_tier" not in doc
    assert "soundness_tier" in _flat_doc("get_sufficiency")


def test_only_an_attested_seal_drops_reachability() -> None:
    text = build_instructions("pro", "user")
    assert "only an attested seal" in text
    doc = _flat_doc("add_trust_boundary")
    assert "only an ATTESTED seal" in doc and 'seal_source="attested"' in doc



def test_an_attestation_is_a_claim_never_a_for_all_proof() -> None:
    doc = _flat_doc("submit_attestation")
    assert "never a proof over every site" in doc
    assert "never a for-all one" in doc
    text = build_instructions("pro", "user")
    assert "An attestation is a claim" in text


def test_sufficiency_and_work_order_state_by_construction_first() -> None:
    for name in ("get_sufficiency", "get_control_work_order"):
        doc = _tool_doc(name)
        assert doc.index("typed_boundary") < doc.index("sink_default_deny"), name
        assert "required_evidence" in doc, name
        assert "suggested_submission" in doc, name
    doc = _flat_doc("get_sufficiency")
    assert "wrong CLASS" in doc
    doc_wo = _flat_doc("get_control_work_order")
    assert "clause_id" in doc_wo
    wo = _flat_doc("get_control_work_order")
    assert "GENERATED" in wo and "universal_rule" in wo and "sound_types" in wo
    assert "test_passes" not in wo


def test_entity_reads_expose_the_attacker_extent() -> None:
    doc = _tool_doc("get_entity")
    assert "surface_extent_source" in doc
    assert "add or edit them after" in _flat_doc("add_component")
    for name in ("add_asset", "edit_asset", "add_attacker", "edit_attacker"):
        d = _tool_doc(name)
        assert "`status`" not in d, name

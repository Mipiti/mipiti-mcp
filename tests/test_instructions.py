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

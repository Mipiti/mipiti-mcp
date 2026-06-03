"""Tests for build_instructions tier/role logic and content presence."""

import pytest

from mipiti_mcp.server import build_instructions


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

"""Mipiti MCP Server — expose threat modeling tools via Model Context Protocol."""

from __future__ import annotations

from typing import Optional

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from .client import MipitiClient
from .types import ThreatModel

mcp = FastMCP(
    "Mipiti",
    instructions=(
        "Security posture platform. "
        "Tools call the Mipiti API."
    ),
)

_client: MipitiClient | None = None


def _get_client() -> MipitiClient:
    global _client
    if _client is None:
        try:
            _client = MipitiClient()
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
    return _client


# ------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------


def _format_threat_model(model: ThreatModel) -> str:
    """Render a ThreatModel as readable markdown for LLM consumption."""
    lines: list[str] = []
    title = model.title or model.feature_description[:80]
    lines.append(f"# Threat Model: {title}")
    lines.append(f"\n**ID**: `{model.id}` | **Version**: {model.version}")

    if model.trust_boundaries:
        lines.append("\n## Trust Boundaries")
        lines.append("| ID | Description | Crosses |")
        lines.append("| --- | --- | --- |")
        for tb in model.trust_boundaries:
            crosses = ", ".join(tb.crosses) if tb.crosses else ""
            lines.append(f"| {tb.id} | {tb.description} | {crosses} |")

    if model.assets:
        lines.append("\n## Assets")
        lines.append("| ID | Asset | Description | Properties | Impact |")
        lines.append("| --- | --- | --- | --- | --- |")
        for a in model.assets:
            props = ", ".join(p.value for p in a.security_properties)
            lines.append(f"| {a.id} | {a.name} | {a.description} | {props} | {a.impact} |")

    if model.attackers:
        lines.append("\n## Attackers")
        lines.append("| ID | Capability | Position | Archetype | Likelihood |")
        lines.append("| --- | --- | --- | --- | --- |")
        for a in model.attackers:
            lines.append(
                f"| {a.id} | {a.capability} | {a.position} | {a.archetype} | {a.likelihood} |"
            )

    if model.control_objectives:
        lines.append("\n## Control Objectives")
        lines.append("| ID | Asset | Property | Attacker | Risk | Statement |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for co in model.control_objectives:
            lines.append(
                f"| {co.id} | {co.asset_id} | {co.security_property.value} "
                f"| {co.attacker_id} | {co.risk_tier} | {co.statement} |"
            )

    if model.assumptions:
        lines.append("\n## Assumptions")
        lines.append("| ID | Description | Status |")
        lines.append("| --- | --- | --- |")
        for a in model.assumptions:
            lines.append(f"| {a.id} | {a.description} | {a.status} |")

    return "\n".join(lines)


# ------------------------------------------------------------------
# Tool implementations (testable without FastMCP wrapper)
# ------------------------------------------------------------------

STEP_NAMES = {
    1: "Generating assets",
    2: "Refining assets",
    3: "Generating attackers",
    4: "Refining attackers",
    5: "Generating trust boundaries and control objectives",
}


async def _generate_threat_model(
    feature_description: str, ctx: Context
) -> str:
    client = _get_client()

    async def on_progress(step: int, total: int, title: str) -> None:
        await ctx.report_progress(step, total)
        label = STEP_NAMES.get(step, title)
        await ctx.info(f"Step {step}/{total}: {label}")

    try:
        model = await client.generate_threat_model(
            feature_description, on_progress=on_progress
        )
        return _format_threat_model(model)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Generation failed: {exc}") from exc


async def _refine_threat_model(
    model_id: str, instruction: str, ctx: Context
) -> str:
    client = _get_client()

    async def on_progress(step: int, total: int, title: str) -> None:
        await ctx.report_progress(step, total)
        await ctx.info(f"Step {step}/{total}: {title}")

    try:
        model = await client.refine_threat_model(
            model_id, instruction, on_progress=on_progress
        )
        return _format_threat_model(model)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Refinement failed: {exc}") from exc


async def _query_threat_model(model_id: str, question: str) -> str:
    client = _get_client()
    try:
        return await client.query_threat_model(model_id, question)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Query failed: {exc}") from exc


async def _list_threat_models() -> str:
    client = _get_client()
    try:
        models = await client.list_models()
        if not models:
            return "No threat models found."
        lines = [
            "| ID | Title | Version | Created |",
            "| --- | --- | --- | --- |",
        ]
        for m in models:
            title = m.title or m.feature_description[:60]
            lines.append(
                f"| `{m.id}` | {title} | v{m.version} | {m.created_at} |"
            )
        return "\n".join(lines)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Failed to list models: {exc}") from exc


async def _get_threat_model(
    model_id: str, version: Optional[int] = None
) -> str:
    client = _get_client()
    try:
        model = await client.get_model(model_id, version)
        return _format_threat_model(model)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Failed to get model: {exc}") from exc


async def _get_controls(model_id: str) -> str:
    client = _get_client()
    try:
        controls = await client.get_controls(model_id)
        if not controls:
            return "No controls found for this model."
        lines = [
            "| Control | COs | Description | Status |",
            "| --- | --- | --- | --- |",
        ]
        for c in controls:
            status = (
                "Implemented" if c.status == "implemented" else "Not Implemented"
            )
            desc = c.description.replace("\n", " ")
            co_str = ", ".join(c.control_objective_ids)
            lines.append(
                f"| {c.id} | {co_str} | {desc} | {status} |"
            )
        return "\n".join(lines)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Failed to get controls: {exc}") from exc


async def _update_control_status(
    model_id: str,
    control_id: str,
    status: str,
    implementation_notes: str = "",
) -> str:
    if status not in ("implemented", "not_implemented"):
        raise ToolError("status must be 'implemented' or 'not_implemented'.")
    client = _get_client()
    try:
        updated = await client.update_control_status(
            model_id, control_id, status, implementation_notes
        )
        label = "Implemented" if updated.status == "implemented" else "Not Implemented"
        result = f"**{updated.id}** → {label}"
        if updated.implementation_notes:
            result += f"\n\nNotes: {updated.implementation_notes}"
        return result
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Failed to update control status: {exc}") from exc


async def _assess_model(model_id: str) -> str:
    client = _get_client()
    try:
        data = await client.assess_model(model_id)
        s = data.get("summary", {})
        total = s.get("mitigated", 0) + s.get("at_risk", 0) + s.get("unassessed", 0)
        lines = [
            f"## Assurance Report",
            "",
            f"**{total} control objectives** evaluated:",
            f"- Mitigated: {s.get('mitigated', 0)}",
            f"- At Risk: {s.get('at_risk', 0)}",
            f"- Unassessed: {s.get('unassessed', 0)}",
        ]

        # Risk tier breakdown
        risk_tier_summary = data.get("risk_tier_summary", {})
        if risk_tier_summary:
            lines.append("")
            lines.append("### By Risk Tier")
            lines.append("")
            lines.append("| Tier | Mitigated | At Risk | Unassessed |")
            lines.append("| --- | --- | --- | --- |")
            for tier in ["critical", "high", "medium", "low"]:
                if tier in risk_tier_summary:
                    ts = risk_tier_summary[tier]
                    lines.append(
                        f"| {tier.capitalize()} | {ts.get('mitigated', 0)} "
                        f"| {ts.get('at_risk', 0)} | {ts.get('unassessed', 0)} |"
                    )

        residual = [a for a in data.get("assessments", []) if a.get("risk") == "at_risk"]
        if residual:
            lines.append("")
            lines.append("### At-Risk Control Objectives")
            lines.append("")
            lines.append("| CO | Risk | Statement | Implemented | Total | Missing Controls |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            # Sort by risk tier: critical first
            tier_sort = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            residual.sort(key=lambda a: tier_sort.get(a.get("risk_tier", "medium"), 9))
            for a in residual:
                missing = ", ".join(a.get("missing_controls", [])) or "\u2014"
                stmt = a.get("statement", "")[:80].replace("\n", " ")
                risk_tier = a.get("risk_tier", "medium")
                lines.append(
                    f"| {a['control_objective_id']} | {risk_tier} | {stmt} "
                    f"| {a.get('implemented_controls', 0)} | {a.get('total_controls', 0)} | {missing} |"
                )

        return "\n".join(lines)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Assessment failed: {exc}") from exc


async def _export_threat_model(model_id: str, format: str = "csv") -> str:
    if format not in ("csv", "pdf", "docx"):
        raise ToolError("format must be 'csv', 'pdf', or 'docx'.")
    client = _get_client()
    try:
        content = await client.export_model(model_id, format)
        if format == "csv":
            return content.decode("utf-8")
        return (
            f"Export ready. Download from:\n"
            f"{client.api_url}/api/models/{model_id}/export?format={format}\n\n"
            f"Include your API key as the X-API-Key header when downloading."
        )
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Export failed: {exc}") from exc


# ------------------------------------------------------------------
# MCP tool registrations (thin wrappers)
# ------------------------------------------------------------------


@mcp.tool()
async def generate_threat_model(
    feature_description: str, ctx: Context
) -> str:
    """Generate a complete threat model from a feature description.

    Analyzes the feature using the Security Properties (Confidentiality, Integrity,
    Availability, Usage) methodology with capability-defined attackers.
    Produces trust boundaries, asset inventory, attacker inventory,
    control objective matrix, and assumptions.

    This operation takes 30-60 seconds as it runs a 5-step AI pipeline.

    Args:
        feature_description: Description of the feature or system to
            threat model. Can be a few sentences or a detailed spec.
    """
    return await _generate_threat_model(feature_description, ctx)


@mcp.tool()
async def refine_threat_model(
    model_id: str, instruction: str, ctx: Context
) -> str:
    """Refine an existing threat model based on an instruction.

    Updates the model's assets, attackers, trust boundaries, and control
    objectives based on the instruction. Creates a new version.

    Args:
        model_id: ID of the threat model to refine.
        instruction: What to change, e.g. "Add CSRF attack vectors"
            or "Remove the admin user attacker".
    """
    return await _refine_threat_model(model_id, instruction, ctx)


@mcp.tool()
async def query_threat_model(model_id: str, question: str) -> str:
    """Ask a question about an existing threat model.

    Uses AI to answer questions about the model's assets, attackers,
    control objectives, assumptions, or security posture.

    Args:
        model_id: ID of the threat model to query.
        question: The question to ask, e.g. "Does this model cover
            SQL injection?" or "What are the highest-risk assets?".
    """
    return await _query_threat_model(model_id, question)


@mcp.tool()
async def list_threat_models() -> str:
    """List all saved threat models.

    Returns a summary of each model including ID, title, creation date,
    and version number. Use the model ID with other tools to interact
    with a specific model.
    """
    return await _list_threat_models()


@mcp.tool()
async def get_threat_model(
    model_id: str, version: Optional[int] = None
) -> str:
    """Get a specific threat model by ID.

    Returns the full threat model including trust boundaries, assets,
    attackers, control objectives, and assumptions.

    Args:
        model_id: ID of the threat model.
        version: Optional specific version number. Defaults to latest.
    """
    return await _get_threat_model(model_id, version)


@mcp.tool()
async def get_controls(model_id: str) -> str:
    """Get implementation controls for a threat model.

    Returns security controls that should be implemented to satisfy each
    control objective. If controls haven't been generated yet, they will
    be auto-generated first.

    Args:
        model_id: ID of the threat model.
    """
    return await _get_controls(model_id)


@mcp.tool()
async def update_control_status(
    model_id: str,
    control_id: str,
    status: str,
    implementation_notes: str = "",
) -> str:
    """Update the implementation status of a security control.

    Mark a control as implemented or not implemented, optionally with
    notes describing where/how it is satisfied in the codebase.

    Args:
        model_id: ID of the threat model the control belongs to.
        control_id: ID of the control to update (e.g. "CTRL-01").
        status: New status — "implemented" or "not_implemented".
        implementation_notes: Optional free-text notes (e.g. which
            file or mechanism satisfies the control).
    """
    return await _update_control_status(
        model_id, control_id, status, implementation_notes
    )


@mcp.tool()
async def assess_model(model_id: str) -> str:
    """Run an assurance assessment on a threat model.

    Evaluates each control objective based on the implementation status
    of its controls. Returns a summary (mitigated / at_risk / unassessed)
    and details for at-risk objectives. No LLM calls — purely
    deterministic based on control status.

    Args:
        model_id: ID of the threat model to assess.
    """
    return await _assess_model(model_id)


@mcp.tool()
async def export_threat_model(model_id: str, format: str = "csv") -> str:
    """Export a threat model as CSV, PDF, or DOCX.

    CSV content is returned directly as text. For PDF and DOCX, a
    download URL is returned.

    Args:
        model_id: ID of the threat model to export.
        format: Export format — "csv" (default), "pdf", or "docx".
    """
    return await _export_threat_model(model_id, format)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

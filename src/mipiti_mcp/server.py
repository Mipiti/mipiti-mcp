"""Mipiti MCP Server — expose threat modeling tools via Model Context Protocol.

Single codebase for both standalone (stdio) and hosted (Streamable HTTP) modes.
All tools call the Mipiti REST API via MipitiClient.
"""

import asyncio
import contextvars
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from .client import MipitiClient

mcp = FastMCP(
    "Mipiti",
    instructions=(
        "Security posture platform — AI-powered threat modeling with the "
        "Security Properties × Capability Attackers methodology. "
        "Tools call the Mipiti API."
    ),
)

# ------------------------------------------------------------------
# Per-request client (contextvars for hosted mode)
# ------------------------------------------------------------------

_request_client: contextvars.ContextVar[MipitiClient | None] = contextvars.ContextVar(
    "_request_client", default=None,
)
_default_client: MipitiClient | None = None


def set_request_client(client: MipitiClient) -> None:
    """Set a per-request MipitiClient (called by hosting middleware)."""
    _request_client.set(client)


def _get_client() -> MipitiClient:
    rc = _request_client.get(None)
    if rc is not None:
        return rc
    global _default_client
    if _default_client is None:
        try:
            _default_client = MipitiClient()
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
    return _default_client


# ------------------------------------------------------------------
# Background job system (async_mode support)
# ------------------------------------------------------------------

_JOB_TTL = 3600


@dataclass
class _Job:
    id: str
    tool_name: str
    status: str = "running"
    progress: int = 0
    total: int = 0
    message: str = ""
    result: Any = None
    error: str = ""
    created_at: float = field(default_factory=time.monotonic)


_jobs: dict[str, _Job] = {}


def _poll_interval(job: _Job, elapsed: float) -> int:
    if elapsed < 10:
        return 3
    if elapsed < 30:
        return 5
    if elapsed < 120:
        return 10
    return 15


def _start_job(tool_name: str, coro_factory, kwargs: dict) -> str:
    # Evict expired jobs
    now = time.monotonic()
    expired = [k for k, j in _jobs.items() if now - j.created_at > _JOB_TTL]
    for k in expired:
        del _jobs[k]

    job_id = f"job_{uuid.uuid4().hex[:12]}"
    job = _Job(id=job_id, tool_name=tool_name)
    _jobs[job_id] = job

    # Capture the per-request client for the background thread
    caller_client = _request_client.get(None)

    def _run():
        loop = asyncio.new_event_loop()
        # Propagate per-request client into the new thread's contextvars
        if caller_client is not None:
            _request_client.set(caller_client)
        try:
            result = loop.run_until_complete(coro_factory(**kwargs))
            job.result = result
            job.status = "completed"
        except Exception as e:
            job.error = str(e)
            job.status = "failed"
        finally:
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return job_id


def _dump(obj: Any) -> dict:
    """Convert Pydantic model or list to dict for MCP tool response."""
    from pydantic import BaseModel
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, list):
        return [_dump(item) for item in obj]
    return obj


def _api_error(exc: Exception) -> ToolError:
    """Convert an httpx error into a ToolError with a clean message."""
    import httpx
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            detail = exc.response.json().get("detail", str(exc))
        except Exception:
            detail = exc.response.text or str(exc)
        return ToolError(f"API error ({exc.response.status_code}): {detail}")
    return ToolError(str(exc))


# ------------------------------------------------------------------
# Tool implementations
# ------------------------------------------------------------------

STEP_NAMES = {
    1: "Generating assets",
    2: "Refining assets",
    3: "Generating attackers",
    4: "Refining attackers",
    5: "Generating trust boundaries and control objectives",
}


# === Threat Model Generation & Management ===


@mcp.tool()
async def generate_threat_model(
    feature_description: str,
    ctx: Context,
    workspace_id: Optional[str] = None,
    async_mode: bool = True,
    force: bool = False,
) -> dict:
    """Generate a complete threat model from a feature description.

    Analyzes the feature using the Security Properties (Confidentiality, Integrity,
    Availability, Usage) methodology with capability-defined attackers.
    Produces trust boundaries, asset inventory, attacker inventory,
    control objective matrix, and assumptions.

    This operation takes 30-60 seconds as it runs a 5-step AI pipeline.

    Args:
        feature_description: Description of the feature or system to
            threat model. Can be a few sentences or a detailed spec.
        workspace_id: Optional workspace to create the model in.
        async_mode: If True (default), returns a job_id for polling.
        force: Skip similar model detection.
    """
    def _summarise(result):
        tm = result.threat_model
        return {
            "model_id": tm.id,
            "version": tm.version,
            "title": tm.title,
            "asset_count": len(tm.assets),
            "attacker_count": len(tm.attackers),
            "control_objective_count": len(tm.control_objectives),
        }

    async def _run(**kw):
        client = _get_client()
        try:
            result = await client.generate_threat_model(kw["feature_description"])
            return _summarise(result)
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        job_id = _start_job("generate_threat_model", _run,
                            {"feature_description": feature_description})
        return {"job_id": job_id}

    client = _get_client()
    async def on_progress(step, total, title):
        await ctx.report_progress(step, total)
        label = STEP_NAMES.get(step, title)
        await ctx.info(f"Step {step}/{total}: {label}")
    try:
        result = await client.generate_threat_model(
            feature_description, on_progress=on_progress,
        )
        return _summarise(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def refine_threat_model(
    model_id: str,
    instruction: str,
    ctx: Context,
    async_mode: bool = True,
) -> dict:
    """Refine an existing threat model based on an instruction.

    Updates the model's assets, attackers, trust boundaries, and control
    objectives based on the instruction. Creates a new version.
    Takes 30-60 seconds.

    Args:
        model_id: ID of the threat model to refine.
        instruction: What to change, e.g. "Add CSRF attack vectors".
        async_mode: If True (default), returns a job_id for polling.
    """
    def _summarise(result):
        tm = result.threat_model
        return {
            "model_id": tm.id,
            "version": tm.version,
            "title": tm.title,
            "asset_count": len(tm.assets),
            "attacker_count": len(tm.attackers),
            "control_objective_count": len(tm.control_objectives),
        }

    async def _run(**kw):
        client = _get_client()
        try:
            result = await client.refine_threat_model(kw["model_id"], kw["instruction"])
            return _summarise(result)
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        job_id = _start_job("refine_threat_model", _run,
                            {"model_id": model_id, "instruction": instruction})
        return {"job_id": job_id}

    client = _get_client()
    async def on_progress(step, total, title):
        await ctx.report_progress(step, total)
        await ctx.info(f"Step {step}/{total}: {title}")
    try:
        result = await client.refine_threat_model(
            model_id, instruction, on_progress=on_progress,
        )
        return _summarise(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def query_threat_model(
    model_id: str,
    question: str,
    ctx: Context,
    async_mode: bool = False,
) -> dict:
    """Ask a question about an existing threat model.

    Uses AI to answer questions about the model's assets, attackers,
    control objectives, assumptions, or security posture.

    Args:
        model_id: ID of the threat model to query.
        question: The question to ask.
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        client = _get_client()
        try:
            result = await client.query_threat_model(kw["model_id"], kw["question"])
            return {"model_id": kw["model_id"], "answer": result.content}
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("query_threat_model", _impl,
                                     {"model_id": model_id, "question": question})}
    return await _impl(model_id=model_id, question=question)


@mcp.tool()
async def list_threat_models(workspace_id: Optional[str] = None) -> dict:
    """List all saved threat models.

    Returns a summary of each model including ID, title, creation date,
    and version number. Use the model ID with other tools.
    """
    try:
        models = await _get_client().list_models()
        items = []
        for m in models:
            items.append({
                "id": m.id,
                "title": m.title or m.feature_description[:80],
                "version": m.version,
                "created_at": m.created_at,
            })
        return {"items": items, "count": len(items)}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def rename_threat_model(model_id: str, name: str) -> dict:
    """Rename a threat model. Metadata change only, does not create new version.

    Args:
        model_id: ID of the threat model.
        name: New name (1-120 chars).
    """
    try:
        result = await _get_client().rename_model(model_id, name)
        return result.model_dump()
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_threat_model(model_id: str) -> dict:
    """Delete a threat model and all associated data. This cannot be undone.

    Args:
        model_id: ID of the threat model to delete.
    """
    try:
        await _get_client().delete_model(model_id)
        return {"deleted": True, "model_id": model_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_threat_model(
    model_id: str,
    version: Optional[int] = None,
    include_cos: bool = False,
) -> dict:
    """Get a specific threat model by ID.

    Returns the full threat model including trust boundaries, assets,
    attackers, control objectives, and assumptions.

    Args:
        model_id: ID of the threat model.
        version: Optional specific version number. Defaults to latest.
        include_cos: Include control objectives inline.
    """
    try:
        model = await _get_client().get_model(model_id, version)
        return model.model_dump()
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def export_threat_model(model_id: str, format: str = "csv") -> str:
    """Export a threat model as CSV, PDF, or HTML.

    CSV content is returned directly as text. For PDF and HTML,
    a download URL is returned.

    Args:
        model_id: ID of the threat model to export.
        format: Export format — "csv" (default), "pdf", or "html".
    """
    if format not in ("csv", "pdf", "html"):
        raise ToolError("format must be 'csv', 'pdf', or 'html'.")
    try:
        content = await _get_client().export_model(model_id, format)
        if format == "csv":
            return content.decode("utf-8")
        client = _get_client()
        return (
            f"Export ready. Download from:\n"
            f"{client.api_url}/api/models/{model_id}/export?format={format}\n\n"
            f"Include your API key as the X-API-Key header when downloading."
        )
    except Exception as exc:
        raise _api_error(exc) from exc


# === Controls ===


@mcp.tool()
async def get_controls(
    model_id: str,
    ctx: Context,
    control_id: Optional[str] = None,
    status: Optional[str] = None,
    co_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
    include_deleted: bool = False,
    async_mode: bool = False,
) -> dict:
    """Get implementation controls for a threat model.

    Returns controls that should be implemented to satisfy control objectives.
    If controls haven't been generated yet, auto-generates them.

    Args:
        model_id: ID of the threat model.
        control_id: Optional specific control for detail mode.
        status: Filter by "implemented", "not_implemented", "verified".
        co_id: Filter by control objective ID.
        offset: Skip first N (for pagination).
        limit: Max to return (0=all).
        include_deleted: Include soft-deleted controls.
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            data = await _get_client().get_controls(kw["model_id"], include_deleted=kw.get("include_deleted", False))
            controls = list(data.controls)

            # Client-side filtering
            if kw.get("control_id"):
                controls = [c for c in controls if c.id == kw["control_id"]]
            if kw.get("status"):
                controls = [c for c in controls if c.status == kw["status"]]
            if kw.get("co_id"):
                controls = [c for c in controls if kw["co_id"] in c.control_objective_ids]

            total = len(controls)
            if kw.get("offset"):
                controls = controls[kw["offset"]:]
            if kw.get("limit"):
                controls = controls[:kw["limit"]]

            return {
                "model_id": kw["model_id"],
                "total": total,
                "returned": len(controls),
                "controls": [c.model_dump() for c in controls],
            }
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("get_controls", _impl, {
            "model_id": model_id, "control_id": control_id, "status": status,
            "co_id": co_id, "offset": offset, "limit": limit,
            "include_deleted": include_deleted,
        })}
    return await _impl(
        model_id=model_id, control_id=control_id, status=status,
        co_id=co_id, offset=offset, limit=limit,
        include_deleted=include_deleted,
    )


@mcp.tool()
async def regenerate_controls(
    model_id: str,
    ctx: Context,
    async_mode: bool = False,
) -> dict:
    """Delete existing controls and regenerate from scratch.

    WARNING: Deletes all existing controls including implementation status.
    Takes 30-60 seconds.

    Args:
        model_id: ID of the threat model.
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            return _dump(await _get_client().regenerate_controls(kw["model_id"]))
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("regenerate_controls", _impl, {"model_id": model_id})}
    return await _impl(model_id=model_id)


@mcp.tool()
async def update_control_status(
    model_id: str,
    control_id: str,
    status: str,
    implementation_notes: str = "",
    evidence: str = "",
) -> dict:
    """Update the implementation status of a security control.

    Args:
        model_id: ID of the threat model the control belongs to.
        control_id: ID of the control to update (e.g. "CTRL-01").
        status: New status — "implemented" or "not_implemented".
        implementation_notes: Optional free-text notes.
        evidence: Optional JSON-encoded list of evidence items.
    """
    if status not in ("implemented", "not_implemented"):
        raise ToolError("status must be 'implemented' or 'not_implemented'.")
    evidence_list = None
    if evidence:
        try:
            evidence_list = json.loads(evidence)
        except json.JSONDecodeError:
            raise ToolError("evidence must be valid JSON array.")
    try:
        return _dump(await _get_client().update_control_status(
            model_id, control_id, status, implementation_notes, evidence_list,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_evidence(
    model_id: str,
    control_id: str,
    type: str = "code",
    label: str = "",
    url: str = "",
) -> dict:
    """Add an evidence item to a control without changing status or notes.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        type: Evidence type: "code", "test", "config", "document", "link".
        label: Description of evidence (required).
        url: Optional file path or URL.
    """
    if not label.strip():
        raise ToolError("label is required.")
    try:
        return _dump(await _get_client().add_evidence(model_id, control_id, type, label, url))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_evidence(
    model_id: str,
    control_id: str,
    evidence_index: int = 0,
) -> dict:
    """Remove an evidence item from a control by index.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        evidence_index: Zero-based index to remove.
    """
    try:
        return _dump(await _get_client().remove_evidence(model_id, control_id, evidence_index))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def import_controls(
    model_id: str,
    ctx: Context,
    controls_json: str = "",
    free_text: str = "",
    source_label: str = "",
    auto_map: bool = True,
    async_mode: bool = False,
) -> dict:
    """Import existing security controls into a threat model.

    Accepts structured JSON or free-text. Controls auto-mapped to COs
    and deduplicated against existing. Takes 10-30 seconds.

    Args:
        model_id: ID of the threat model.
        controls_json: JSON array of {description, co_ids?, framework_refs?}.
        free_text: Free-text controls (narrative/CSV/bullets).
        source_label: Origin label (e.g., "ISO 27001").
        auto_map: Auto-map controls to COs using LLM (default: True).
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            return _dump(await _get_client().import_controls(
                kw["model_id"], kw.get("controls_json", ""),
                kw.get("free_text", ""), kw.get("source_label", ""),
                kw.get("auto_map", True),
            ))
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("import_controls", _impl, {
            "model_id": model_id, "controls_json": controls_json,
            "free_text": free_text, "source_label": source_label,
            "auto_map": auto_map,
        })}
    return await _impl(
        model_id=model_id, controls_json=controls_json,
        free_text=free_text, source_label=source_label, auto_map=auto_map,
    )


@mcp.tool()
async def delete_control(
    model_id: str,
    control_id: str,
    reason: str = "",
) -> dict:
    """Soft-delete a security control with justification.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to delete.
        reason: Justification for deletion.
    """
    try:
        return _dump(await _get_client().delete_control(model_id, control_id, reason))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def check_control_gaps(
    model_id: str,
    ctx: Context,
    async_mode: bool = False,
) -> dict:
    """Check for missing controls.

    Analyzes existing controls against control objectives and suggests
    COs with insufficient coverage.

    Args:
        model_id: ID of the threat model.
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            return _dump(await _get_client().check_control_gaps(kw["model_id"]))
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("check_control_gaps", _impl, {"model_id": model_id})}
    return await _impl(model_id=model_id)


# === Control Objectives & Assurance ===


@mcp.tool()
async def get_control_objectives(
    model_id: str,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Get control objective matrix for a threat model.

    Returns COs with references to which controls cover each one.
    By default returns compact summary (total count only).
    Pass offset/limit to retrieve specific COs.

    Args:
        model_id: ID of the threat model.
        offset: Skip first N.
        limit: Max to return (0=summary only).
    """
    try:
        return _dump(await _get_client().get_control_objectives(model_id, offset, limit))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def assess_model(
    model_id: str,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Run assurance assessment on a threat model.

    Evaluates each control objective based on control implementation status.
    Returns summary (mitigated/at_risk/unassessed). No LLM calls — deterministic.

    Args:
        model_id: ID of the threat model to assess.
        status: Filter: "mitigated", "at_risk", "unassessed".
        offset: Skip first N.
        limit: Max to return.
    """
    try:
        return _dump(await _get_client().assess_model(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_review_queue() -> dict:
    """Returns controls not reviewed in 90+ days.

    Lists implemented/verified controls whose evidence has not been checked
    recently. For each stale control, verify evidence against codebase.
    """
    try:
        return _dump(await _get_client().get_review_queue())
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assets & Attackers ===


@mcp.tool()
async def add_asset(
    model_id: str,
    name: str,
    description: str = "",
    security_properties: Optional[list[str]] = None,
    impact: str = "M",
    notes: str = "",
) -> dict:
    """Add a new asset to a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        name: Asset name (required).
        description: Optional description.
        security_properties: List of "C", "I", "A", "U" (default: ["C"]).
        impact: Impact level: "H", "M", "L".
        notes: Optional notes.
    """
    body: dict[str, Any] = {"name": name, "impact": impact}
    if description:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = security_properties
    if notes:
        body["notes"] = notes
    try:
        return _dump(await _get_client().add_asset(model_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_asset(
    model_id: str,
    asset_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    security_properties: Optional[list[str]] = None,
    impact: Optional[str] = None,
    notes: Optional[str] = None,
) -> dict:
    """Edit an existing asset. Creates a new version. Only provided fields changed.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset (e.g., "A1").
        name: New name (optional).
        description: New description (optional).
        security_properties: New properties (optional).
        impact: New impact level (optional).
        notes: New notes (optional).
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if description is not None:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = security_properties
    if impact is not None:
        body["impact"] = impact
    if notes is not None:
        body["notes"] = notes
    try:
        return _dump(await _get_client().edit_asset(model_id, asset_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_asset(model_id: str, asset_id: str) -> dict:
    """Remove an asset from a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset to remove.
    """
    try:
        return _dump(await _get_client().remove_asset(model_id, asset_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_attacker(
    model_id: str,
    capability: str,
    position: str = "",
    archetype: str = "",
    likelihood: str = "M",
) -> dict:
    """Add a new attacker to a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        capability: Attacker capability description (required).
        position: Position/access level.
        archetype: Archetype (e.g., "insider", "external").
        likelihood: Likelihood: "H", "M", "L".
    """
    body: dict[str, Any] = {"capability": capability, "likelihood": likelihood}
    if position:
        body["position"] = position
    if archetype:
        body["archetype"] = archetype
    try:
        return _dump(await _get_client().add_attacker(model_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_attacker(
    model_id: str,
    attacker_id: str,
    capability: Optional[str] = None,
    position: Optional[str] = None,
    archetype: Optional[str] = None,
    likelihood: Optional[str] = None,
) -> dict:
    """Edit an existing attacker. Creates a new version. Only provided fields changed.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker (e.g., "T1").
        capability: New capability (optional).
        position: New position (optional).
        archetype: New archetype (optional).
        likelihood: New likelihood (optional).
    """
    body: dict[str, Any] = {}
    if capability is not None:
        body["capability"] = capability
    if position is not None:
        body["position"] = position
    if archetype is not None:
        body["archetype"] = archetype
    if likelihood is not None:
        body["likelihood"] = likelihood
    try:
        return _dump(await _get_client().edit_attacker(model_id, attacker_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_attacker(model_id: str, attacker_id: str) -> dict:
    """Remove an attacker from a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker to remove.
    """
    try:
        return _dump(await _get_client().remove_attacker(model_id, attacker_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Compliance ===


@mcp.tool()
async def list_compliance_frameworks() -> dict:
    """List available compliance frameworks.

    Returns built-in frameworks (e.g., OWASP ASVS) and custom frameworks.
    """
    try:
        return _dump(await _get_client().list_compliance_frameworks())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def select_compliance_frameworks(
    model_id: str,
    framework_ids: list[str],
) -> dict:
    """Select compliance frameworks for a threat model. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        framework_ids: List of framework IDs to select.
    """
    try:
        return _dump(await _get_client().select_compliance_frameworks(model_id, framework_ids))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_compliance_report(
    model_id: str,
    framework_id: str,
    level: Optional[int] = None,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Get compliance gap analysis report.

    Evaluates each framework requirement against mapped controls.
    By default returns summary; pass status/offset/limit for details.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        level: Optional level filter (e.g., 1 for L1 only).
        status: Filter: "covered", "partial", "uncovered", "unmapped", "excluded".
        offset: Skip first N.
        limit: Max to return.
    """
    try:
        return _dump(await _get_client().get_compliance_report(
            model_id, framework_id, level, status or "", offset, limit,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def map_control_to_requirement(
    model_id: str,
    framework_id: str,
    requirement_id: str,
    control_id: str,
    confidence: str = "manual",
    notes: str = "",
) -> dict:
    """Map a security control to a compliance framework requirement.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        requirement_id: ID of the requirement (e.g., "V2.1.1").
        control_id: ID of the control (e.g., "CTRL-01").
        confidence: Mapping confidence: "llm", "manual", "verified".
        notes: Optional notes about mapping.
    """
    try:
        return _dump(await _get_client().map_control_to_requirement(
            model_id, framework_id, requirement_id, control_id, confidence, notes,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def auto_map_controls(
    model_id: str,
    framework_id: str,
    ctx: Context,
    control_id: Optional[str] = None,
    async_mode: bool = False,
) -> dict:
    """Use LLM to map controls to framework requirements. Takes 20-45 seconds.

    Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        control_id: Optional specific control to map.
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            return _dump(await _get_client().auto_map_controls(
                kw["model_id"], kw["framework_id"], kw.get("control_id", ""),
            ))
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("auto_map_controls", _impl, {
            "model_id": model_id, "framework_id": framework_id,
            "control_id": control_id or "",
        })}
    return await _impl(model_id=model_id, framework_id=framework_id,
                       control_id=control_id or "")


@mcp.tool()
async def suggest_compliance_remediation(
    model_id: str,
    framework_id: str,
    ctx: Context,
    async_mode: bool = True,
) -> dict:
    """Suggest missing assets and attackers to close compliance gaps.

    Takes 3-5 minutes. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        async_mode: If True (default), returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            return _dump(await _get_client().suggest_compliance_remediation(
                kw["model_id"], kw["framework_id"],
            ))
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("suggest_compliance_remediation", _impl, {
            "model_id": model_id, "framework_id": framework_id,
        })}
    return await _impl(model_id=model_id, framework_id=framework_id)


@mcp.tool()
async def apply_compliance_remediation(
    model_id: str,
    framework_id: str,
    ctx: Context,
    job_id: Optional[str] = None,
    suggestions: Optional[list[dict]] = None,
) -> dict:
    """Apply approved remediation suggestions to a threat model.

    Preferred: pass job_id from suggest_compliance_remediation.
    Alternative: pass suggestions directly.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        job_id: Job ID from suggest_compliance_remediation.
        suggestions: Direct list of suggestions (if no job_id).
    """
    actual_suggestions = suggestions
    if job_id and not actual_suggestions:
        job = _jobs.get(job_id)
        if job is None:
            raise ToolError(f"Job {job_id} not found.")
        if job.status != "completed":
            raise ToolError(f"Job {job_id} is {job.status}, not completed.")
        actual_suggestions = job.result.get("suggestions", []) if isinstance(job.result, dict) else []

    try:
        return _dump(await _get_client().apply_compliance_remediation(
            model_id, framework_id, actual_suggestions,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Workspaces & Systems ===


@mcp.tool()
async def list_workspaces() -> dict:
    """List workspaces the current user belongs to."""
    try:
        return _dump(await _get_client().list_workspaces())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_systems(workspace_id: Optional[str] = None) -> dict:
    """List all saved systems in current workspace.

    Args:
        workspace_id: Optional workspace to list from.
    """
    try:
        return _dump(await _get_client().list_systems(workspace_id or ""))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_system(system_id: str) -> dict:
    """Get a system container by ID with member model summaries.

    Args:
        system_id: ID of the system to retrieve.
    """
    try:
        return _dump(await _get_client().get_system(system_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def create_system(
    name: str,
    description: str = "",
    workspace_id: Optional[str] = None,
) -> dict:
    """Create a new system container.

    Args:
        name: System name (e.g., "Mobile Banking Platform").
        description: Optional description.
        workspace_id: Optional workspace to create in.
    """
    try:
        return _dump(await _get_client().create_system(name, description, workspace_id or ""))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_model_to_system(system_id: str, model_id: str) -> dict:
    """Add a threat model to a system container.

    Args:
        system_id: ID of the system.
        model_id: ID of the threat model to add.
    """
    try:
        return _dump(await _get_client().add_model_to_system(system_id, model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === System Compliance ===


@mcp.tool()
async def select_system_compliance_frameworks(
    system_id: str,
    framework_ids: list[str],
) -> dict:
    """Select compliance frameworks for a system. Requires PRO tier.

    Args:
        system_id: ID of the system.
        framework_ids: List of framework IDs to select.
    """
    try:
        return _dump(await _get_client().select_system_compliance_frameworks(system_id, framework_ids))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_system_compliance_report(
    system_id: str,
    framework_id: str,
    level: Optional[int] = None,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Get aggregated compliance report for a system. Requires PRO tier.

    Args:
        system_id: ID of the system.
        framework_id: ID of the compliance framework.
        level: Optional level filter.
        status: Filter: "covered", "partial", "uncovered", "unmapped", "excluded".
        offset: Skip first N.
        limit: Max to return.
    """
    try:
        return _dump(await _get_client().get_system_compliance_report(
            system_id, framework_id, level, status or "", offset, limit,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assertions & Verification ===


@mcp.tool()
async def submit_assertions(
    model_id: str,
    control_id: str,
    assertions_json: str,
) -> dict:
    """Submit evidence assertions for a security control. Requires PRO tier.

    Each assertion is a typed, machine-verifiable claim about a codebase property.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-01").
        assertions_json: JSON array of assertion objects with type, params, description.
    """
    try:
        assertions = json.loads(assertions_json)
    except json.JSONDecodeError:
        raise ToolError("assertions_json must be valid JSON array.")
    try:
        return _dump(await _get_client().submit_assertions(model_id, control_id, assertions))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_assertions(model_id: str, control_id: str) -> dict:
    """List active evidence assertions for a security control.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
    """
    try:
        return _dump(await _get_client().list_assertions(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_assertion(
    model_id: str,
    control_id: str,
    assertion_id: str,
) -> dict:
    """Delete an evidence assertion. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        assertion_id: ID of the assertion to delete.
    """
    try:
        await _get_client().delete_assertion(model_id, control_id, assertion_id)
        return {"deleted": True, "assertion_id": assertion_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_verification_report(model_id: str) -> dict:
    """Get verification report with summary stats and drift detection.

    Returns tier1/tier2 pass/fail/pending counts, per-control verification
    status, and drift items. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_verification_report(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def mark_evidence_complete(model_id: str, control_id: str) -> dict:
    """Mark evidence as complete for a control.

    Call after submitting all assertions. Enables Tier 2 semantic verification
    and collective sufficiency evaluation. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-01").
    """
    try:
        return _dump(await _get_client().mark_evidence_complete(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Findings ===


@mcp.tool()
async def submit_findings(
    model_id: str,
    findings_json: str,
) -> dict:
    """Submit negative findings discovered by scanning codebase. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        findings_json: JSON array of finding objects with control_id, title,
            description, severity, checked_locations, checked_patterns,
            expected_evidence.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        raise ToolError("findings_json must be valid JSON array.")
    try:
        return _dump(await _get_client().submit_findings(model_id, findings))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_findings(
    model_id: str,
    control_id: str = "",
    status: str = "",
) -> dict:
    """List negative findings for a threat model. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        control_id: Optional filter by control ID.
        status: Optional filter: "discovered", "acknowledged", "remediated",
            "verified", "dismissed".
    """
    try:
        return _dump(await _get_client().list_findings(model_id, control_id, status))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def update_finding(
    model_id: str,
    finding_id: str,
    status: str,
    notes: str = "",
    reason: str = "",
    remediation_assertion_ids: str = "",
) -> dict:
    """Update lifecycle status of a finding. Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        finding_id: ID of the finding.
        status: New status.
        notes: Optional notes.
        reason: Optional reason (required for dismissal).
        remediation_assertion_ids: Comma-separated assertion IDs linking fix.
    """
    try:
        return _dump(await _get_client().update_finding(
            model_id, finding_id, status, notes, reason, remediation_assertion_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Scan Prompt ===


@mcp.tool()
async def get_scan_prompt(
    model_id: str,
    control_id: str = "",
) -> dict:
    """Get scan prompt to guide codebase gap discovery. Requires PRO tier.

    Returns prompts instructing agent what to look for when scanning
    codebase against controls. Only includes NOT_IMPLEMENTED controls.

    Args:
        model_id: ID of the threat model.
        control_id: Optional specific control ID.
    """
    try:
        return _dump(await _get_client().get_scan_prompt(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Async Operations ===


@mcp.tool()
async def get_operation_status(job_id: str) -> dict:
    """Check status of a background operation.

    Returns progress updates while running. When complete, returns result.

    IMPORTANT POLLING PROTOCOL: When status="running", response includes
    poll_after_seconds. MUST sleep for that many seconds before calling again.

    Args:
        job_id: Job ID returned when async_mode=True.
    """
    job = _jobs.get(job_id)
    if job is None:
        raise ToolError(f"Unknown job_id: {job_id}")

    elapsed = time.monotonic() - job.created_at
    result: dict[str, Any] = {
        "job_id": job.id,
        "tool_name": job.tool_name,
        "status": job.status,
        "progress": job.progress,
        "total": job.total,
        "message": job.message,
        "elapsed_seconds": round(elapsed, 1),
    }

    if job.status == "running":
        result["poll_after_seconds"] = _poll_interval(job, elapsed)
        result["instruction"] = (
            f"Operation in progress. Wait {result['poll_after_seconds']} seconds "
            f"before polling again."
        )
    elif job.status == "completed":
        result["result"] = job.result
    elif job.status == "failed":
        result["error"] = job.error

    return result


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

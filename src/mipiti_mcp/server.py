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
from typing import Any, Literal, Optional

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from .assertion_types import format_for_docstring
from .client import MipitiClient

# ------------------------------------------------------------------
# Instructions (tier-aware)
# ------------------------------------------------------------------

_SERVER_VERSION = "1"

_INSTRUCTIONS_UPDATE_MESSAGE = (
    "Server instructions have been updated since your session started. "
    "Reconnect your MCP client to get the latest capabilities "
    "(e.g., run /mcp in Claude Code and reconnect)."
)

_INSTRUCTIONS_BASE = """\
Mipiti generates threat models from feature descriptions and tracks security \
controls with machine-verifiable assertions.

Every tool call must include `server_version` set to """ + f'`{_SERVER_VERSION}`' + """.
If the server responds with an `instructions_updated` field, relay the message \
to the user, in a way appropriate to your environment, then continue with the \
current task.

## When to use

Before implementing changes, call `generate_threat_model` with a description \
of the change. It automatically discovers similar existing models — either \
returning matches to refine or proceeding with generation. Use the resulting \
controls to guide your implementation.

## Threat modeling

- `generate_threat_model` — creates a new model with trust boundaries, \
assets, attackers, and control objectives. Automatically detects similar \
existing models and routes accordingly. Returns a `job_id` — poll with \
`get_operation_status`.
- `refine_threat_model` — updates an existing model when you already have \
a model ID and want to change it (returns `job_id`).
- `add_asset` / `edit_asset` / `remove_asset` — targeted single-entity \
changes without full refinement. Each asset has a `status` field: \
`unverified` (default), `confirmed` (assertions prove it exists), \
`absent` (agent confirmed it is not applicable). Use `edit_asset` to \
update status after verifying.
- `add_attacker` / `edit_attacker` / `remove_attacker` — same for attackers. \
Attacker `status` works the same way: `confirmed` means the attack \
surface exists, `absent` means it is not applicable.
- `get_threat_model` — retrieve a model's full structure (excludes COs by \
default; use `include_cos=True` to include them).
- `query_threat_model` — ask questions about an existing model.
- `list_threat_models` — browse existing models.
- `rename_threat_model` — rename a model (metadata only, no new version).
- `delete_threat_model` — permanently delete a model and all its data.
- `export_threat_model` — download as PDF, HTML, or CSV.

## Controls and assertions

A threat model produces control objectives. Controls are derived from these \
and represent specific security requirements to implement. Assertions are \
typed, machine-verifiable claims about system properties that prove a \
control is satisfied. A system property can be verified by examining \
source code, configuration files, infrastructure definitions, or \
external service settings.

**Key tools:**
- `get_controls` — lists controls with current status. Use `summary_only=True` \
for a compact response (id, description, status, assertion_count only).
- `get_control_objectives` — lists COs with which controls cover each one. \
Includes `boundary_reachable` and `boundary_unreachable_reason` per CO. \
Useful for understanding scope before linking assumptions or regenerating.
- `submit_assertions` — provide proof for a control. See that tool's docstring for \
assertion types and required params. Always verify locally first: \
`mipiti-verify verify <type> -p key=value --project-root .` \
Read the target file and confirm a reviewer would agree with the claim.
- `list_assertions` / `delete_assertion` — list active assertions for a control; \
delete stale or incorrect ones before resubmitting.
- `update_control_status` — mark implemented or not_implemented. Requires \
at least one assertion BEFORE marking implemented. Always submit \
assertions first, then update status.
- `get_verification_report` — shows which controls are verified, which \
have sufficiency gaps, and which lack assertions entirely. Read \
`sufficiency_details` for the specific aspects that still need proof.
- `get_sufficiency` — quick check: do assertions for a single control \
collectively cover all aspects? Evaluated server-side at submission.
- `refine_control` — modify a control's description if it doesn't match \
the actual security requirement.
- `delete_control` — soft-delete a control with justification. Blocked if \
it is the only control covering a CO — add a replacement first.
- `import_controls` — import existing controls from JSON or free text, \
auto-mapped to COs and deduplicated against existing controls.
- `add_evidence` / `remove_evidence` — attach auxiliary metadata (docs, links, \
artifacts) to a control. Evidence is contextual only — it does NOT prove \
a control is implemented. Only assertions do that.
- `regenerate_controls` — regenerate controls. Supports `mode="per_co"` \
for thorough single-responsibility generation, and `co_ids="CO1,CO5"` \
to regenerate only specific COs (preserving other controls). Controls \
whose descriptions survive unchanged keep their implementation status, \
assertions, and mappings.

**Workflow — handle in this order:**

1. **Controls outside the system boundary** (externally handled): Read each \
not_implemented control description. If it describes something the system \
owner cannot implement (e.g., "restrict CI runner egress", "vendor maintains \
PCI DSS certification") — it belongs outside your trust boundary. Use \
`assume_control` to link it to an existing assumption, or create an \
assumption first with `add_assumption`. Do NOT submit codebase assertions \
for controls outside your boundary.

2. **Controls already satisfied by existing code** (no code changes): \
use `get_controls` to list controls. For each, search the codebase for \
code that already implements it. If found, craft assertions that prove \
the implementation, verify locally, submit assertions, then call \
`update_control_status` to mark as implemented.

3. **Sufficiency gaps on verified controls** (no code changes): call \
`get_verification_report` and read `sufficiency_details` for controls \
that are partially verified. These are implemented but some aspects \
lack proof. Search the codebase for code that proves the missing \
aspects and submit additional assertions. If you cannot find proof \
for specific aspects, call `check_control_gaps` — the control's \
prescribed mechanism may need refinement.

4. **Controls requiring implementation** (code changes needed): before \
implementing, call `check_control_gaps` to verify the control's \
mechanism is appropriate. Then search the codebase for existing \
mechanisms that may already address the control. If found, call \
`refine_control` with `codebase_findings` — the platform evaluates \
whether the existing mechanism satisfies the objective and proposes \
a revised control if so. If accepted, submit assertions for the \
refined control. If rejected or no existing mechanism found, implement \
as prescribed, submit assertions, and update status.

Sufficiency is evaluated automatically server-side when assertions \
are submitted — no manual trigger needed.

## Assurance posture

- `assess_model` — deterministic assessment of all control objectives. \
Returns mitigated/at_risk/unassessed counts and progressive metrics \
(defined/implemented/verified COs). Use `summary_only=True` for a \
compact response with just the counts and a contextual `message` \
explaining the current state (e.g., "13 controls not implemented, \
blocking 35 COs"). Use `status` to filter, `offset`/`limit` to paginate. \
Each CO assessment includes `mitigated_by: "controls" | "assumption" | null` \
— `"assumption"` is a fully resolved state, not a gap. Only `at_risk` \
and `unassessed` COs require action.

**Boundary context and risk reason**: Each CO assessment includes:
- `boundary_reachable` — false if the attacker cannot reach the asset \
across any trust boundary.
- `risk_reason` — why a non-mitigated CO is at risk: `missing_controls` \
(implement controls), `pending_attestation` (submit an attestation for \
the linked boundary assumption), `expired_attestation` (renew an expired \
attestation), `unassessed` (generate controls or create an assumption), \
`asset_absent` (asset is not applicable — skip this CO), \
`attacker_irrelevant` (attack surface is not applicable — skip this CO).
- `asset_status` / `attacker_status` — verification status of the \
asset and attacker for this CO (`unverified`, `confirmed`, `absent`).
- `pending_assumption_ids` / `expired_assumption_ids` — assumption IDs \
that need attestation action.

**Action routing by risk_reason**: \
`missing_controls` → implement controls and submit assertions. \
`pending_attestation` → call `submit_attestation` for the assumption IDs \
listed in `pending_assumption_ids` — do NOT try to implement controls \
for boundary-excluded COs. \
`expired_attestation` → call `submit_attestation` to renew for the \
assumption IDs listed in `expired_assumption_ids`. \
`unassessed` → generate controls with `regenerate_controls`, or if the \
CO is boundary-unreachable (`boundary_reachable=false`), create an \
assumption with `add_assumption`. \
`asset_absent` → the asset is not applicable. No action \
needed — skip controls for this CO. \
`attacker_irrelevant` → the attack surface is not applicable. No action \
needed — skip controls for this CO.

## Gap discovery

For controls with status not_implemented, determine whether the code \
already implements them (submit assertions) or genuinely lacks them \
(submit findings):
- `get_review_queue` — start here for periodic maintenance: returns controls \
not reviewed in 90+ days. For each stale control, verify its assertions \
still hold against the current codebase.
- `get_scan_prompt` — returns targeted prompts for scanning the codebase \
against specific not_implemented controls.
- `check_control_gaps` — AI-powered gap analysis across all controls.
- `submit_findings` — report confirmed gaps where controls are missing.
- `list_findings` / `update_finding` — track finding lifecycle.

## Project setup

- `get_setup_status` — check which onboarding steps are done and which \
are pending. Call before suggesting setup actions to avoid repeating \
completed steps.
- `complete_setup_step` — mark an onboarding step as done. Call after \
completing a setup action: `mcp_configured` (after MCP server is \
connected), `mipiti_verify_installed` (after installing mipiti-verify), \
`ci_secret_added` (after adding the API key to CI secrets), \
`ci_pipeline_added` (after adding the verification job to CI).

## Trust boundaries and assumptions

Trust boundaries and assumptions are versioned (CRUD creates new model \
versions with carry-forward).

**Decision rule — control or assumption?** \
If a security requirement can be implemented and machine-verified in the \
codebase → it is a **control**. If it describes a property that must be \
upheld by an external party (customer, vendor, operator) and cannot be \
implemented by the system owner → it is an **assumption**. The trust boundary \
is the dividing line. When in doubt: if you cannot write a codebase assertion \
that proves it, it is an assumption.

- `get_threat_model` — returns existing trust boundaries (along with assets, \
attackers, and assumptions). Use this to review current boundaries before \
adding or modifying them.
- `add_trust_boundary` / `edit_trust_boundary` / `remove_trust_boundary` \
— CRUD for trust boundaries (defines where trust transitions occur).
- `add_assumption` — add an assumption, optionally linking it to COs it \
covers via `linked_co_ids`. Linked assumptions can mitigate COs when attested.
- `edit_assumption` — update description and/or linked COs.
- `remove_assumption` — soft-delete an assumption (preserved for audit). \
Linked COs are no longer mitigated by it; controls with `assumed_by` pointing \
to it become inert (pointer preserved to enable restore).
- `restore_assumption` — restore a soft-deleted assumption. Controls with \
`assumed_by` pointing to it automatically reconnect. Re-attestation required \
before the assumption mitigates COs again.
- `submit_attestation` — record that a responsible party affirmed an \
assumption holds. Provide `attested_by`, `statement`, and `expires_at` \
(ISO 8601, e.g. "2027-03-29T00:00:00Z"). Expiry triggers CO re-evaluation.
- `list_attestations` — attestation history for an assumption.

**Assumption types**: Two types, set via `assumption_type` in `add_assumption`:
- `non_applicability` — entity is not applicable to the feature. Requires CI \
verification (submit assertions + run mipiti-verify). Manual attestation is \
rejected. Auto-created during generation for flagged entities.
- `external` (default) — responsibility handled by a third party \
that cannot be CI-verified against the codebase (e.g., vendor SLAs, \
infrastructure isolation, customer CI hardening). Allows manual attestation \
via `submit_attestation`.

**Assumption-based mitigation**: An active assumption with linked COs and \
a current (non-expired) attestation mitigates those COs. The assessment \
reports `mitigated_by: "assumption"` — this is a resolved state, not a gap.

**Control-level assumed_by**: For COs that span trust boundaries, individual \
controls within a CO can be marked as externally handled:
- `assume_control` — mark a control as handled by an assumption. Counts as \
active for group completeness when the assumption is active and attested.
- `unassume_control` — clear the externally-handled status; control reverts \
to not_implemented.

**Violation workflow**: When an assumption is violated or attestation \
expires, affected COs become at-risk. Four remediation paths:
1. Re-attest — `submit_attestation` with new expiry (assumption still valid)
2. Restore — `restore_assumption` if assumption was soft-deleted and is \
still valid; re-attest after restoring
3. Convert to controls — `convert_assumption_to_controls` generates \
controls for affected COs and retires the assumption linkage
4. Accept risk — use the Mipiti web interface (no MCP tool available for \
risk acceptance)

"""

_INSTRUCTIONS_COMPLIANCE = """\

## Compliance

1. `list_compliance_frameworks` — available frameworks (SOC 2, ISO 27001, etc.).
2. `select_compliance_frameworks` — activate frameworks for a model. \
**Automatically triggers auto-remediation**: maps existing controls, \
excludes non-applicable requirements by taxonomy, and suggests/applies \
new entities for remaining gaps. Returns `auto_remediate_jobs` with \
job IDs for polling.
3. `get_compliance_report` — coverage report (run after auto-remediation completes).
4. `auto_remediate` — re-trigger auto-remediation manually (e.g. after model changes).
5. `auto_map_controls` — map controls to framework requirements (runs automatically \
during auto-remediation, but can be triggered independently).
6. `map_control_to_requirement` — manually map a specific control to a \
specific requirement (use when auto-mapping misses or misassigns).

## Systems and workspaces

- `list_workspaces` — list workspaces the current user can access. Use to \
find the right workspace when working across team contexts.
- `list_systems` / `get_system` — browse and retrieve system groups.
- `create_system` / `add_model_to_system` — group related models into a system.
- `select_system_compliance_frameworks` / `get_system_compliance_report` — \
cross-model compliance reporting.
"""

_INSTRUCTIONS_ASYNC = """\

## Async operations

`generate_threat_model`, `refine_threat_model`, \
`suggest_compliance_remediation`, and `auto_remediate` return a `job_id` by default. \
`get_controls`, `check_control_gaps`, `auto_map_controls`, \
`import_controls`, and `regenerate_controls` accept `async_mode=True` \
for long-running operations. Poll with `get_operation_status(job_id)` \
and respect `poll_after_seconds` in the response.
"""


def build_instructions(tier: str = "pro", role: str = "user") -> str:
    """Build tier-appropriate MCP instructions.

    Args:
        tier: User's plan tier. "pro", "organization", or "enterprise"
              get full instructions including compliance.
              "developer" (free) gets everything except compliance.
        role: User's role. "admin" and "superadmin" get full instructions
              regardless of tier.
    """
    if tier in ("pro", "organization", "enterprise") or role in ("admin", "superadmin"):
        return _INSTRUCTIONS_BASE + _INSTRUCTIONS_COMPLIANCE + _INSTRUCTIONS_ASYNC
    return _INSTRUCTIONS_BASE + _INSTRUCTIONS_ASYNC


mcp = FastMCP(
    "Mipiti",
    instructions=build_instructions("pro"),
)


# ------------------------------------------------------------------
# Server version check middleware
# ------------------------------------------------------------------

from fastmcp.server.middleware import Middleware


class VersionCheckMiddleware(Middleware):
    """Block tool calls from clients with stale instructions.

    If the client's server_version doesn't match, return the update
    message WITHOUT executing the tool. This forces reconnection
    before serving data under wrong instructions.
    """

    async def on_call_tool(self, context, call_next):
        args = (context.message.arguments or {}) if context.message and hasattr(context.message, "arguments") else {}
        client_version = args.get("server_version", "")
        if client_version and client_version != _SERVER_VERSION:
            from fastmcp.tools.base import ToolResult
            return ToolResult(content=_INSTRUCTIONS_UPDATE_MESSAGE)
        return await call_next(context)


mcp.add_middleware(VersionCheckMiddleware())


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

    # Inject job_id so async coroutines can update progress
    if "_job_id" in kwargs:
        kwargs["_job_id"] = job_id

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
    """Convert Pydantic model or list to dict for MCP tool response.

    FastMCP structured_content requires a dict, so lists are wrapped.
    """
    from pydantic import BaseModel
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, list):
        return {"items": [_dump(item) for item in obj]}
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
    6: "Deriving security controls",
}


# === Threat Model Generation & Management ===


@mcp.tool()
async def generate_threat_model(
    server_version: str,
    feature_description: str,
    ctx: Context,
    async_mode: bool = True,
    force: bool = False,
) -> dict:
    """Generate a complete threat model from a feature description.

    Analyzes the feature using the Security Properties (Confidentiality, Integrity,
    Availability, Usage) methodology with capability-defined attackers.
    Produces trust boundaries, asset inventory, attacker inventory,
    control objective matrix, and assumptions.

    Runs a multi-step AI pipeline as a background job. Poll with
    get_operation_status — the response includes poll_after_seconds
    with adaptive intervals.

    Args:
        feature_description: Description of the feature or system to
            threat model. Can be a few sentences or a detailed spec.
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
        job = _jobs.get(kw.get("_job_id", ""))
        async def _on_progress(step, total, title):
            if job:
                job.progress = step
                job.total = total
                job.message = f"Step {step}/{total}: {STEP_NAMES.get(step, title)}"
        try:
            result = await client.generate_threat_model(
                kw["feature_description"], on_progress=_on_progress,
            )
            return _summarise(result)
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        job_id = _start_job("generate_threat_model", _run,
                            {"feature_description": feature_description,
                             "_job_id": None})  # populated by _start_job
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
    server_version: str,
    model_id: str,
    instruction: str,
    ctx: Context,
    async_mode: bool = True,
) -> dict:
    """Refine an existing threat model based on an instruction.

    Updates the model's assets, attackers, trust boundaries, and control
    objectives based on the instruction. Creates a new version.
    Runs as a background job — poll with get_operation_status
    (includes adaptive poll_after_seconds).

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
    server_version: str,
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
async def list_threat_models(server_version: str) -> dict:
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
async def rename_threat_model(server_version: str, model_id: str, name: str) -> dict:
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
async def delete_threat_model(server_version: str, model_id: str) -> dict:
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
    server_version: str,
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
async def export_threat_model(server_version: str, model_id: str, format: Literal["csv", "pdf", "html"] = "csv") -> dict:
    """Export a threat model as CSV, PDF, or HTML.

    CSV returns content inline. PDF and HTML return a download URL.

    Args:
        model_id: ID of the threat model to export.
        format: Export format — "csv" (default), "pdf", or "html".
    """
    if format not in ("csv", "pdf", "html"):
        raise ToolError("format must be 'csv', 'pdf', or 'html'.")
    try:
        content = await _get_client().export_model(model_id, format)
        if format == "csv":
            return {"format": "csv", "content": content.decode("utf-8")}
        client = _get_client()
        return {
            "format": format,
            "download_url": f"{client.api_url}/api/models/{model_id}/export?format={format}",
            "message": "Include your API key as the X-API-Key header when downloading.",
        }
    except Exception as exc:
        raise _api_error(exc) from exc


# === Controls ===


@mcp.tool()
async def get_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    control_id: Optional[str] = None,
    status: Optional[str] = None,
    co_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
    include_deleted: bool = False,
    summary_only: bool = False,
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
        summary_only: If True, returns only id, description, status, and
            assertion_count per control (much smaller response).
        async_mode: If True, returns a job_id for polling.
    """
    async def _impl(**kw):
        try:
            data = await _get_client().get_controls(
                kw["model_id"],
                include_deleted=kw.get("include_deleted", False),
                control_id=kw.get("control_id") or "",
                status=kw.get("status") or "",
                co_id=kw.get("co_id") or "",
                offset=kw.get("offset", 0),
                limit=kw.get("limit", 0),
                summary_only=kw.get("summary_only", False),
            )
            result = _dump(data)
            # Ensure total/returned are set (older backends may not return them)
            if not result.get("total"):
                result["total"] = len(result.get("controls", []))
            if not result.get("returned"):
                result["returned"] = len(result.get("controls", []))
            return result
        except Exception as exc:
            raise _api_error(exc) from exc

    if async_mode:
        return {"job_id": _start_job("get_controls", _impl, {
            "model_id": model_id, "control_id": control_id, "status": status,
            "co_id": co_id, "offset": offset, "limit": limit,
            "include_deleted": include_deleted, "summary_only": summary_only,
        })}
    return await _impl(
        model_id=model_id, control_id=control_id, status=status,
        co_id=co_id, offset=offset, limit=limit,
        include_deleted=include_deleted, summary_only=summary_only,
    )


@mcp.tool()
async def regenerate_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    async_mode: bool = False,
    mode: str = "batch",
    co_ids: Optional[str] = None,
) -> dict:
    """Regenerate controls from control objectives.

    Controls whose descriptions survive regeneration unchanged preserve
    their implementation status, evidence, notes, assertions, Jira
    mappings, and compliance mappings. Controls with changed or removed
    descriptions are soft-deleted (queryable via include_deleted=True).

    When co_ids is specified, only the controls for those COs are
    regenerated — other controls are preserved as-is.

    Args:
        model_id: ID of the threat model.
        async_mode: If True, returns a job_id for polling.
        mode: "batch" (default, fast) or "per_co" (thorough, one LLM
            call per CO with accumulated context).
        co_ids: Optional comma-separated CO IDs to regenerate (e.g.
            "CO1,CO5"). When omitted, regenerates all controls.
    """
    # Workaround for Claude Code MCP array serialization bug
    # (anthropics/claude-code#18260) — accept comma-separated string
    parsed_co_ids: list[str] | None = None
    if co_ids:
        parsed_co_ids = [c.strip() for c in co_ids.split(",") if c.strip()]

    async def _impl(**kw):
        try:
            return _dump(await _get_client().regenerate_controls(
                kw["model_id"], mode=kw.get("mode", "batch"),
                co_ids=kw.get("co_ids"),
            ))
        except Exception as exc:
            raise _api_error(exc) from exc

    params = {"model_id": model_id, "mode": mode, "co_ids": parsed_co_ids}
    if async_mode:
        return {"job_id": _start_job("regenerate_controls", _impl, params)}
    return await _impl(**params)


@mcp.tool()
async def update_control_status(
    server_version: str,
    model_id: str,
    control_id: str,
    status: str,
    implementation_notes: str = "",
) -> dict:
    """Update the implementation status of a security control.

    Requires at least one assertion before marking as implemented.
    Check the control's assertion_count from get_controls before calling.

    Args:
        model_id: ID of the threat model the control belongs to.
        control_id: ID of the control to update (e.g. "CTRL-01").
        status: New status — "implemented" or "not_implemented".
        implementation_notes: Optional free-text notes.
    """
    if status not in ("implemented", "not_implemented"):
        raise ToolError("status must be 'implemented' or 'not_implemented'.")
    try:
        return _dump(await _get_client().update_control_status(
            model_id, control_id, status, implementation_notes,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def refine_control(
    server_version: str,
    model_id: str,
    control_id: str,
    description: str = "",
    justification: str = "",
    codebase_findings: str = "",
) -> dict:
    """Refine a control's description with AI-gated CO sufficiency check.

    Two modes:
    - Provide `description`: proposes a new description directly.
    - Provide `codebase_findings`: the platform proposes a description
      based on existing code that may already satisfy the control.
    - Both can be provided: the platform evaluates the proposed
      description with the codebase findings as context.

    The AI evaluates whether the mitigation group still collectively
    satisfies all mapped control objectives. If rejected, returns
    {accepted: false, reason, per_co} with per-CO reasoning.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to refine (e.g., "CTRL-03").
        description: Proposed new control description (optional if
            codebase_findings provided).
        justification: Why this refinement is appropriate (min 10 chars).
        codebase_findings: Description of existing code that may already
            satisfy this control's objective (optional). When provided
            without description, the platform proposes a description.
    """
    if not description.strip() and not codebase_findings.strip():
        raise ToolError("Either description or codebase_findings is required.")
    if len(justification.strip()) < 10:
        raise ToolError("justification must be at least 10 characters.")
    try:
        return _dump(await _get_client().refine_control(
            model_id, control_id,
            description.strip(), justification.strip(),
            codebase_findings=codebase_findings.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_evidence(
    server_version: str,
    model_id: str,
    control_id: str,
    type: str = "code",
    label: str = "",
    url: str = "",
) -> dict:
    """Attach auxiliary metadata to a control (docs, links, artifacts).

    Evidence is contextual metadata — it does NOT count toward
    implementation status. Only assertions prove controls.

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
    server_version: str,
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
    server_version: str,
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
    server_version: str,
    model_id: str,
    control_id: str,
    reason: str = "",
) -> dict:
    """Soft-delete a security control with justification.

    Blocks with HTTP 409 if this is the only control covering any control
    objective. Add a replacement control or refine the threat model first.

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
    server_version: str,
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
    server_version: str,
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
    server_version: str,
    model_id: str,
    summary_only: bool = False,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Run assurance assessment on a threat model.

    Evaluates each control objective based on control implementation status.
    Returns summary (mitigated/at_risk/unassessed) and progressive metrics
    (defined/implemented/verified). No LLM calls — deterministic.

    Use summary_only=True to get just the counts without per-CO assessments.

    Args:
        model_id: ID of the threat model to assess.
        summary_only: If True, returns only summary counts (no per-CO details).
        status: Filter: "mitigated", "at_risk", "unassessed".
        offset: Skip first N.
        limit: Max to return (0=all).
    """
    try:
        return _dump(await _get_client().assess_model(
            model_id, summary_only=summary_only,
            status=status or "", offset=offset, limit=limit,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_review_queue(server_version: str) -> dict:
    """Returns controls not reviewed in 90+ days.

    Lists implemented/verified controls whose assertions have not been checked
    recently. For each stale control, verify assertions against codebase.
    """
    try:
        return _dump(await _get_client().get_review_queue())
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assets & Attackers ===


@mcp.tool()
async def add_asset(
    server_version: str,
    model_id: str,
    name: str,
    description: str = "",
    security_properties: Optional[str] = None,
    impact: str = "M",
    notes: str = "",
) -> dict:
    """Add a new asset to a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        name: Asset name (required).
        description: Optional description.
        security_properties: Comma-separated properties, e.g. "C,I,A" (default: "C").
        impact: Impact level: "H", "M", "L".
        notes: Optional notes.
    """
    body: dict[str, Any] = {"name": name, "impact": impact}
    if description:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = [p.strip() for p in security_properties.split(",") if p.strip()]
    if notes:
        body["notes"] = notes
    try:
        return _dump(await _get_client().add_asset(model_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_asset(
    server_version: str,
    model_id: str,
    asset_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    security_properties: Optional[str] = None,
    impact: Optional[str] = None,
    notes: Optional[str] = None,
) -> dict:
    """Edit an existing asset. Creates a new version. Only provided fields changed.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset (e.g., "A1").
        name: New name (optional).
        description: New description (optional).
        security_properties: Comma-separated properties, e.g. "C,I" (optional).
        impact: New impact level (optional).
        notes: New notes (optional).
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if description is not None:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = [p.strip() for p in security_properties.split(",") if p.strip()]
    if impact is not None:
        body["impact"] = impact
    if notes is not None:
        body["notes"] = notes
    try:
        return _dump(await _get_client().edit_asset(model_id, asset_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_asset(server_version: str, model_id: str, asset_id: str) -> dict:
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
    server_version: str,
    model_id: str,
    capability: str,
    position: str = "",
    archetype: str = "",
    likelihood: str = "M",
    trust_boundary_ids: Optional[str] = None,
) -> dict:
    """Add a new attacker to a threat model. Creates a new version.

    Args:
        model_id: ID of the threat model.
        capability: Attacker capability description (required).
        position: Position/access level.
        archetype: Archetype (e.g., "insider", "external").
        likelihood: Likelihood: "H", "M", "L".
        trust_boundary_ids: Comma-separated trust boundary IDs this attacker
            is positioned at (e.g., "TB1,TB2").
    """
    body: dict[str, Any] = {"capability": capability, "likelihood": likelihood}
    if position:
        body["position"] = position
    if archetype:
        body["archetype"] = archetype
    if trust_boundary_ids:
        body["trust_boundary_ids"] = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()]
    try:
        return _dump(await _get_client().add_attacker(model_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_attacker(
    server_version: str,
    model_id: str,
    attacker_id: str,
    capability: Optional[str] = None,
    position: Optional[str] = None,
    archetype: Optional[str] = None,
    likelihood: Optional[str] = None,
    trust_boundary_ids: Optional[str] = None,
) -> dict:
    """Edit an existing attacker. Creates a new version. Only provided fields changed.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker (e.g., "T1").
        capability: New capability (optional).
        position: New position (optional).
        archetype: New archetype (optional).
        likelihood: New likelihood (optional).
        trust_boundary_ids: Comma-separated trust boundary IDs (replaces existing).
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
    if trust_boundary_ids is not None:
        body["trust_boundary_ids"] = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()]
    try:
        return _dump(await _get_client().edit_attacker(model_id, attacker_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_attacker(server_version: str, model_id: str, attacker_id: str) -> dict:
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
async def list_compliance_frameworks(server_version: str) -> dict:
    """List available compliance frameworks.

    Returns built-in frameworks (e.g., OWASP ASVS) and custom frameworks.
    """
    try:
        return _dump(await _get_client().list_compliance_frameworks())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def select_compliance_frameworks(
    server_version: str,
    model_id: str,
    framework_ids: str,
) -> dict:
    """Select compliance frameworks for a threat model. Requires PRO tier.

    Selecting a framework automatically triggers auto-remediation in the
    background: auto-maps existing controls, excludes non-applicable
    requirements by taxonomy, and suggests/applies new entities for remaining
    gaps. The response includes auto_remediate_jobs with job IDs that can be
    polled via get_operation_status.

    Args:
        model_id: ID of the threat model.
        framework_ids: Comma-separated framework IDs (e.g. "asvs-4.0,nist-csf").
    """
    parsed_ids = [f.strip() for f in framework_ids.split(",") if f.strip()]
    try:
        return _dump(await _get_client().select_compliance_frameworks(model_id, parsed_ids))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_compliance_report(
    server_version: str,
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
    server_version: str,
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
    server_version: str,
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
async def auto_remediate(
    server_version: str,
    model_id: str,
    framework_id: str,
) -> dict:
    """Automatically close compliance gaps for a framework. Requires PRO tier.

    Three-phase loop: (1) auto-map existing controls to unmapped requirements,
    (2) exclude requirements for non-applicable taxonomy primitives,
    (3) suggest and apply new assets/attackers for remaining gaps.

    Converges automatically: stops when fully covered or when no further
    progress can be made. Returns a job_id for polling.

    This runs automatically when a framework is selected, but can be
    re-triggered manually if the model changes.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
    """
    try:
        return _dump(await _get_client().auto_remediate(model_id, framework_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Workspaces & Systems ===


@mcp.tool()
async def list_workspaces(server_version: str) -> dict:
    """List workspaces the current user belongs to."""
    try:
        return _dump(await _get_client().list_workspaces())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_systems(server_version: str) -> dict:
    """List all saved systems in current workspace."""
    try:
        return _dump(await _get_client().list_systems())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_system(server_version: str, system_id: str) -> dict:
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
    server_version: str,
    name: str,
    description: str = "",
) -> dict:
    """Create a new system container.

    Args:
        name: System name (e.g., "Mobile Banking Platform").
        description: Optional description.
    """
    try:
        return _dump(await _get_client().create_system(name, description))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_model_to_system(server_version: str, system_id: str, model_id: str) -> dict:
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
    server_version: str,
    system_id: str,
    framework_ids: str,
) -> dict:
    """Select compliance frameworks for a system. Requires PRO tier.

    Args:
        system_id: ID of the system.
        framework_ids: Comma-separated framework IDs (e.g. "asvs-4.0,nist-csf").
    """
    parsed_ids = [f.strip() for f in framework_ids.split(",") if f.strip()]
    try:
        return _dump(await _get_client().select_system_compliance_frameworks(system_id, parsed_ids))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_system_compliance_report(
    server_version: str,
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


_SUBMIT_ASSERTIONS_DOC = f"""\
Submit assertions for a security control or an assumption.

Each assertion is a typed, machine-verifiable claim about a system property \
(source code, configuration, infrastructure, or external service settings).

Provide exactly one of control_id or assumption_id:
- control_id: proves a control is implemented (e.g., "CTRL-01")
- assumption_id: proves a system property claim (e.g., "AS5" — asset \
non-applicability, attacker non-applicability, scope decisions)

For assumption assertions against the feature description (greenfield), \
use target instead of file in params:
{{"type": "pattern_matches", "params": {{"target": "feature_description", \
"pattern": "password.*TOTP"}}, "description": "..."}}

Args:
    model_id: ID of the threat model.
    control_id: ID of the control (omit if using assumption_id).
    assumption_id: ID of the assumption (omit if using control_id).
    assertions_json: JSON array of assertion objects. Each object has:
        - type (required): one of the assertion types below
        - params (required): type-specific parameters (file or target + pattern/name/etc.)
        - description (required): human-readable explanation of what this proves
        - repo (optional): "org/repo-name" for multi-repo setups

Assertion types:
{format_for_docstring()}
"""


@mcp.tool(description=_SUBMIT_ASSERTIONS_DOC)
async def submit_assertions(
    server_version: str,
    model_id: str,
    assertions_json: str,
    control_id: Optional[str] = None,
    assumption_id: Optional[str] = None,
) -> dict:
    if not control_id and not assumption_id:
        raise ToolError("Exactly one of control_id or assumption_id must be provided.")
    if control_id and assumption_id:
        raise ToolError("Provide control_id OR assumption_id, not both.")
    try:
        assertions = json.loads(assertions_json)
    except json.JSONDecodeError:
        raise ToolError("assertions_json must be valid JSON array.")
    try:
        return _dump(await _get_client().submit_assertions(
            model_id, assertions,
            control_id=control_id or "",
            assumption_id=assumption_id or "",
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_assertions(
    server_version: str, model_id: str,
    control_id: Optional[str] = None,
    assumption_id: Optional[str] = None,
) -> dict:
    """List active assertions for a control or assumption.

    Provide exactly one of control_id or assumption_id.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (omit if using assumption_id).
        assumption_id: ID of the assumption (omit if using control_id).
    """
    if not control_id and not assumption_id:
        raise ToolError("Exactly one of control_id or assumption_id must be provided.")
    if control_id and assumption_id:
        raise ToolError("Provide control_id OR assumption_id, not both.")
    try:
        return _dump(await _get_client().list_assertions(
            model_id, control_id=control_id or "", assumption_id=assumption_id or "",
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_assertion(
    server_version: str,
    model_id: str,
    assertion_id: str,
    control_id: Optional[str] = None,
    assumption_id: Optional[str] = None,
) -> dict:
    """Delete an assertion.

    Provide the control_id or assumption_id the assertion belongs to.

    Args:
        model_id: ID of the threat model.
        assertion_id: ID of the assertion to delete.
        control_id: ID of the control (omit if using assumption_id).
        assumption_id: ID of the assumption (omit if using control_id).
    """
    try:
        await _get_client().delete_assertion(
            model_id, assertion_id,
            control_id=control_id or "", assumption_id=assumption_id or "",
        )
        return {"deleted": True, "assertion_id": assertion_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_verification_report(
    server_version: str,
    model_id: str,
    status: str = "",
    summary_only: bool = True,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Get verification report with summary stats and sufficiency gaps.

    Returns tier1/tier2 pass/fail/pending counts, per-control verification
    status, and sufficiency details.

    By default returns summary only (no per-assertion details). Set
    summary_only=False to include full assertion details and drift items.

    Args:
        model_id: ID of the threat model.
        status: Filter by verification status: "verified",
            "partially_verified", "pending", "unverified".
        summary_only: Omit per-assertion details and drift items (default True).
        offset: Skip first N control entries.
        limit: Max control entries to return (0=all).
    """
    try:
        return _dump(await _get_client().get_verification_report(
            model_id, status=status, summary_only=summary_only,
            offset=offset, limit=limit,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_sufficiency(
    server_version: str,
    model_id: str,
    control_id: str,
) -> dict:
    """Get sufficiency status for a single control.

    Returns whether the submitted assertions collectively cover all
    aspects of the control. Evaluated server-side when assertions
    are submitted — no CI round-trip needed.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-01").
    """
    try:
        return await _get_client().get_sufficiency(model_id, control_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Findings ===


@mcp.tool()
async def submit_findings(
    server_version: str,
    model_id: str,
    findings_json: str,
) -> dict:
    """Submit negative findings discovered by scanning codebase.

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
    server_version: str,
    model_id: str,
    control_id: str = "",
    status: str = "",
) -> dict:
    """List negative findings for a threat model.

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
    server_version: str,
    model_id: str,
    finding_id: str,
    status: str,
    notes: str = "",
    reason: str = "",
    remediation_assertion_ids: str = "",
) -> dict:
    """Update lifecycle status of a finding.

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
    server_version: str,
    model_id: str,
    control_id: str = "",
) -> dict:
    """Get scan prompt to guide codebase gap discovery.

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
async def get_operation_status(server_version: str, job_id: str) -> dict:
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


# === Project Setup ===


@mcp.tool()
async def complete_setup_step(server_version: str, step_id: str) -> dict:
    """Mark an onboarding setup step as done.

    Call after completing a setup action on behalf of the user.

    Args:
        step_id: One of: mcp_configured, mipiti_verify_installed,
            ci_secret_added, ci_pipeline_added.
    """
    valid = {"mcp_configured", "mipiti_verify_installed", "ci_secret_added", "ci_pipeline_added"}
    if step_id not in valid:
        return {"error": f"Invalid step_id. Must be one of: {', '.join(sorted(valid))}"}
    try:
        return await _get_client().complete_setup_step(step_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_setup_status(server_version: str) -> dict:
    """Get project onboarding status.

    Returns the setup checklist with completed and pending steps.
    Check this before suggesting setup actions to avoid repeating
    steps that are already done.
    """
    try:
        return await _get_client().get_setup_status()
    except Exception as exc:
        raise _api_error(exc) from exc


# === Trust Boundary CRUD ===


@mcp.tool()
async def add_trust_boundary(
    server_version: str, model_id: str, description: str,
    crosses: Optional[str] = None,
) -> dict:
    """Add a trust boundary. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        description: What this boundary represents (e.g., "Public network to API server").
        crosses: Optional comma-separated asset IDs that cross this boundary.
    """
    parsed_crosses = [c.strip() for c in crosses.split(",") if c.strip()] if crosses else []
    try:
        return await _get_client().add_trust_boundary(model_id, description, parsed_crosses or None)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_trust_boundary(
    server_version: str, model_id: str, tb_id: str,
    description: Optional[str] = None,
    crosses: Optional[str] = None,
) -> dict:
    """Edit a trust boundary. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        tb_id: ID of the trust boundary (e.g., "TB1").
        description: New description.
        crosses: New comma-separated asset IDs.
    """
    kwargs: dict = {}
    if description is not None:
        kwargs["description"] = description
    if crosses is not None:
        kwargs["crosses"] = [c.strip() for c in crosses.split(",") if c.strip()]
    try:
        return await _get_client().edit_trust_boundary(model_id, tb_id, **kwargs)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_trust_boundary(server_version: str, model_id: str, tb_id: str) -> dict:
    """Remove a trust boundary. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        tb_id: ID of the trust boundary to remove.
    """
    try:
        return await _get_client().remove_trust_boundary(model_id, tb_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption CRUD ===


@mcp.tool()
async def add_assumption(
    server_version: str, model_id: str, description: str,
    linked_co_ids: Optional[str] = None,
    assumption_type: str = "external",
) -> dict:
    """Add an assumption. Creates a new model version.

    Assumptions represent security properties outside the system owner's
    trust boundary. When linked to COs and attested, they mitigate those
    COs in the assessment.

    Args:
        model_id: ID of the threat model.
        description: What is assumed (e.g., "Customer restricts CI runner egress").
        linked_co_ids: Optional comma-separated CO IDs this assumption covers.
        assumption_type: "external" (default, allows manual attestation)
            or "non_applicability" (requires CI verification, no manual attestation).
    """
    parsed = [c.strip() for c in linked_co_ids.split(",") if c.strip()] if linked_co_ids else None
    try:
        return await _get_client().add_assumption(model_id, description, parsed, assumption_type=assumption_type)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_assumption(
    server_version: str, model_id: str, assumption_id: str,
    description: Optional[str] = None,
    linked_co_ids: Optional[str] = None,
) -> dict:
    """Edit an assumption. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption (e.g., "AS1").
        description: New description.
        linked_co_ids: New comma-separated CO IDs (replaces existing linkage).
    """
    kwargs: dict = {}
    if description is not None:
        kwargs["description"] = description
    if linked_co_ids is not None:
        kwargs["linked_co_ids"] = [c.strip() for c in linked_co_ids.split(",") if c.strip()]
    try:
        return await _get_client().edit_assumption(model_id, assumption_id, **kwargs)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_assumption(server_version: str, model_id: str, assumption_id: str) -> dict:
    """Soft-delete an assumption. Creates a new model version.

    The assumption is marked as deleted (preserved for audit trail). Linked
    COs are no longer mitigated by it. Controls with assumed_by pointing to
    it are preserved as inert pointers — they reconnect automatically if the
    assumption is restored via restore_assumption.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption to soft-delete.
    """
    try:
        return await _get_client().remove_assumption(model_id, assumption_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Attestation ===


@mcp.tool()
async def submit_attestation(
    server_version: str, model_id: str, assumption_id: str,
    attested_by: str = "", statement: str = "",
    expires_at: str = "", evidence_url: str = "",
) -> dict:
    """Record that a responsible party affirmed an assumption holds.

    Only for external assumptions. Non-applicability assumptions
    require CI verification (submit assertions + run mipiti-verify) — manual
    attestation is rejected for them.

    An assumption with a current attestation can mitigate linked COs.
    When the attestation expires, those COs become at-risk until
    re-attested or covered by controls.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption (e.g., "AS1").
        attested_by: Who is attesting (name, role, organization).
        statement: What was attested.
        expires_at: ISO 8601 expiry date (e.g., "2026-06-30T00:00:00Z").
        evidence_url: Optional link to supporting documentation.
    """
    try:
        return await _get_client().submit_attestation(
            model_id, assumption_id,
            attested_by=attested_by, statement=statement,
            expires_at=expires_at, evidence_url=evidence_url,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_attestations(server_version: str, model_id: str, assumption_id: str) -> dict:
    """List attestation history for an assumption.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption.
    """
    try:
        return await _get_client().list_attestations(model_id, assumption_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Control Assumption ===


@mcp.tool()
async def assume_control(
    server_version: str, model_id: str, control_id: str, assumption_id: str,
) -> dict:
    """Mark a control as externally handled by an assumption.

    The control counts as active for mitigation group completeness
    when the referenced assumption is active and attested.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-03").
        assumption_id: ID of the assumption that covers this control.
    """
    try:
        client = _get_client()
        return await client._post(
            f"/api/models/{model_id}/controls/{control_id}/assume",
            {"assumption_id": assumption_id},
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def unassume_control(server_version: str, model_id: str, control_id: str) -> dict:
    """Clear the externally-handled status on a control.

    The control reverts to not_implemented and needs to be implemented
    by the system owner.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
    """
    try:
        client = _get_client()
        return await client._delete(f"/api/models/{model_id}/controls/{control_id}/assume")
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption Restore ===


@mcp.tool()
async def restore_assumption(server_version: str, model_id: str, assumption_id: str) -> dict:
    """Restore a soft-deleted assumption. Creates a new model version.

    The assumption returns to active status. Controls with assumed_by
    pointing to this assumption automatically reconnect. Re-attestation
    is required before the assumption mitigates COs.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption to restore.
    """
    try:
        client = _get_client()
        return await client._post(
            f"/api/models/{model_id}/assumptions/{assumption_id}/restore", {},
        )
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption Violation Workflow ===


@mcp.tool()
async def convert_assumption_to_controls(
    server_version: str, model_id: str, assumption_id: str,
) -> dict:
    """Convert a violated or retired assumption to controls.

    Generates controls for the COs that were covered by this assumption,
    then retires the assumption's CO linkage. Use when an assumption is
    no longer valid and the system owner needs to implement controls
    instead.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption to convert.
    """
    try:
        return await _get_client().convert_assumption_to_controls(model_id, assumption_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

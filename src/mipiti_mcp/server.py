"""Mipiti MCP Server — expose threat modeling tools via Model Context Protocol.

Single codebase for both standalone (stdio) and hosted (Streamable HTTP) modes.
All tools call the Mipiti REST API via MipitiClient.
"""

import asyncio
import contextvars
import json
import time
from typing import Any, Literal, Optional

from anyio import BrokenResourceError, ClosedResourceError
from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from .assertion_types import format_for_docstring
from .client import MipitiClient

# ------------------------------------------------------------------
# Instructions (tier-aware)
# ------------------------------------------------------------------

_SERVER_VERSION = "12"

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
existing models and routes accordingly. Progress reported automatically.
- `refine_threat_model` — updates an existing model when you already have \
a model ID and want to change it. Progress reported automatically.
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
- `rename_threat_model` — rename a model (metadata only, no new version). \
Model titles must be unique within a workspace (case-insensitive); pick a \
distinct name on the first try to avoid a 409 retry.
- `delete_threat_model` — permanently delete a model and all its data.
- `export_threat_model` — download as PDF, HTML, or CSV.
- `export_threat_model_archive` — download the self-contained JSON audit \
archive (every version, controls, assertions with CI verdicts, findings, \
attestations, sufficiency signatures). Independently verifiable without \
origin-instance access.
- `import_threat_model_archive` — restore an audit archive into a \
workspace. Assigns a fresh model_id every time; title collisions \
auto-suffix `(imported YYYY-MM-DD)`.

## Controls and assertions

A threat model produces control objectives. Controls are derived from these \
and represent specific security requirements to implement. Assertions are \
typed, machine-verifiable claims about system properties that prove a \
control is satisfied. A system property can be verified by examining \
source code, configuration files, infrastructure definitions, or \
external service settings.

**Key tools:**
- `get_controls` — lists controls with current status. Use `summary_only=True` \
for a compact response (id, description, status, assertion_count, assumed_by).
- `get_control_objectives` — lists COs with which controls cover each one. \
Includes `boundary_reachable` and `boundary_unreachable_reason` per CO. \
Useful for understanding scope before linking assumptions or regenerating.
- `submit_assertions` — provide proof for a control. See that tool's docstring for \
assertion types and required params. Always verify locally first: \
`mipiti-verify verify <type> -p key=value --project-root .` \
Read the target file and confirm a reviewer would agree with the claim.
- **Assertion design: prefer decomposition over breadth.** Tier 2 \
(semantic LLM check) evaluates each assertion with only its own \
check-type evidence. A single broad claim like "X calls Y to do \
A and B using C" will pass Tier 1 but fail Tier 2 — the mechanical \
evidence (e.g., a function_calls result) doesn't surface facts \
A, B, C. Split into multiple atomic assertions — one for each \
narrow aspect — each with a check type that directly shows the \
relevant code (`pattern_matches` on the specific line, \
`function_exists` for the named function, etc.). Submit them as \
a group on the same control. Sufficiency combines them; \
individually each is trivially provable.
- `list_assertions` / `delete_assertion` — list active assertions for a control; \
delete stale or incorrect ones before resubmitting.
- `update_control_status` — mark implemented or not_implemented. Requires \
at least one assertion BEFORE marking implemented. Always submit \
assertions first, then update status.
- `get_verification_report` — shows which controls are verified, which \
have sufficiency gaps, and which lack assertions entirely. Read \
`sufficiency_details` for the specific aspects that still need proof. \
Each `sufficiency` block also carries `misaligned_assertion_ids` \
(off-topic assertions that should be rebound, superseded, or rewritten — \
do not treat them as evidence) and `stale: true` (cached verdict no \
longer matches current inputs; a background re-eval was triggered on \
read — call again shortly for a refreshed verdict).
- `get_sufficiency` — quick check: do assertions for a single control \
collectively cover all aspects? Evaluated server-side at submission.
- `get_mitigation_groups` — get the current group structure for a CO with \
control details (id, description, status) for each entry. Shows numbered \
groups (AND within, OR across), defense-in-depth controls, and unmapped \
controls available for assignment. Use before `set_mitigation_groups`, \
when reviewing why a CO is at_risk, or to find unmapped controls.
- `set_mitigation_groups` — set which controls are required vs defense-in-depth \
for a CO. Use when a control is blocking a CO but is redundant with existing \
mitigations (e.g., HMAC signing redundant with TLS + content hash), or when \
restructuring alternative mitigation paths. Groups define: within group AND \
(all required), across groups OR (any complete group mitigates). AI-gated: \
rejected if the new structure doesn't satisfy the CO.
- `refine_control` — modify a control's description if it doesn't match \
the actual security requirement. **Side effect on accepted refinements**: \
every assertion attached to the control is superseded — their claims \
were authored against the prior description and may not be on-topic for \
the new one. Response carries `superseded_assertions: <count>`. Re-submit \
any assertion that still applies; superseded rows remain in history.
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
for controls outside your boundary. The platform runs an AI relevance gate \
on every assumption-to-control linkage; if the assumption's description \
doesn't cover what the control requires, the call raises and there is no \
override. If rejected, either pick an assumption that covers the control or \
edit the assumption's description to make coverage explicit. For compound \
("AS1 AND AS2") or multi-path ("AS1 OR AS2") cases, use \
`set_control_assumption_groups` instead of `assume_control`.

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

**Control-level assumption groups**: For COs that span trust boundaries, \
individual controls can be marked as externally handled by assumptions. \
Assumption groups express alternative sets of external claims: within a \
group all assumptions must be active+attested (AND), any complete group \
suffices (OR).
- `get_control_assumption_groups` / `set_control_assumption_groups` — \
inspect and set the full group structure. Use for compound cases \
("AWS KMS + quarterly review" or "HSM + FIPS certification") or \
multiple independent paths.
- `assume_control` / `unassume_control` — shorthand for the common \
single-assumption, single-group case (writes to group 1).

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
- `get_system_dependencies` — view cross-model dependency graph. Shows \
which assumptions are linked to other models and whether they are satisfied.
- `link_dependency` — link an external assumption to a target model in the \
same system. Makes it a cross-model dependency that appears as a compliance \
requirement on the target model. Two independent satisfaction paths: \
auto-attestation from target controls (no manual action needed), or manual \
attestation via `submit_attestation`. Either alone suffices.
- `select_system_compliance_frameworks` / `get_system_compliance_report` — \
cross-model compliance reporting.

## Components

Components bridge security architecture (trust boundaries) to code \
organization (repos). Add components to a model to scope controls \
to specific codebases.

- `add_component` — create a component with name, repo_url, and \
optional path (for monorepos) and trust_boundary_ids.
- `edit_component` / `remove_component` — modify or delete a component.
- `get_controls` with `component_id` — filter controls by component.
"""

_INSTRUCTIONS_ASYNC = """\

## Long-running operations

`generate_threat_model`, `refine_threat_model`, `auto_remediate`, \
`auto_map_controls`, `regenerate_controls`, and `check_control_gaps` \
run LLM pipelines that may take several minutes. They block until complete \
and report progress automatically — no polling needed.
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
            from fastmcp.exceptions import ToolError
            raise ToolError(_INSTRUCTIONS_UPDATE_MESSAGE)
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
# Backend job polling helper
# ------------------------------------------------------------------


async def _await_backend_job(client: MipitiClient, job_id: str, ctx: Context, timeout: float = 600) -> dict:
    """Poll a backend job until completion, reporting progress via MCP protocol.

    Detects client disconnect (when running over Streamable HTTP transport) and
    aborts polling early so we don't keep doing work for a dead client. The
    backend job itself is intentionally NOT cancelled — it continues running so
    that a retry with the same Idempotency-Key can pick up the cached result.
    """
    deadline = time.monotonic() + timeout

    # Resolve the underlying ASGI request once (HTTP transport only). For stdio
    # there is no HTTP request and disconnect detection does not apply.
    http_request = None
    try:
        from fastmcp.server.dependencies import get_http_request
        http_request = get_http_request()
    except Exception:
        http_request = None

    # MCP spec invariants on a progressToken sequence:
    #   - `progress` is strictly increasing
    #   - `total`, if provided, is CONSTANT across the sequence
    # Clients are allowed to drop sequences that violate either.
    #
    # The backend may advertise (progress_current, progress_total). When it
    # does, we lock onto the first total we see and only emit when current
    # strictly advances AND the total still matches. If the backend shifts
    # phases (total changes) we SKIP the emission rather than violate the
    # invariant — the client's bar stays where it was, which is a better UX
    # than dropping the whole sequence. When numerics are absent, fall back
    # to indeterminate mode: a locally-incrementing poll counter with
    # total=None (clients render a spinner).
    last_progress: float = 0.0
    locked_total: float | None = None
    poll_counter: int = 0

    while True:
        if http_request is not None:
            try:
                if await http_request.is_disconnected():
                    raise ToolError("Client disconnected before job completed. Retry the tool to check status.")
            except ToolError:
                raise
            except Exception:
                # is_disconnected() can raise on some transport states; treat
                # as still-connected to avoid false positives that would abort
                # legitimate long-running jobs.
                pass

        data = await client.get_operation(job_id)
        status = data.get("status")
        if status == "completed":
            return data.get("result", {})
        if status == "failed":
            raise ToolError(data.get("error", "Background job failed"))
        if time.monotonic() > deadline:
            raise ToolError(f"Operation timed out after {timeout}s")

        message = data.get("progress") or ""
        cur = data.get("progress_current")
        tot = data.get("progress_total")

        if cur is not None and tot is not None and float(tot) > 0:
            cur_f = float(cur)
            tot_f = float(tot)
            if locked_total is None:
                locked_total = tot_f
            # Only emit when total matches the locked value AND current strictly
            # advances. Phase shifts (total changed) and duplicate polls are
            # both silently skipped to preserve MCP invariants.
            if tot_f == locked_total and cur_f > last_progress:
                last_progress = cur_f
                await _safe_report_progress(ctx, last_progress, locked_total, str(message))
        elif message:
            # Indeterminate mode: no numerics advertised, bump a local monotonic
            # counter and omit `total` so clients render a spinner.
            poll_counter += 1
            await _safe_report_progress(ctx, poll_counter, None, str(message))

        wait = data.get("poll_after_seconds", 3)
        await asyncio.sleep(wait)


async def _safe_report_progress(
    ctx: Context, progress: float, total: float | None, message: str,
) -> None:
    """Forward a progress notification, suppressing closed-channel errors.

    The MCP transport channel can close mid-tool — client disconnect,
    idle timeout, cancellation. Once that happens, every subsequent
    ``ctx.report_progress`` raises ``ClosedResourceError`` /
    ``BrokenResourceError`` from the underlying anyio memory stream.
    Without this guard the exception propagates up through the SSE
    consumer and aborts the surrounding tool, even though the upstream
    work has already completed and persisted server-side. Tool results
    must not depend on whether the client is still listening for
    progress notifications.
    """
    try:
        await ctx.report_progress(progress, total, message=message)
    except (ClosedResourceError, BrokenResourceError):
        pass


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
    """Convert an httpx error into a ToolError with a clean message.

    Special-cases the backend's DUPLICATE_NATURAL_KEY 409 (Tier 3 uniqueness
    constraint) so the LLM agent gets a structured "this already exists"
    message with the existing entity's id, instead of a generic API error
    blob it would have to parse itself.
    """
    import httpx
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            payload = exc.response.json()
            detail = payload.get("detail", str(exc))
        except Exception:
            detail = exc.response.text or str(exc)
            payload = {}

        # Structured DUPLICATE_NATURAL_KEY response from the Tier 3 constraint
        if (
            exc.response.status_code == 409
            and isinstance(detail, dict)
            and detail.get("error") == "DUPLICATE_NATURAL_KEY"
        ):
            entity_type = detail.get("entity_type", "entity")
            existing_id = detail.get("existing_id") or "(unknown id)"
            message = detail.get("message") or f"A {entity_type} with this key already exists."
            return ToolError(
                f"{message} The existing {entity_type} has id={existing_id}. "
                "Use the existing entity instead, or rename/differentiate the new one."
            )

        return ToolError(f"API error ({exc.response.status_code}): {detail}")
    return ToolError(str(exc))


# ------------------------------------------------------------------
# Tool implementations
# ------------------------------------------------------------------



# === Threat Model Generation & Management ===


@mcp.tool()
async def generate_threat_model(
    server_version: str,
    feature_description: str,
    ctx: Context,
    force: bool = False,
) -> dict:
    """Generate a complete threat model from a feature description.

    Analyzes the feature using the Security Properties (Confidentiality,
    Integrity, Availability, Usage) methodology with capability-defined
    attackers. Produces trust boundaries, asset inventory, attacker
    inventory, control objective matrix, and assumptions.

    Runs a multi-step AI pipeline. Progress is reported automatically.

    **Similar-model short-circuit:** if the backend finds an existing
    model in the workspace whose feature description substantially
    overlaps with the new one, it does NOT generate a duplicate. This
    tool returns ``{"similar_models": [{"id", "title", "reason"}, ...],
    "suggestion": "..."}`` with the candidate IDs instead. The agent
    should then either:

    - Call ``refine_threat_model`` on one of the candidates to extend
      the existing model (usually the right answer — avoids duplicate
      modeling of the same system and preserves control/assertion
      history).
    - Retry this tool with ``force=True`` to bypass the check and
      create a genuinely new model anyway (e.g., when the similarity
      is superficial and the operator confirmed the new model is
      distinct).

    Args:
        feature_description: Description of the feature or system to
            threat model. Can be a few sentences or a detailed spec.
        force: Skip the similar-model detection and always create a
            new model. Default False — the check fires unless the
            operator / agent has explicit reason to bypass it.

    Return shape (normal generation):
        ``{"model_id", "version", "title", "asset_count",
           "attacker_count", "control_objective_count"}``

    Return shape (similar-model short-circuit):
        ``{"similar_models": [{"id", "title", "reason"}, ...],
           "suggestion": "..."}``
    """
    # Track the last (progress, total) seen from the upstream stream so the
    # final "Complete" notification emits (total, total) and preserves the
    # MCP spec invariants: progress monotonically non-decreasing, and `total`
    # constant across a single progressToken sequence. Clients are allowed
    # to drop progressToken sequences that violate either invariant.
    last_progress_total: list[float] = [0.0, 0.0]  # [last_progress, last_total]

    async def on_progress(progress, total, message):
        last_progress_total[0] = progress
        last_progress_total[1] = total
        await _safe_report_progress(ctx, progress, total, message)
    try:
        result = await _get_client().generate_threat_model(
            feature_description,
            force_generate=force,
            on_progress=on_progress,
        )
        # Emit a final 100% notification aligned with the sequence's total.
        # If on_progress was never called (stream had no step events), skip
        # the Complete notification — any arbitrary (progress, total) here
        # would violate the monotonic / constant-total invariant.
        if last_progress_total[1] > 0:
            await _safe_report_progress(
                ctx, last_progress_total[1], last_progress_total[1], "Complete",
            )
        # Similar-model short-circuit: client returned a plain dict
        # with a `similar_models` key, not a GenerateResult.
        if isinstance(result, dict) and "similar_models" in result:
            return {
                "similar_models": list(result.get("similar_models") or []),
                "suggestion": (
                    "Feature description overlaps existing model(s) in the "
                    "workspace. Either call refine_threat_model(model_id=<candidate>, "
                    "instruction=\"...\") to extend the existing one — usually the "
                    "right answer, as it preserves controls and history — or retry "
                    "generate_threat_model with force=True to create a new model "
                    "anyway."
                ),
            }
        tm = result.threat_model
        return {
            "model_id": tm.id,
            "version": tm.version,
            "title": tm.title,
            "asset_count": len(tm.assets),
            "attacker_count": len(tm.attackers),
            "control_objective_count": len(tm.control_objectives),
        }
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def refine_threat_model(
    server_version: str,
    model_id: str,
    instruction: str,
    ctx: Context,
) -> dict:
    """Refine an existing threat model based on an instruction.

    Updates the model's assets, attackers, trust boundaries, and
    control objectives based on the instruction. Creates a new
    version. Progress is reported automatically.

    Refine CANNOT silently replace an entity's identity under a
    stable ID or silently drop an entity. Behavior:

    - **Preserved entities** where the LLM proposed an identity-
      bearing rewrite (name / description / security_properties on
      assets; capability / archetype / position on attackers) run
      through a semantic-preservation guard. Rewrites classified as
      ``replace`` or ``ambiguous`` (or ``unavailable`` if the gate
      LLM is down) have their identity fields REVERTED to the
      pre-refine values. Each rejection shows up as an entry in the
      ``semantic_rejections`` array in this tool's return value —
      surface these to the operator.
    - **Entities the LLM drops** from the refined output are re-
      appended to the model unchanged. The only sanctioned removal
      path is ``remove_asset`` / ``remove_attacker`` (soft-delete).
    - **CO IDs are stable** across refinements; pairs (asset,
      attacker) that disappear come back as tombstones with
      ``removed=True`` (not renumbered). Controls that only mapped
      to tombstoned COs become orphaned at read time.

    Args:
        model_id: ID of the threat model to refine.
        instruction: What to change, e.g. "Add CSRF attack vectors".

    Return shape:
        {
          model_id, version, title,
          asset_count, live_asset_count,
          attacker_count, live_attacker_count,
          control_objective_count, live_control_objective_count,
          semantic_rejections: [{kind, id, classification, reason, per_field}, ...],
        }

    ``*_count`` includes soft-deleted / tombstoned entries;
    ``live_*_count`` excludes them. Agents summarizing the result
    should typically quote the live counts unless specifically
    looking at history.
    """
    # See generate_threat_model for rationale on the last-total tracker.
    last_progress_total: list[float] = [0.0, 0.0]

    async def on_progress(progress, total, message):
        last_progress_total[0] = progress
        last_progress_total[1] = total
        await _safe_report_progress(ctx, progress, total, message)
    try:
        result = await _get_client().refine_threat_model(
            model_id, instruction, on_progress=on_progress,
        )
        if last_progress_total[1] > 0:
            await _safe_report_progress(
                ctx, last_progress_total[1], last_progress_total[1], "Complete",
            )
        tm = result.threat_model
        live_assets = [a for a in tm.assets if not getattr(a, "deleted", False)]
        live_attackers = [t for t in tm.attackers if not getattr(t, "deleted", False)]
        live_cos = [c for c in tm.control_objectives if not getattr(c, "removed", False)]
        return {
            "model_id": tm.id,
            "version": tm.version,
            "title": tm.title,
            "asset_count": len(tm.assets),
            "live_asset_count": len(live_assets),
            "attacker_count": len(tm.attackers),
            "live_attacker_count": len(live_attackers),
            "control_objective_count": len(tm.control_objectives),
            "live_control_objective_count": len(live_cos),
            "semantic_rejections": list(
                getattr(result, "semantic_rejections", []) or []
            ),
        }
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def query_threat_model(
    server_version: str,
    model_id: str,
    question: str,
    ctx: Context,
) -> dict:
    """Ask a question about an existing threat model.

    Uses AI to answer questions about the model's assets, attackers,
    control objectives, assumptions, or security posture.

    Args:
        model_id: ID of the threat model to query.
        question: The question to ask.
    """
    try:
        result = await _get_client().query_threat_model(model_id, question)
        return {"model_id": model_id, "answer": result.content}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_threat_models(
    server_version: str,
    source: str = "",
    include_assessment_summary: bool = False,
) -> dict:
    """List all saved threat models.

    Returns a summary of each model including ID, title, creation date,
    and version number. Use the model ID with other tools.

    Args:
        source: Filter by source system. One of "web", "mcp", "jira", "api".
            Omit to list all models regardless of source.
        include_assessment_summary: If True, include an `assessment_summary`
            object with each model (counts of mitigated / at_risk /
            unassessed COs plus a human-readable `message`). Useful for
            aggregate posture queries across the workspace in a single
            call — e.g. "which of my models are at risk?" — instead of
            calling `assess_model` once per model (N+1 at the agent layer).
            Adds ~100 bytes per model to the response.
    """
    try:
        include = "assessment_summary" if include_assessment_summary else ""
        models = await _get_client().list_models(source=source, include=include)
        items = []
        for m in models:
            entry: dict = {
                "id": m.id,
                "title": m.title or m.feature_description[:80],
                "version": m.version,
                "created_at": m.created_at,
            }
            if include_assessment_summary:
                # Pydantic `extra=allow` lets us read the inline enrichment
                # off the ModelSummary instance directly.
                extra_asmt = getattr(m, "assessment", None)
                if extra_asmt is not None:
                    entry["assessment_summary"] = extra_asmt
            items.append(entry)
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

    **Important for agents reading model state:**

    - Assets and attackers may carry ``deleted: true`` (soft-deleted).
      Exclude these when showing "what's in the model now"; include
      them only when discussing history or offering restore. Restore
      an entity via ``restore_asset`` / ``restore_attacker``.
    - Control objectives may carry ``removed: true`` (tombstone — the
      (asset, attacker) pair was removed in a later version). Exclude
      these from coverage math and LLM prompts; they exist to keep
      CO IDs stable so controls referencing them can be detected as
      "orphaned" rather than silently rebinding.

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


@mcp.tool()
async def export_threat_model_archive(server_version: str, model_id: str) -> dict:
    """Export the self-contained JSON audit archive for a threat model.

    The archive carries every version, controls, assertions (with CI Tier
    1/Tier 2 verdicts and attested flags), findings, risk acceptances,
    assumption overrides, attestations, and instance sufficiency
    signatures. Independently verifiable — CI OIDC JWTs verify against
    the issuer's public JWKS, workspace signatures against the
    workspace's published key, and sufficiency signatures against the
    origin instance's key (via the target's trusted_signers table).

    Args:
        model_id: ID of the threat model to export.

    Returns:
        {"envelope": <full archive dict>} — pass this envelope to
        `import_threat_model_archive` on any instance to restore.
    """
    try:
        envelope = await _get_client().export_model_full(model_id)
        return {"envelope": envelope}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def import_threat_model_archive(
    server_version: str,
    envelope: dict,
    workspace_id: str,
) -> dict:
    """Import a JSON audit archive (from `export_threat_model_archive`)
    into the target workspace.

    A fresh model_id is assigned every time, so the same envelope can be
    imported any number of times without collisions. Title collisions in
    the target workspace auto-suffix `(imported YYYY-MM-DD)`. The caller
    must have write access to the target workspace.

    Args:
        envelope: The full archive dict returned by
            `export_threat_model_archive`.
        workspace_id: Target workspace to import into.

    Returns:
        {"model_id": "<new id>"}.
    """
    if not isinstance(envelope, dict):
        raise ToolError("envelope must be a dict returned by export_threat_model_archive.")
    if not workspace_id:
        raise ToolError("workspace_id is required.")
    try:
        return await _get_client().import_model_full(envelope, workspace_id)
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
    component_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
    include_deleted: bool = False,
    include_orphaned: bool = False,
    summary_only: bool = False,
) -> dict:
    """Get implementation controls for a threat model.

    Returns controls that should be implemented to satisfy control objectives.
    If controls haven't been generated yet, auto-generates them.

    By default excludes ORPHANED controls — controls whose every mapped
    CO is tombstoned (its asset/attacker pair was removed in a later
    version). Pass include_orphaned=True to see them. Each returned
    control carries a boolean `orphaned` field so callers can render
    the distinction.

    Args:
        model_id: ID of the threat model.
        control_id: Optional specific control for detail mode.
        status: Filter by "implemented", "not_implemented", "verified".
        co_id: Filter by control objective ID.
        component_id: Filter by component ID (e.g., "CMP1").
        offset: Skip first N (for pagination).
        limit: Max to return (0=all).
        include_deleted: Include soft-deleted controls.
        include_orphaned: Include controls mapped only to tombstoned
            COs (default False).
        summary_only: If True, returns only id, description, status,
            assertion_count, and assumed_by per control (much smaller response).
    """
    try:
        data = await _get_client().get_controls(
            model_id,
            include_deleted=include_deleted,
            include_orphaned=include_orphaned,
            control_id=control_id or "",
            status=status or "",
            co_id=co_id or "",
            component_id=component_id or "",
            offset=offset,
            limit=limit,
            summary_only=summary_only,
        )
        result = _dump(data)
        if not result.get("total"):
            result["total"] = len(result.get("controls", []))
        if not result.get("returned"):
            result["returned"] = len(result.get("controls", []))
        return result
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def regenerate_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    mode: str = "batch",
    batch_size: int = 0,
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
        mode: "batch" (default) or "per_co" (most thorough, one LLM
            call per CO).
        batch_size: COs per batch in batch mode (default: 15). Smaller
            = more accurate + granular progress, more LLM calls.
        co_ids: Optional comma-separated CO IDs to regenerate (e.g.
            "CO1,CO5"). When omitted, regenerates all controls.
    """
    # Workaround for Claude Code MCP array serialization bug
    # (anthropics/claude-code#18260) — accept comma-separated string
    parsed_co_ids: list[str] | None = None
    if co_ids:
        parsed_co_ids = [c.strip() for c in co_ids.split(",") if c.strip()]
    try:
        client = _get_client()
        result = await client.regenerate_controls(
            model_id, mode=mode, batch_size=batch_size, co_ids=parsed_co_ids,
        )
        if isinstance(result, dict) and "job_id" in result:
            return await _await_backend_job(client, result["job_id"], ctx)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc


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

    **Side effect on accepted refinements**: every assertion attached
    to this control is superseded — their claims were authored against
    the prior description and are not guaranteed to align with the new
    one. The response includes ``superseded_assertions: <count>`` so
    the caller knows how many. Re-submit any assertion that still
    applies under the new description; superseded rows remain in
    history with ``superseded_by="control_refined:..."``.

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
async def remap_control(
    server_version: str,
    model_id: str,
    control_id: str,
    co_ids: str,
    change_reason: str,
) -> dict:
    """Mechanical, non-AI-gated remap of a control's CO mappings.

    Distinct from `refine_control` (AI-gated description edit) and
    `set_mitigation_groups` (AI-gated CO-centric group authoring).
    Use `remap_control` when the operator already knows the correct
    co_ids and just needs to persist the mapping change — e.g.,
    restoring mappings after an asset/attacker edit left the control
    with stale or orphaned CO references. No LLM evaluation runs.

    Rejects target co_ids that do not exist on the model or are
    tombstoned (the pair was removed in a later version) — map to
    live COs only.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to remap (e.g., "CTRL-03").
        co_ids: Comma-separated list of target CO IDs (e.g.,
            "CO1,CO2,CO3"). Must include at least one CO.
        change_reason: Why this remapping is appropriate (min 10
            chars). Captured in the control's version history.
    """
    parsed = [c.strip() for c in co_ids.split(",") if c.strip()]
    if not parsed:
        raise ToolError("co_ids must contain at least one CO ID.")
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        return _dump(await _get_client().remap_control(
            model_id, control_id, parsed, change_reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def assign_control_to_components(
    server_version: str,
    model_id: str,
    control_id: str,
    component_ids: str,
    change_reason: str,
) -> dict:
    """Replace a control's component scope.

    Components are the canonical code-binding for controls. A control
    scoped to one or more components is visible to coding agents working
    in those repos (matched via Component.repo_url + Component.path);
    an unscoped control is visible everywhere.

    Use this tool when:
    - Wiring a previously unscoped control to the component(s) that
      implement it (so coding agents see the control on their repo).
    - Adding a second component to a cross-cutting control (e.g.,
      "all microservices enforce JWT validation").
    - Correcting a wrong component assignment.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to scope (e.g., "CTRL-03").
        component_ids: Comma-separated component IDs (e.g., "CMP1,CMP2").
            Empty string = unscoped (visible to every coding agent).
            Validated against the model: every supplied ID must exist.
        change_reason: Why this scope is appropriate (min 10 chars).
            Captured in the control's version history.
    """
    parsed = [c.strip() for c in component_ids.split(",") if c.strip()] if component_ids else []
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        return _dump(await _get_client().assign_control_to_components(
            model_id, control_id, parsed, change_reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def assign_asset_to_components(
    server_version: str,
    model_id: str,
    asset_id: str,
    component_ids: str,
    change_reason: str,
) -> dict:
    """Replace an asset's component scope.

    Mirror of ``assign_control_to_components`` for assets. Components
    are the canonical bridge between security architecture (trust
    boundaries) and code organization (repos). Linking assets to
    components flows boundary context into reachability derivation
    without giving Asset its own ``trust_boundary_ids``.

    An asset's component scope can be:
    - Unscoped (empty string): no explicit code-ownership binding.
      Reach decisions fall back to LLM judgment of the asset's
      description / security properties.
    - Single-component: standard case for assets handled by one
      deployable unit.
    - Multi-component: a multi-instance asset that flows through
      several components (e.g., a session token on client + cache
      + DB — each component handles a distinct instance).

    Mechanical, non-AI-gated. Validates only that every referenced
    component exists on the model.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset to scope (e.g., "A1").
        component_ids: Comma-separated component IDs (e.g., "CMP1,CMP2").
            Empty string = unscoped.
        change_reason: Why this scope is appropriate (min 10 chars).
            Captured in the model's version history.
    """
    parsed = [c.strip() for c in component_ids.split(",") if c.strip()] if component_ids else []
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        return _dump(await _get_client().assign_asset_to_components(
            model_id, asset_id, parsed, change_reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def model_coherence_report(
    server_version: str,
    model_id: str,
) -> dict:
    """Static-analysis report on coherence between the model's
    component declarations and the code-binding strings on its
    controls and assertions.

    Findings flag drift between the canonical component graph and the
    repo strings carried on assertions:
    - ``control_component_unknown`` — control references a component
      ID that no longer exists on the model.
    - ``assertion_repo_mismatch`` — an assertion's ``repo`` does not
      match the ``repo_url`` of any component scoping its control.
    - ``assertion_repo_orphan`` — an assertion has a ``repo`` but its
      control is unscoped, so the binding cannot be cross-checked.
    - ``control_unscoped_with_scoped_assertions`` — a control is
      unscoped but assertions targeting it carry ``repo`` values,
      indicating the control should be scoped to those repos.

    Use this before relying on component-scoped control discovery, or
    when assertion verification fails for path/repo reasons.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().model_coherence_report(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_mitigation_groups(
    server_version: str,
    model_id: str,
    co_id: str,
) -> dict:
    """Get the current mitigation group structure for a control objective.

    Returns the grouped view of controls for this CO with details
    (id, description, status) for each control:
    - groups: numbered groups (within=AND, across=OR)
    - defense_in_depth: tracked but not required for mitigation
    - unmapped: model controls not mapped to this CO (available for assignment)

    Use cases:
    - Before set_mitigation_groups to see the current structure
    - When reviewing a CO's assessment to understand why it is at_risk or mitigated
    - When deciding which unmapped controls to assign to a CO

    Args:
        model_id: ID of the threat model.
        co_id: ID of the control objective (e.g., "CO5").
    """
    try:
        return _dump(await _get_client().get_mitigation_groups(model_id, co_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def set_mitigation_groups(
    server_version: str,
    model_id: str,
    co_id: str,
    groups: str,
    defense_in_depth: str = "",
    justification: str = "",
) -> dict:
    """Declaratively set the mitigation group structure for a CO.

    Replaces all mitigation group assignments for this CO. AI-gated:
    the platform evaluates whether the new structure satisfies the CO.

    Mitigation groups define alternative paths to satisfy a CO:
    - Within a group: AND — all controls must be implemented
    - Across groups: OR — any complete group mitigates the CO
    - Defense-in-depth: tracked but not required for mitigation

    Args:
        model_id: ID of the threat model.
        co_id: ID of the control objective (e.g., "CO5").
        groups: JSON object mapping group numbers to control ID lists.
            Example: '{"1": ["CTRL-01", "CTRL-02"], "2": ["CTRL-03"]}'
        defense_in_depth: Comma-separated control IDs for defense-in-depth.
            Example: "CTRL-04,CTRL-05"
        justification: Why this group structure is appropriate (min 10 chars).
    """
    import json as _json
    try:
        parsed_groups = _json.loads(groups)
    except _json.JSONDecodeError:
        raise ToolError("groups must be valid JSON: {\"1\": [\"CTRL-01\"], ...}")
    if not isinstance(parsed_groups, dict):
        raise ToolError("groups must be a JSON object")

    did_list = [s.strip() for s in defense_in_depth.split(",") if s.strip()] if defense_in_depth else []

    if len(justification.strip()) < 10:
        raise ToolError("justification must be at least 10 characters.")

    try:
        return _dump(await _get_client().set_mitigation_groups(
            model_id, co_id, parsed_groups, did_list, justification.strip(),
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
    """
    try:
        return _dump(await _get_client().import_controls(
            model_id, controls_json, free_text, source_label, auto_map,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


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
) -> dict:
    """Check for missing controls.

    Analyzes existing controls against control objectives and suggests
    COs with insufficient coverage.

    Args:
        model_id: ID of the threat model.
    """
    try:
        client = _get_client()
        result = await client.check_control_gaps(model_id)
        if isinstance(result, dict) and "job_id" in result:
            return await _await_backend_job(client, result["job_id"], ctx)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc


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


_ASSET_FACTOR_PARAMS = (
    "confidentiality_subscore", "integrity_subscore",
    "availability_subscore", "usage_subscore",
    "blast_radius", "recoverability", "regulatory_scope",
)


@mcp.tool()
async def add_asset(
    server_version: str,
    model_id: str,
    name: str,
    description: str = "",
    security_properties: Optional[str] = None,
    notes: str = "",
    component_ids: Optional[str] = None,
) -> dict:
    """Add a new asset to a threat model. Creates a new version.

    The caller supplies identity-bearing fields (name, description,
    security_properties, notes) plus optional component scoping; the
    backend LLM-reasons the factor decomposition (and composes the
    ``impact`` rating from it). The same prompt the generation
    pipeline uses for LLM-produced assets is reused here, so factors
    are calibrated consistently regardless of who introduced the
    asset. Override any factor post-create via ``edit_asset`` with a
    ``change_reason`` for the audit trail.

    ``component_ids`` (optional) links the asset to one or more
    deployable units. Components are the canonical bridge between
    security architecture (trust boundaries) and code organization
    (repos); linking assets here flows boundary context into the
    reachability graph. Multi-component is the right shape for
    multi-instance assets (e.g., a session token on client + cache).

    LLM-gated against a re-add of a previously soft-deleted asset on
    the same model. Three possible outcomes:

    - **Normal create** — fresh asset with a new ID. Returns the
      envelope ``{"model": ThreatModel, "controls_carried": N, ...}``.
    - **Auto-restore** — proposal matched a soft-deleted asset; that
      asset is un-deleted (CO tombstones revive). Response carries
      ``auto_restored: True``, ``restored_asset_id``, and
      ``discarded_fields``.
    - **Similar-verdict rejection** — ``{"accepted": False,
      "classification": "similar", "candidate_restore_id": "A-N",
      ...}``; nothing saved.

    Fails with a tool error on:
    - 503 — restore-candidate evaluator OR factor-reasoning evaluator
      unavailable. Retry with backoff.
    - 502 — restore-candidate evaluator returned malformed response.
      Retry same prompt.

    Args:
        model_id: ID of the threat model.
        name: Asset name (required).
        description: Optional description (recommended — feeds the
            factor-reasoning prompt).
        security_properties: Comma-separated properties, e.g. "C,I,A"
            (default: "C").
        notes: Optional notes.
        component_ids: Comma-separated component IDs scoping the asset
            (e.g., "CMP1,CMP2"). Empty / omitted = unscoped. Validated
            against components declared on the model.
    """
    body: dict[str, Any] = {"name": name}
    if description:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = [p.strip() for p in security_properties.split(",") if p.strip()]
    if notes:
        body["notes"] = notes
    if component_ids is not None:
        body["component_ids"] = [c.strip() for c in component_ids.split(",") if c.strip()]
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
    confidentiality_subscore: Optional[str] = None,
    integrity_subscore: Optional[str] = None,
    availability_subscore: Optional[str] = None,
    usage_subscore: Optional[str] = None,
    blast_radius: Optional[str] = None,
    recoverability: Optional[str] = None,
    regulatory_scope: Optional[str] = None,
    impact_rationale: Optional[str] = None,
    notes: Optional[str] = None,
    change_reason: Optional[str] = None,
) -> dict:
    """Edit an existing asset. Only provided fields changed.

    The composed ``impact`` is server-derived from the factor fields;
    there is no way to set it directly. To change the rating, set
    factor values (the platform composes the new rating) and supply
    ``change_reason`` documenting the operator override of the
    LLM-generated factors. The reason is captured in the
    rating-revision audit trail.

    LLM-gated on identity-bearing fields (name, description,
    security_properties). Factor and notes edits skip the gate.

    Outcomes when identity fields change:
    - **Accepted edit** (LLM classifies as ``preserve``) — normal
      envelope response.
    - **Rejected edit** (LLM classifies as ``replace`` /
      ``ambiguous``) — ``{"accepted": False, ...}``; nothing saved.
      Soft-delete + add-new instead.

    Editing a soft-deleted asset is rejected — ``restore_asset``
    first. 503 on evaluator outage, 502 on malformed response, 400
    when factor fields are sent without ``change_reason``.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset (e.g., "A1").
        name: New name (optional).
        description: New description (optional).
        security_properties: Comma-separated properties (optional).
        confidentiality_subscore: "None" | "Low" | "High".
        integrity_subscore: "None" | "Low" | "High".
        availability_subscore: "None" | "Low" | "High".
        usage_subscore: "None" | "Low" | "High".
        blast_radius: "Isolated" | "Multiplicative" | "Cascading".
        recoverability: "Trivial" | "Manageable" | "Permanent".
        regulatory_scope: "None" | "Notification" | "Legal".
        impact_rationale: New rationale (optional).
        notes: New notes (optional).
        change_reason: Required when any factor field is supplied —
            documents the operator override of LLM-generated factors
            for the audit trail.
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if description is not None:
        body["description"] = description
    if security_properties is not None:
        body["security_properties"] = [p.strip() for p in security_properties.split(",") if p.strip()]
    for fkey, fval in (
        ("confidentiality_subscore", confidentiality_subscore),
        ("integrity_subscore", integrity_subscore),
        ("availability_subscore", availability_subscore),
        ("usage_subscore", usage_subscore),
        ("blast_radius", blast_radius),
        ("recoverability", recoverability),
        ("regulatory_scope", regulatory_scope),
    ):
        if fval is not None:
            body[fkey] = fval
    if impact_rationale is not None:
        body["impact_rationale"] = impact_rationale
    if notes is not None:
        body["notes"] = notes
    if change_reason is not None:
        body["change_reason"] = change_reason
    # Pre-flight: factor edits without change_reason will 400 server-
    # side; surface that as a tool-level error so callers don't burn
    # an HTTP round-trip on the obvious case.
    factor_sent = any(k in body for k in _ASSET_FACTOR_PARAMS)
    if factor_sent and not (change_reason and change_reason.strip()):
        raise ToolError(
            "change_reason is required when editing rating factors. "
            "Factors are LLM-generated; an operator override needs a "
            "documented reason for the audit trail."
        )
    try:
        return _dump(await _get_client().edit_asset(model_id, asset_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_asset(server_version: str, model_id: str, asset_id: str) -> dict:
    """Soft-delete an asset. Creates a new version.

    The asset's ID is preserved forever — never reused. Its linked
    (asset × attacker) CO pairs are tombstoned, which orphans any
    controls mapped to them. Use `restore_asset` to un-delete and
    revive the tombstones (orphaned controls become active again).

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset to soft-delete.
    """
    try:
        return _dump(await _get_client().remove_asset(model_id, asset_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def restore_asset(server_version: str, model_id: str, asset_id: str) -> dict:
    """Un-soft-delete an asset. Revives its tombstoned COs with
    their original IDs, un-orphaning any linked controls.

    Args:
        model_id: ID of the threat model.
        asset_id: ID of the asset to restore.
    """
    try:
        return _dump(await _get_client().restore_asset(model_id, asset_id))
    except Exception as exc:
        raise _api_error(exc) from exc


_ATTACKER_FACTOR_PARAMS = (
    "attack_vector", "privileges_required", "attack_complexity",
    "user_interaction", "capability_prevalence",
)


@mcp.tool()
async def add_attacker(
    server_version: str,
    model_id: str,
    capability: str,
    position: str = "",
    archetype: str = "",
    trust_boundary_ids: Optional[str] = None,
) -> dict:
    """Add a new attacker to a threat model. Creates a new version.

    The caller supplies identity-bearing fields (capability, position,
    archetype, trust_boundary_ids); the backend LLM-reasons the factor
    decomposition. Override any factor post-create via ``edit_attacker``
    with a ``change_reason``. Mirror of ``add_asset`` semantics.

    Three outcomes (normal create / auto-restore / similar-rejection)
    mirror ``add_asset``. 503 on factor-reasoning or restore-candidate
    evaluator outage, 502 on malformed restore-candidate response.

    Args:
        model_id: ID of the threat model.
        capability: Attacker capability description (required).
        position: Position/access level.
        archetype: Archetype (e.g., "insider", "external").
        trust_boundary_ids: Comma-separated trust boundary IDs.
    """
    body: dict[str, Any] = {"capability": capability}
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
    attack_vector: Optional[str] = None,
    privileges_required: Optional[str] = None,
    attack_complexity: Optional[str] = None,
    user_interaction: Optional[str] = None,
    capability_prevalence: Optional[str] = None,
    likelihood_rationale: Optional[str] = None,
    trust_boundary_ids: Optional[str] = None,
    change_reason: Optional[str] = None,
) -> dict:
    """Edit an existing attacker. Only provided fields changed.

    The composed ``likelihood`` is server-derived from the factor
    fields; to change the rating, set factor values and supply
    ``change_reason`` for the audit trail.

    LLM-gated on identity-bearing fields (capability, archetype,
    position). Factor and trust_boundary edits skip the gate.

    503 on evaluator outage, 502 on malformed response, 400 when
    factor fields are sent without ``change_reason``.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker (e.g., "T1").
        capability: New capability (optional).
        position: New position (optional).
        archetype: New archetype (optional).
        attack_vector: "Network" | "Adjacent" | "Local" | "Physical".
        privileges_required: "None" | "Low" | "High".
        attack_complexity: "Low" | "High".
        user_interaction: "None" | "Required".
        capability_prevalence: "Commodity" | "Targeted" | "Rare".
        likelihood_rationale: New rationale (optional).
        trust_boundary_ids: Comma-separated trust boundary IDs (replaces existing).
        change_reason: Required when any factor field is supplied —
            documents the operator override of LLM-generated factors.
    """
    body: dict[str, Any] = {}
    if capability is not None:
        body["capability"] = capability
    if position is not None:
        body["position"] = position
    if archetype is not None:
        body["archetype"] = archetype
    for fkey, fval in (
        ("attack_vector", attack_vector),
        ("privileges_required", privileges_required),
        ("attack_complexity", attack_complexity),
        ("user_interaction", user_interaction),
        ("capability_prevalence", capability_prevalence),
    ):
        if fval is not None:
            body[fkey] = fval
    if likelihood_rationale is not None:
        body["likelihood_rationale"] = likelihood_rationale
    if trust_boundary_ids is not None:
        body["trust_boundary_ids"] = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()]
    if change_reason is not None:
        body["change_reason"] = change_reason
    factor_sent = any(k in body for k in _ATTACKER_FACTOR_PARAMS)
    if factor_sent and not (change_reason and change_reason.strip()):
        raise ToolError(
            "change_reason is required when editing rating factors. "
            "Factors are LLM-generated; an operator override needs a "
            "documented reason for the audit trail."
        )
    try:
        return _dump(await _get_client().edit_attacker(model_id, attacker_id, **body))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_attacker(server_version: str, model_id: str, attacker_id: str) -> dict:
    """Soft-delete an attacker. Creates a new version.

    Same lifecycle as remove_asset: ID preserved, linked COs
    tombstoned, orphaned controls derived at read time. Use
    `restore_attacker` to un-delete.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker to soft-delete.
    """
    try:
        return _dump(await _get_client().remove_attacker(model_id, attacker_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def restore_attacker(server_version: str, model_id: str, attacker_id: str) -> dict:
    """Un-soft-delete an attacker. Revives tombstoned COs; un-orphans
    any linked controls.

    Args:
        model_id: ID of the threat model.
        attacker_id: ID of the attacker to restore.
    """
    try:
        return _dump(await _get_client().restore_attacker(model_id, attacker_id))
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
    gaps. The response includes auto_remediate_jobs — these run in the
    background and complete automatically.

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
) -> dict:
    """Use LLM to map controls to framework requirements. Takes 20-45 seconds.

    Requires PRO tier.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        control_id: Optional specific control to map.
    """
    try:
        client = _get_client()
        result = await client.auto_map_controls(
            model_id, framework_id, control_id or "",
        )
        if isinstance(result, dict) and "job_id" in result:
            return await _await_backend_job(client, result["job_id"], ctx)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def auto_remediate(
    server_version: str,
    model_id: str,
    framework_id: str,
    ctx: Context,
) -> dict:
    """Automatically close compliance gaps for a framework. Requires PRO tier.

    Three-phase loop: (1) auto-map existing controls to unmapped requirements,
    (2) exclude requirements for non-applicable taxonomy primitives,
    (3) suggest and apply new assets/attackers for remaining gaps.

    Phase (3) routes every proposal whose name matches a soft-deleted
    asset/attacker through the same restore-candidate LLM gate
    ``add_asset`` uses, so reanimating a previously removed entity
    reinstates its stable ID and every CO tombstone + control tied to
    it (rather than spawning a duplicate fresh ID). The response
    distinguishes ``assets_added`` / ``attackers_added`` (genuinely new)
    from ``assets_restored`` / ``attackers_restored`` (revived soft-
    deletes) and lists ``restored_asset_ids`` / ``restored_attacker_ids``.
    Proposals the gate classified as ``similar`` (or that fail-closed
    on an unavailable / malformed gate response) appear under
    ``skipped`` with a per-entry reason — the operator decides whether
    to restore manually or rephrase.

    Converges automatically: stops when fully covered or when no further
    progress can be made.

    This runs automatically when a framework is selected, but can be
    re-triggered manually if the model changes.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
    """
    try:
        client = _get_client()
        result = await client.auto_remediate(model_id, framework_id)
        if isinstance(result, dict) and "job_id" in result:
            return await _await_backend_job(client, result["job_id"], ctx)
        return _dump(result)
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


# === Components ===


@mcp.tool()
async def add_component(
    server_version: str,
    model_id: str,
    name: str,
    repo_url: str = "",
    path: str = "",
    trust_boundary_ids: str = "",
) -> dict:
    """Add a component to a threat model.

    Components bridge security architecture to code organization. They map
    trust boundaries to repos so controls can be scoped to the codebase
    that implements them.

    Args:
        model_id: ID of the threat model.
        name: Component name (e.g., "Backend API", "Auth Worker").
        repo_url: Repository URL (e.g., "github.com/org/backend").
        path: Path within repo for monorepos (e.g., "services/auth").
        trust_boundary_ids: Comma-separated trust boundary IDs.
    """
    tb_ids = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()] if trust_boundary_ids else []
    try:
        return _dump(await _get_client().add_component(
            model_id, name, repo_url, path, tb_ids or None,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_component(
    server_version: str,
    model_id: str,
    component_id: str,
    name: str = "",
    repo_url: str = "",
    path: str = "",
    trust_boundary_ids: str = "",
) -> dict:
    """Edit a component's properties.

    Args:
        model_id: ID of the threat model.
        component_id: ID of the component (e.g., "CMP1").
        name: New name (empty = unchanged).
        repo_url: New repo URL (empty = unchanged).
        path: New path (empty = unchanged).
        trust_boundary_ids: New trust boundary IDs (comma-separated, empty = unchanged).
    """
    fields: dict = {}
    if name:
        fields["name"] = name
    if repo_url:
        fields["repo_url"] = repo_url
    if path:
        fields["path"] = path
    if trust_boundary_ids:
        fields["trust_boundary_ids"] = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()]
    try:
        return _dump(await _get_client().edit_component(model_id, component_id, **fields))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_component(
    server_version: str,
    model_id: str,
    component_id: str,
) -> dict:
    """Remove a component. Clears component_id from associated controls.

    Args:
        model_id: ID of the threat model.
        component_id: ID of the component to remove.
    """
    try:
        return _dump(await _get_client().remove_component(model_id, component_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Cross-Model Dependencies ===


@mcp.tool()
async def get_system_dependencies(
    server_version: str,
    system_id: str,
) -> dict:
    """Get cross-model dependency graph for a system.

    Returns all assumptions linked to other models in the system, with
    satisfaction status. Each dependency is satisfied when either the
    target model's mapped controls are implemented or a valid manual
    attestation exists.

    Use cases:
    - View which assumptions are satisfied by other models' controls
    - Identify unsatisfied cross-model dependencies
    - Verify system-level completeness (all dependencies met)

    Args:
        system_id: ID of the system.
    """
    try:
        return _dump(await _get_client().get_system_dependencies(system_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def link_dependency(
    server_version: str,
    model_id: str,
    assumption_id: str,
    target_model_id: str = "",
) -> dict:
    """Link an external assumption to a target model in the same system.

    Makes the assumption a cross-model dependency: it becomes a compliance
    requirement on the target model. Two independent satisfaction paths:
    auto-attestation when the target model's controls satisfy the
    requirement (no manual action needed), or manual attestation via
    submit_attestation. Either path alone suffices.

    The assumption must already be linked to control objectives (via
    add_assumption or edit_assumption with linked_co_ids). Pass empty
    target_model_id to unlink.

    Args:
        model_id: ID of the threat model containing the assumption.
        assumption_id: ID of the assumption (e.g., "AS1").
        target_model_id: ID of the target model in the same system.
            Pass "" to unlink.
    """
    try:
        return _dump(await _get_client().link_assumption(
            model_id, assumption_id, target_model_id,
        ))
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

    Each per-control ``sufficiency`` block carries:

    - ``status``: ``"sufficient" | "insufficient" | "pending" | "stale"``.
      ``"stale"`` means the cached verdict no longer reflects the current
      control description or active assertion set; a background
      re-evaluation has been triggered automatically on this read — call
      this tool again shortly for a refreshed verdict.
    - ``details``: human-readable LLM reasoning.
    - ``misaligned_assertion_ids``: assertions whose stated subject is
      off-topic for the control's current description (common after a
      control has been refined or regenerated). Treat as a directive:
      rebind to the right control, supersede via ``delete_assertion``,
      or rewrite. Do NOT treat them as evidence. A non-empty list forces
      the verdict to ``"insufficient"``.
    - ``stale``: boolean shortcut for ``status == "stale"``, kept distinct
      so an INSUFFICIENT verdict that's also stale (the prior insufficient
      decision was computed under outdated inputs) can be flagged without
      overloading ``status``.

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

    Writes the assumption to group 1 as the sole member. The control counts
    as active for mitigation group completeness when the referenced
    assumption is active and attested.

    AI relevance gate: the platform evaluates whether the assumption
    plausibly covers the control before saving. If the evaluator rejects,
    this tool raises with the rejection reasoning — there is NO override.
    Resolve by either picking an assumption whose description covers the
    control's responsibility, or by refining the chosen assumption's
    description to make coverage explicit. For compound (AND) or
    multi-path (OR) cases, use set_control_assumption_groups instead.

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


@mcp.tool()
async def get_control_assumption_groups(
    server_version: str,
    model_id: str,
    control_id: str,
) -> dict:
    """Get the current assumption group structure for a control.

    Assumption groups define alternative sets of external claims that can
    satisfy a control:
    - Within a group: AND — all assumptions must be active and attested
    - Across groups: OR — any complete group is sufficient to mark the
      control as externally handled

    Returns:
    - groups: numbered groups with member assumption details
      (id, description, status, attestation_status)
    - unmapped: active model assumptions not assigned to any group

    Use cases:
    - Before set_control_assumption_groups to see current structure
    - When reviewing why a control is / isn't externally handled
    - When an assumption's attestation expires and you need to trace impact

    The legacy assume_control / unassume_control tools remain as shorthand
    for the common single-assumption, single-group case. They operate on
    group 1.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-03").
    """
    try:
        return _dump(await _get_client().get_control_assumption_groups(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def set_control_assumption_groups(
    server_version: str,
    model_id: str,
    control_id: str,
    groups: str,
    justification: str = "",
) -> dict:
    """Declaratively set the assumption group structure for a control.

    Replaces all assumption group assignments for this control. Each group
    is a set of assumption IDs that together externally handle the control;
    any one group being fully active+attested is sufficient.

    - Within a group: AND — all referenced assumptions must be active and
      attested for the group to count as complete
    - Across groups: OR — any one complete group marks the control as
      externally handled for mitigation purposes

    To clear all assumption groups (revert to "not externally handled"),
    pass an empty JSON object: `{}`.

    AI relevance gate (per group, no override):
      Each non-empty proposed group is evaluated independently. The behavior
      depends on how many groups pass:

      - All groups accepted → 200 success, structure persisted as submitted.
      - Some groups accepted (partial): the accepted groups ARE persisted
        (runtime OR-semantics activate immediately), the rejected groups
        are NOT saved, the call raises with HTTP 422 detailing both
        persisted_groups and rejected_groups (with per-group reasoning).
        Resubmit only the rejected groups with assumptions that cover the
        control, or sharpen those assumptions' descriptions.
      - All groups rejected: existing groups on this control are
        re-evaluated through the same gate. Relevant existing groups are
        preserved; irrelevant existing groups are dropped (assumptions
        themselves remain in the model — only this control's linkage is
        removed). The call raises with HTTP 422 detailing what was
        persisted, what was rejected, and what existing was dropped.
      - Empty submission ({}): clears all groups, no evaluation.

    There is no force-override. To get a group accepted, choose assumptions
    whose descriptions actually cover the control or refine an assumption's
    description so coverage is explicit.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g., "CTRL-03").
        groups: JSON object mapping group numbers to assumption ID lists.
            Example: '{"1": ["AS1", "AS2"], "2": ["AS3"]}'
            Empty object `{}` clears all groups.
        justification: Why this group structure is appropriate (min 10 chars
            when groups is non-empty; optional when clearing).
    """
    import json as _json
    try:
        parsed_groups = _json.loads(groups)
    except _json.JSONDecodeError:
        raise ToolError("groups must be valid JSON: {\"1\": [\"AS1\"], ...}")
    if not isinstance(parsed_groups, dict):
        raise ToolError("groups must be a JSON object")

    if parsed_groups and len(justification.strip()) < 10:
        raise ToolError("justification must be at least 10 characters when setting groups.")

    try:
        return _dump(await _get_client().set_control_assumption_groups(
            model_id, control_id, parsed_groups, justification.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption Restore ===


@mcp.tool()
async def restore_assumption(server_version: str, model_id: str, assumption_id: str) -> dict:
    """Restore a soft-deleted assumption. Creates a new model version.

    The assumption returns to active status. Controls whose assumption_groups
    referenced this assumption keep their existing group structure intact
    (members were never removed by soft-delete — only the assumption's own
    status changed). Re-attestation is required before the assumption
    mitigates COs.

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

    Side effect on control-level linkage: this assumption is also removed
    from every assumption_groups entry on every control that referenced it.
    Any group left empty by the removal is dropped, and any control that
    no longer has at least one complete group reverts to not_implemented.
    Underlying assumptions are not deleted — only the linkages.

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

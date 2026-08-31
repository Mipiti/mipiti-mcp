"""Mipiti MCP Server — expose threat modeling tools via Model Context Protocol.

Single codebase for both standalone (stdio) and hosted (Streamable HTTP) modes.
All tools call the Mipiti REST API via MipitiClient.
"""

import asyncio
import contextvars
import json
import os
import time
from typing import Any, Dict, List, Literal, Optional

from anyio import BrokenResourceError, ClosedResourceError
from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from .assertion_types import format_for_docstring
from .client import MipitiClient

# ------------------------------------------------------------------
# Instructions (tier-aware)
# ------------------------------------------------------------------

# SERVER_VERSION env var is the authoritative version identifier sent
# to clients on every tool call. Required at startup. The value must
# change exactly when this package's runtime behavior changes —
# instructions block, tool docstrings, tool schemas, tool function
# bodies — so connected clients invalidate cached MCP guidance and
# pick up the new surface. A commit SHA of this package's source is
# the typical value; deployment tooling sets it. Local runs can set
# it to any string ("dev", a feature-branch name, etc.).
_SERVER_VERSION = os.environ["SERVER_VERSION"]

_INSTRUCTIONS_UPDATE_MESSAGE = (
    "Server instructions have been updated since your session started. "
    "Tool descriptions are pinned per session — a soft reconnect, reauth, or "
    "/mcp toggle does NOT refresh them, and re-adding under the same server "
    "name reuses the pinned schemas. In Claude Code, do a full teardown and "
    "re-add under a NEW name: (1) exit the session entirely; (2) run "
    "`claude mcp remove Mipiti` (substitute the name you used when adding if "
    "different); (3) re-run your original `claude mcp add ...` command but "
    "with a new server name — e.g. append `-1` (Mipiti -> Mipiti-1); "
    "(4) reauthenticate; (5) resume. The new name is what forces the client "
    "to load the fresh tool schemas; there is no need to start and exit an "
    "extra session in between."
)

_INSTRUCTIONS_BASE = """\
Mipiti generates threat models from feature descriptions and tracks security controls with machine-verifiable assertions.

Every tool call must include `server_version` set to """ + f"`{_SERVER_VERSION}`" + """. If the server responds with an `instructions_updated` field, relay the message to the user, in a way appropriate to your environment, then continue with the current task.

## When to use

Before implementing changes, call `generate_threat_model` with a description of the change. It automatically discovers similar existing models — either returning matches to refine or proceeding with generation. Use the resulting controls to guide your implementation.

## Constructing `feature_description`

Output quality scales with input quality. A one-line "this is a backend that handles payments" produces a generic, shallow model; a multi-paragraph spec with concrete components, integrations, and trust boundaries produces a useful one. Two scenarios require different gathering strategies:

**Scenario A — planned change (you're about to implement something).** The in-progress design discussion or PR description is usually enough. Pass it verbatim or lightly edited. Don't pad with unrelated repo context.

**Scenario B — existing repo (operator said "threat-model this repo" or similar).** The conversation context alone is almost never enough. Before calling `generate_threat_model`, gather:

1. **Purpose** — open `README.md` (and any `docs/` overview). One or two sentences on what the system does and who uses it.
2. **Components / processes** — entry points, services, daemons, workers. Look at `Procfile`, `docker-compose.yml`, `fly.toml`, k8s manifests, the `scripts` block in `package.json`, `__main__.py` / top-level `main.py` / `cmd/` directories, the `[project.scripts]` table in `pyproject.toml`. List each component with a short purpose.
3. **External integrations** — third-party APIs, databases, queues, auth providers, payment processors. Grep env-var references (`os.environ`, `process.env`), SDK imports (`stripe`, `boto3`, `@octokit`, etc.), and infrastructure definitions. Name each one and what it's used for.
4. **Data flows / assets** — what data enters the system and where it goes. Skim HTTP route files, webhook handlers, message-queue consumers, schema/model files. Note PII, secrets, credentials, regulated data.
5. **Trust boundaries** — where requests cross from less-trusted to more-trusted (network ingress, auth middleware, service-to-service calls, worker IPC). At minimum: "anonymous internet → authenticated API → internal services → datastore."
6. **Deployment shape** — SaaS / on-prem / hybrid / library. Single-tenant vs. multi-tenant. Look at `Dockerfile`, `fly.toml`, `helm/`, `terraform/`, or absence thereof.

Pass all of this as a multi-paragraph `feature_description`. The backend will detect similar existing models — if one matches, prefer `refine_threat_model` on it instead of `force=True`.

## Threat modeling

- `generate_threat_model` — creates a new model with trust boundaries, assets, attackers, and control objectives. Automatically detects similar existing models and routes accordingly. Progress reported automatically.
- `refine_threat_model` — updates an existing model when you already have a model ID and want to change it. Progress reported automatically.
- `add_asset` / `edit_asset` — targeted single-entity changes without full refinement. Each asset has a `status` field: `unverified` (default), `confirmed` (assertions prove it exists), `absent` (agent confirmed it is not applicable). Use `edit_asset` to update status after verifying.
- `add_attacker` / `edit_attacker` — same for attackers. Attacker `status` works the same way: `confirmed` means the attack surface exists, `absent` means it is not applicable.
- **Entity quality (authoring contract)**: an asset must name the *data or resource being protected* and the security property at stake (Confidentiality / Integrity / Availability / Usage), not a mechanism or control — name the key material, not "the KMS encryption". An attacker's `capability` must name the *operations performable from its position* — phrase it as "From [position], the attacker can [concrete operations] …" — not just the access or vantage point. Assets and attackers that fall short are flagged with a `quality_warning` and yield under-specified control objectives; sharpen them with `edit_asset` / `edit_attacker`, or re-run the check with `revalidate_entity_quality`.
- `get_entity(entity_type=…)` — read any single entity by type + id. One reader for every entity kind: `asset`, `attacker`, `component`, `trust_boundary`, or `assumption`.
- `remove_entity(entity_type=…)` / `restore_entity(entity_type=…)` — soft-delete or restore any entity by type + id (removals are audit-preserving; restore applies to `asset`, `attacker`, and `assumption`).
- `reevaluate_threat_model_factors` — bulk LLM re-run of the factor decomposition (subscores + blast/recoverability/regulatory on assets; CVSS-Base + capability_prevalence on attackers) for every live entity in a model. Use this to re-baseline an existing model after the feature description changes meaningfully, or to refresh stale ratings — without regenerating the whole model (which would destroy controls, assertions, components). The platform's factor judgment is a calibrated *starting point*; layer deployment-specific reality on top via `edit_asset` / `edit_attacker` with a `change_reason` documenting the override (e.g., "regulatory_scope=Legal — tenant is HIPAA-covered", "capability_prevalence=Commodity — endpoint is public-internet exposed"). The rating-revision audit trail distinguishes platform suggestions from operator overrides.
- `revalidate_entity_quality` — re-run quality validation over an existing model's assets and attackers (a fast first-pass check on every entity, a deeper review only on the ones it flags). Use it to apply validation improvements to an already-generated model or clear stale quality warnings, without regenerating. Non-destructive (it flags rather than deletes) and saves a new version.
- `get_threat_model` — retrieve a model's full structure (excludes COs by default; use `include_cos=True` to include them).
- `query_threat_model` — ask questions about an existing model.
- `list_threat_models` — browse existing models.
- `rename_threat_model` — rename a model (metadata only, no new version). Model titles must be unique within a workspace (case-insensitive); pick a distinct name on the first try to avoid a 409 retry.
- `set_threat_model_parent` — wire a model under (or detach it from) a parent on the recursive composition tree. Pass `parent_id=None` to clear. Server rejects cycles and over-deep chains; bumps version on success.
- `delete_threat_model` — permanently delete a model and all its data.
- `export_report` — export a threat model. Its scope/format params produce a PDF, HTML, or CSV report, or the self-contained JSON audit archive (every version, controls, assertions with CI verdicts, findings, attestations, sufficiency signatures — independently verifiable without origin-instance access). The same tool produces the group/tag auditor report (see Tags).
- `import_threat_model_archive` — restore an audit archive into a workspace. Assigns a fresh model_id every time; title collisions auto-suffix `(imported YYYY-MM-DD)`.

## Controls and assertions

A threat model produces control objectives. Controls are derived from these and represent specific security requirements to implement. Assertions are typed, machine-verifiable claims about system properties that prove a control is satisfied. A system property can be verified by examining source code, configuration files, infrastructure definitions, or external service settings.

**Key tools:**
- `get_controls` — lists controls with current status; pass a single control id to read just one. Use `summary_only=True` for a compact response (id, description, status, assertion_count, assumed_by).
- `get_control_objectives` — lists COs with which controls cover each one; pass a single CO id to read just one. Pair with `get_reachability_verdicts` to surface composer reachability state per CO before linking assumptions or regenerating.
- `submit_assertions` — provide proof for a control. See that tool's docstring for assertion types and required params. Always verify locally first: `mipiti-verify verify <type> -p key=value --project-root .` Read the target file and confirm a reviewer would agree with the claim.
- **Assertion design: prefer decomposition over breadth.** Tier 2 (semantic LLM check) evaluates each assertion with only its own check-type evidence. A single broad claim like "X calls Y to do A and B using C" will pass Tier 1 but fail Tier 2 — the mechanical evidence (e.g., a function_calls result) doesn't surface facts A, B, C. Split into multiple atomic assertions — one for each narrow aspect — each with a check type that directly shows the relevant code (`pattern_matches` on the specific line, `function_exists` for the named function, etc.). Submit them as a group on the same control. Sufficiency combines them; individually each is trivially provable.
- `list_assertions` / `delete_assertion` — list active assertions for a control; delete stale or incorrect ones before resubmitting.
- `update_control_status` — mark implemented or not_implemented. Requires at least one assertion BEFORE marking implemented. Always submit assertions first, then update status.
- `get_verification_report` — shows which controls are verified, which have sufficiency gaps, and which lack assertions entirely. Read `sufficiency_details` for the specific aspects that still need proof. Each `sufficiency` block also carries `misaligned_assertion_ids` (off-topic assertions that should be rebound, superseded, or rewritten — do not treat them as evidence) and `stale: true` (cached verdict no longer matches current inputs; a background re-eval was triggered on read — call again shortly for a refreshed verdict).
- `get_sufficiency` — quick check: do assertions for a single control collectively cover all aspects? Evaluated server-side at submission.
- `get_mitigation_groups` — get the current group structure for a CO with control details (id, description, status) for each entry. Shows numbered groups (AND within, OR across), defense-in-depth controls, and unmapped controls available for assignment. Use before `set_mitigation_groups`, when reviewing why a CO is at_risk, or to find unmapped controls.
- `set_mitigation_groups` — set which controls are required vs defense-in-depth for a CO. Use when a control is blocking a CO but is redundant with existing mitigations (e.g., HMAC signing redundant with TLS + content hash), or when restructuring alternative mitigation paths. Groups define: within group AND (all required), across groups OR (any complete group mitigates). AI-gated: rejected if the new structure doesn't satisfy the CO.
- `refine_control` — modify a control's description if it doesn't match the actual security requirement. **Side effect on accepted refinements**: every assertion attached to the control is superseded — their claims were authored against the prior description and may not be on-topic for the new one. Response carries `superseded_assertions: <count>`. Re-submit any assertion that still applies; superseded rows remain in history.
- `delete_control` — soft-delete a control with justification. Blocked if it is the only control covering a CO — add a replacement first.
- `import_controls` — import existing controls from JSON or free text, auto-mapped to COs and deduplicated against existing controls.
- `add_evidence` / `remove_evidence` — attach auxiliary metadata (docs, links, artifacts) to a control. Evidence is contextual only — it does NOT prove a control is implemented. Only assertions do that.
- `regenerate_controls` — regenerate controls. Supports `mode="per_co"` for thorough single-responsibility generation, and `co_ids="CO1,CO5"` to regenerate only specific COs (preserving other controls). Controls whose descriptions survive unchanged keep their implementation status, assertions, and mappings.

**Workflow — handle in this order:**

1. **Controls outside the system boundary** (externally handled): Read each not_implemented control description. If it describes something the system owner cannot implement (e.g., "restrict CI runner egress", "vendor maintains PCI DSS certification") — it belongs outside your trust boundary. Use `set_control_assumption_groups` to link it to an existing assumption, or create an assumption first with `add_assumption`. Do NOT submit codebase assertions for controls outside your boundary. The platform runs an AI relevance gate on every assumption-to-control linkage; if the assumption's description doesn't cover what the control requires, the call raises and there is no override. If rejected, either pick an assumption that covers the control or edit the assumption's description to make coverage explicit. `set_control_assumption_groups` handles both the simple single-assumption, single-group case and compound ("AS1 AND AS2") or multi-path ("AS1 OR AS2") cases.

2. **Controls already satisfied by existing code** (no code changes): use `get_controls` to list controls. For each, search the codebase for code that already implements it. If found, craft assertions that prove the implementation, verify locally, submit assertions, then call `update_control_status` to mark as implemented.

3. **Sufficiency gaps on verified controls** (no code changes): call `get_verification_report` and read `sufficiency_details` for controls that are partially verified. These are implemented but some aspects lack proof. Search the codebase for code that proves the missing aspects and submit additional assertions. If you cannot find proof for specific aspects, call `check_control_gaps` — the control's prescribed mechanism may need refinement.

4. **Controls requiring implementation** (code changes needed): before implementing, call `check_control_gaps` to verify the control's mechanism is appropriate. Then search the codebase for existing mechanisms that may already address the control. If found, call `refine_control` with `codebase_findings` — the platform evaluates whether the existing mechanism satisfies the objective and proposes a revised control if so. If accepted, submit assertions for the refined control. If rejected or no existing mechanism found, implement as prescribed, submit assertions, and update status.

Sufficiency is evaluated automatically server-side when assertions are submitted — no manual trigger needed.

**Diagnosing "implemented but not verified" — check in this order.** A control that is marked implemented but still reads `partially_verified` is the most common state you will meet, and the fields are easy to misread. Work down this list and stop at the first hit; do NOT skip to a recompute.

1. `get_sufficiency` (or `get_verification_report` for the whole model) — **start here, it is free and it is usually the answer.** If `status` is `insufficient`, `details` names each uncovered clause and the evidence that would close it. That is the work list. Write those assertions.
2. Check the clause against reality. If the control describes a mechanism the system deliberately does not use (it returns 404 where the control demands 403, say), the DESCRIPTION is what is wrong — `refine_control`, do not manufacture evidence to match prose no one intends to honour.
3. `list_assertions` — only if sufficiency looks fine. A `fail` on `tier1_status`/`tier2_status` means the evidence itself is broken. `coherence_status: "pending"` is advisory: it is not a blocker and not a missing verdict.
4. `recompute_verdicts` — **only** when control-to-CO MAPPINGS look wrong (`get_verdict_divergence` shows missing/spurious mappings). It does not compute per-control sufficiency or assertion coherence, it costs credits proportional to model size, and running it for a sufficiency gap changes nothing. Quote with `dry_run=True` and show the operator the number first.

The general rule: exhaust the free read-only verdict surfaces before recommending any metered write.

## When you hit an implementation constraint mid-coding

When a reviewer, hardware limit, library bound, or operator decision forces you off the prescribed mechanism (e.g., "this device only supports AES-128, not AES-256"), do NOT silently weaken the existing control or its assertions. Record the constraint structurally so the threat model reflects reality and the audit trail captures the reasoning. Use this 3-step pattern:

1. **Add the alternative control** — call `import_controls` with a single-entry `controls_json` describing the weaker-but-feasible mechanism. Set `co_ids` to the affected CO. Set `framework_refs` **honestly**: include only bindings the alternative actually satisfies — drop any that the weaker mechanism cannot meet. Then call `assign_to_components` to scope it to the constrained component(s) only, so the original control still applies elsewhere.

2. **Declare them as OR-alternatives** — call `set_mitigation_groups` on the affected CO with the original (strict) control in one group and the new (weaker) control in another (across groups = OR). Pass the operator's plain-language constraint reason in `justification` — it flows into the AI gate's verdict and the activity log.

3. **Record the constraint context** — call `add_assumption` with `linked_co_ids=[<co>]` capturing what reviewer or system imposed the constraint, the rationale, and any expiry conditions (e.g., "hardware refresh in 2027 lifts the AES-128 limit"). Then `submit_attestation` so the assumption is active.

If the alternative drops a framework binding the original carried, the platform automatically emits a `framework_binding_asymmetry` finding for the security team to triage — surfaced via `list_findings` and `get_findings_risks`.

## Assurance posture

- `assess_model` — deterministic assessment of all control objectives. Returns mitigated/at_risk/unassessed counts and progressive metrics (defined/implemented/verified COs). Use `summary_only=True` for a compact response with just the counts and a contextual `message` explaining the current state (e.g., "13 controls not implemented, blocking 35 COs"). Use `status` to filter, `offset`/`limit` to paginate. Each CO assessment includes `mitigated_by: "controls" | "assumption" | null` — `"assumption"` is a fully resolved state, not a gap. Only `at_risk` and `unassessed` COs require action.

**Reachability and risk reason**: Reachability per CO is exposed by `get_reachability_verdicts` (deterministic-computation provenance — re-derived from structural primitives, never persisted). Each CO assessment also includes:
- `risk_reason` — why a non-mitigated CO is at risk: `missing_controls` (implement controls), `pending_attestation` (submit an attestation for the linked boundary assumption), `expired_attestation` (renew an expired attestation), `unassessed` (generate controls or create an assumption), `asset_absent` (asset is not applicable — skip this CO), `attacker_irrelevant` (attack surface is not applicable — skip this CO), `coverage_gap` (controls are implemented but do not span the CO's full threat — add controls to close the gap, or dismiss/accept if intentional), `insufficient_by_design` (the controls *defined* for the CO's mitigation group would not mitigate the objective even if fully implemented — a design gap, not an implementation gap; redesign or add controls so the group can span the threat). `insufficient_by_design` is more binding than `missing_controls` and takes precedence over it.
- `asset_status` / `attacker_status` — verification status of the asset and attacker for this CO (`unverified`, `confirmed`, `absent`).
- `pending_assumption_ids` / `expired_assumption_ids` — assumption IDs that need attestation action.

**Before acting on any risk_reason, check whether a control is actually REQUIRED for the objective.** `get_mitigation_groups` splits a CO's controls into numbered groups (within=AND, across=OR) and `defense_in_depth`. Only the groups earn mitigation credit. If a CO has controls attached but ALL of them sit in `defense_in_depth`, or it has no groups at all, then nothing is required to mitigate it and the CO cannot leave at-risk no matter how many controls you generate or how much evidence you submit. That is a modelling gap, not an evidence gap: decide which controls genuinely carry the objective and place them in a required group with `set_mitigation_groups` (AI-gated, so the structure has to actually satisfy the CO). Generating or proving controls in this state is wasted work.

**Action routing by risk_reason**: `missing_controls` → implement controls and submit assertions. `pending_attestation` → call `submit_attestation` for the assumption IDs listed in `pending_assumption_ids` — do NOT try to implement controls for boundary-excluded COs. `expired_attestation` → call `submit_attestation` to renew for the assumption IDs listed in `expired_assumption_ids`. `unassessed` → generate controls with `regenerate_controls`. If the composer says the CO is indeterminate (per `get_reachability_verdicts`), the model is missing structure — supply it (position the attacker, scope the asset to a component) rather than asserting a conclusion. If the objective genuinely does not apply to this system, record that with `create_co_disposition`: the objective stays in the matrix and the counts, carrying the owner and justification, instead of disappearing. `asset_absent` → the asset is not applicable. No action needed — skip controls for this CO. `attacker_irrelevant` → the attack surface is not applicable. No action needed — skip controls for this CO. `coverage_gap` → the controls are implemented but leave part of the CO's threat unaddressed. Inspect the linked `coverage_gap` finding via `list_findings` for the uncovered aspects + suggested control, add controls (`regenerate_controls` / `import_controls`) and submit assertions; if it's a false positive `dismiss` the finding, or if intentional record a risk acceptance / assumption. `insufficient_by_design` → the controls *defined* for the CO's mitigation group would not mitigate the objective even if fully implemented. Do NOT just implement the defined controls — that will not help. Inspect the linked `insufficient_by_design` finding via `list_findings` for the rationale, then redesign or ADD controls to the mitigation group (`regenerate_controls` / `import_controls`, then `set_mitigation_groups`) so the group can actually span the objective's threat, and submit assertions; if it's a false positive `dismiss` the finding, or if intentional record a risk acceptance / assumption. (Contrast with `missing_controls`, where the defined controls *would* mitigate the CO and you simply implement them and submit assertions.)

## Gap discovery

For controls with status not_implemented, determine whether the code already implements them (submit assertions) or genuinely lacks them (submit findings):
- `get_review_queue` — start here for periodic maintenance: returns controls not reviewed in 90+ days. For each stale control, verify its assertions still hold against the current codebase.
- `get_scan_prompt` — returns targeted prompts for scanning the codebase against specific not_implemented controls (this is the security-control kind; the same tool serves the functional-conformance per-test briefs when you pass the functional kind — see Functional conformance).
- `check_control_gaps` — AI-powered gap analysis across all controls.
- `submit_findings` — report confirmed gaps where controls are missing.
- `list_findings` / `update_finding` — track finding lifecycle.
- `get_findings_risks` — workspace-wide dashboard: open findings, active risk acceptances, and at-risk Control Objectives in one call. Use as the triage entry point when the operator asks "what's open?" / "what should I work on next?".
- `get_risk_view` — Prioritized Risk View rows for a specific target (pass the scope — a model, a system, or a tag/group) with risk dimensions, control coverage counts, and open-finding counts per CO. Use when narrowing from workspace-wide to a specific target.
- `get_remediation_leverage` — for one model, the not-yet-satisfied controls ranked by how many control objectives each closes, plus a greedy minimal fix order. Use to prioritize implementation: which controls to build first for the shortest path to coverage; each entry names its owning model, so a high-leverage control inherited from a parent model is clear.
- `list_risk_acceptances` — see which risks have been explicitly accepted on a model (with owner, justification, review deadline) so you can separate intentional acceptances from genuinely unaddressed gaps.
- `create_risk_acceptance` — record a deliberate acceptance of a control objective's residual risk (owner, justification, review deadline) so a known-and-accepted decision is explicit and auditable rather than an implicit gap.
- `create_co_disposition` — record that a control objective DOES NOT APPLY to this system (owner, justification, review deadline). The sibling of a risk acceptance, and the difference is the claim: an acceptance says the exposure is real and is being carried; a disposition says the objective does not apply here at all. The objective is NOT removed — it stays in the matrix and in every coverage count, reported in its own class with the owner and justification attached, so a reviewer can challenge the judgment. What it does suppress is work: no controls are generated for it and no coverage gap is raised against it.
- `list_co_dispositions` — see every signed judgment on a model's objectives (both kinds, including expired and revoked ones, which are part of the audit trail). Read this before authoring a new one: an existing judgment may already cover the objective, or may have expired and need re-signing rather than duplicating.
- `recompute_verdicts` — force a fresh evaluation of every control's coverage verdict and every live CO's group-sufficiency verdict when the surfaced divergences look stale. Runs in the background; the response includes an informational cost estimate and a spend status object (an exhausted status means the work is queued and resumes automatically — never dropped). Pass its quote-only param to get the cost estimate alone, pre-flight, without enqueuing the recompute.

## Remediating findings (structural drift)

The platform emits structural-drift findings (e.g. duplicate controls that accumulated from prior platform behavior, framework-binding asymmetries when mitigation groups have inconsistent compliance coverage) via list_findings. For findings whose kind supports automatic remediation, you can offer the operator a one-click cleanup flow:

1. Call preview_finding_remediation(finding_id) to see the proposed change. The response is a structured diff scoped to that one finding — typically very small.

2. SHOW THE OPERATOR THE DIFF. Do not commit silently. The operator should see exactly which controls would be merged, what framework refs would consolidate, etc.

3. Get the operator's confirmation AND a one-line rationale (e.g. "cleaning up duplicates from pre-fix trigger bug").

4. Call apply_finding_remediation(finding_id, justification=<rationale>) to commit. The platform records who, what, and why for the audit trail.

Never apply remediation without preview. The platform does not enforce this — it's the agent's responsibility to surface the change before committing.

**Diagnose-and-hand-off findings.** Some finding kinds have NO automatic remediation handler (`preview_finding_remediation` / `apply_finding_remediation` return 422) — they describe a gap for you to resolve directly with the control tools, then submit assertions / `update_finding`: `coverage_gap` (the CO's controls do not span its full threat → add the missing controls via `regenerate_controls` / `import_controls`, or `dismiss` if a false positive, or record a risk acceptance / assumption if intentional), `insufficient_by_design` (the controls *defined* for the CO's mitigation group would not mitigate it even if fully implemented → do NOT just implement the defined controls; redesign or add controls to the mitigation group via `regenerate_controls` / `import_controls` + `set_mitigation_groups` so the group can span the threat, or `dismiss` if a false positive, or record a risk acceptance / assumption if intentional), `control_mechanism` (an existing control's mechanism is wrong and could not be corrected automatically → edit, split, or remove it; the finding's details list the control's full CO-set so you see the blast radius before changing a shared control), `misclassified_defense_in_depth` (a defense-in-depth control is load-bearing for a CO's coverage → promote it into that CO's mitigation group via `set_mitigation_groups`). Do not call `apply_finding_remediation` for these kinds.

## Project setup

- `get_setup_status` — check which onboarding steps are done and which are pending. Call before suggesting setup actions to avoid repeating completed steps.
- `complete_setup_step` — mark an onboarding step as done. Call after completing a setup action: `mcp_configured` (after MCP server is connected), `mipiti_verify_installed` (after installing mipiti-verify), `ci_secret_added` (after adding the API key to CI secrets), `ci_pipeline_added` (after adding the verification job to CI).

## Trust boundaries and assumptions

Trust boundaries and assumptions are versioned (CRUD creates new model versions with carry-forward).

**Decision rule — control or assumption?** If a security requirement can be implemented and machine-verified in the codebase → it is a **control**. If it describes a property that must be upheld by an external party (customer, vendor, operator) and cannot be implemented by the system owner → it is an **assumption**. The trust boundary is the dividing line. When in doubt: if you cannot write a codebase assertion that proves it, it is an assumption.

- `get_threat_model` — returns existing trust boundaries (along with assets, attackers, and assumptions). Use this to review current boundaries before adding or modifying them.
- `add_trust_boundary` / `edit_trust_boundary` — create or edit trust boundaries (defines where trust transitions occur); soft-delete one with `remove_entity(entity_type="trust_boundary")`.
- `add_assumption` — add an assumption, optionally linking it to COs it covers via `linked_co_ids`. Linked assumptions can mitigate COs when attested.
- `edit_assumption` — update description and/or linked COs.
- `remove_entity(entity_type="assumption")` — soft-delete an assumption (preserved for audit). Linked COs are no longer mitigated by it; controls with `assumed_by` pointing to it become inert (pointer preserved to enable restore).
- `restore_entity(entity_type="assumption")` — restore a soft-deleted assumption. Controls with `assumed_by` pointing to it automatically reconnect. Re-attestation required before the assumption mitigates COs again.
- `submit_attestation` — record that a responsible party affirmed an assumption holds. Provide `attested_by`, `statement`, and `expires_at` (ISO 8601, e.g. "2027-03-29T00:00:00Z"). Expiry triggers CO re-evaluation.
- `list_attestations` — attestation history for an assumption.

**Assumption types**: Two types, set via `assumption_type` in `add_assumption`:
- `non_applicability` — entity is not applicable to the feature. Requires CI verification (submit assertions + run mipiti-verify). Manual attestation is rejected. Originates from the taxonomy-classification step (which judges the feature against the closed 17-primitive taxonomy) or from operator-authored declarations. Generation-time validation failures on individual assets / attackers do NOT auto-create non-applicability assumptions; entities that exhaust the validation loop's retries receive a `quality_warning` field for the operator to review.
- `external` (default) — responsibility handled by a third party that cannot be CI-verified against the codebase (e.g., vendor SLAs, infrastructure isolation, customer CI hardening). Allows manual attestation via `submit_attestation`.

**Assumption-based mitigation**: An active assumption with linked COs and a current (non-expired) attestation mitigates those COs. The assessment reports `mitigated_by: "assumption"` — this is a resolved state, not a gap.

**Control-level assumption groups**: For COs that span trust boundaries, individual controls can be marked as externally handled by assumptions. Assumption groups express alternative sets of external claims: within a group all assumptions must be active+attested (AND), any complete group suffices (OR).
- `get_control_assumption_groups` / `set_control_assumption_groups` — inspect and set the full group structure. Use `set_control_assumption_groups` for every case: the common single-assumption, single-group case (write one assumption into group 1), compound cases ("AWS KMS + quarterly review" or "HSM + FIPS certification"), and multiple independent paths.

**Violation workflow**: When an assumption is violated or attestation expires, affected COs become at-risk. Four remediation paths:
1. Re-attest — `submit_attestation` with new expiry (assumption still valid)
2. Restore — `restore_entity(entity_type="assumption")` if assumption was soft-deleted and is still valid; re-attest after restoring
3. Convert to controls — `convert_assumption_to_controls` generates controls for affected COs and retires the assumption linkage
4. Accept risk — `create_risk_acceptance` (the exposure is real and is being carried), or `create_co_disposition` (the objective does not apply to this system at all). Both are signed, owned, justified and expiring; `list_co_dispositions` shows what is already recorded.

## Composition (recursive-tree multi-model)

Threat models can compose hierarchically — a child model inherits assets, attackers, components, trust boundaries, and baseline controls from its parent (and transitively from ancestors). With composition enabled, the effective model = own ⊕ inherited; the platform computes effective control objectives, coverage, compliance, reachability, attack paths, and finding inheritance over that composed view.

**When to use**: a child model that shares a security baseline with its parent (e.g., a feature built on top of a multi-tenant platform that already has auth / MFA / RBAC / KMS controls). Composition lets the child operator focus on the feature's delta while the parent's controls credit the child automatically.

### Reading the composed view

Start with the overview, then drill in:
- `get_composition_overview` — flag state, tree position, own-vs-inherited counts, reconciliation badge. Cheapest call (~1-2KB). Use first.
- `composition_entities` — full own + inherited entity set per kind.
- `composition_control_objectives` — effective CO list (classified own / cross / inherited).
- `composition_coverage` — effective coverage / compliance numbers.
- `composition_reachability` — composed reachability verdicts.
- `composition_attack_paths` — AttackPath references resolved against the effective entity set (paths spanning inherited entities resolve cleanly).

### Reconciliation — surfaced cross-tree duplicates

When the same entity is authored on both the child and an ancestor (e.g., both name an "API Gateway" component), the detector surfaces it as a reconciliation candidate. Two tiers:
- `certain` — identical name AND identical structural refs (same trust boundary / asset attachments). Auto-merge eligible.
- `heuristic` — identical name only; structural refs differ. Triage needed.

Tools:
- `composition_reconciliation` — paginated candidate list with names, source-model titles, and reasons.
- `reject_reconciliation_candidate` — record "these are NOT duplicates"; the detector filters the pair out of future queues, durable at org scope.
- `unreject_reconciliation_candidate` — undo a rejection.
- `list_reconciliation_candidates` — the unified candidate reader; pass its rejections param to list the rejected pairs for a model instead of the active candidates.

### Mutations — lift and split

When the operator confirms a duplicate should be reconciled, lift it to the lowest common ancestor (LCA). Inverse: split an ancestor entity down to specific descendants when the entity isn't shared after all.
- `lift_composition_entity` — promote shared-anchor entity from two descendants to their LCA. Carries operator confirmations (LCA, third-party subtree acknowledgements, field-resolutions, attached-state resolutions, optional over-application-gate override). Emits `lift_applied`; audit pack surfaces under `lift_history`.
- `split_composition_entity` — push an ancestor entity down to operator-chosen descendants. Emits `split_applied`; audit pack `split_history`.

### Undo with divergence detection

Both lift and split mutations are reversible. The divergence detector refuses the undo with enumerated reasons if state has continued to evolve since the mutation (e.g., entity edited after lift, re-lifted further up, descendant collision, attached-state mutation, model deletion).
- `preview_undo_composition(…)` — read-only preview of undoing a lift or split (pass the event type / id); returns `{plan, refusal}`. Always preview FIRST.
- `undo_composition_event(…)` — apply the inverse of a prior lift or split mutation. Emits `lift_undone` / `split_undone` citing `original_event_id`.

**Operator pattern**: preview → inspect plan or refusal-reasons → if clean proceed with apply; if refused, surface the enumerated reasons (operator decides whether to edit the divergence manually or accept it).

## Cross-model dependencies (delegation)

Distinct from the parent/composition tree (containment): a *reliance* edge declares that one model depends on a control implemented in ANOTHER model — the right tool when a product is built on shared services (auth, logging, a shared datastore) rather than being a sub-part of them. The target is always a provider *control*, so credit terminates at a proven mechanism. Reliance is scoped to the current workspace: a consumer can only delegate to provider models in the SAME workspace (these tools don't see models across workspace boundaries), so pick the foundation from this workspace's models. These tools are available when the recursive-tree feature is enabled.

- `declare_foundation` — mark a shared-service model as a foundation that advertises specific controls other models can delegate to.
- `propose_attach_foundation` → `attach_foundation` — bulk flow: propose which of a consumer's objectives each foundation capability covers (read-only, scored), then create draft delegation edges for the chosen subset.
- `create_reliance` — declare a single dependency. `delegated` (consumer has no local control for an objective; the provider handles it — pass `source_objective_id`) or `relied_upon` (consumer keeps its own control but its validity depends on the provider's — pass `source_control_id`).
- `confirm_reliance` — promote a draft edge to active. Edges run LLM semantic validation on creation and carry NO credit until confirmed, and only when validation returned `valid` (a `partial` or mode-mismatch is refused — never silently credited).
- `list_reliance` — a model's dependency edges (as consumer) plus who relies on it (as provider — the blast radius before changing its controls).
- `delete_reliance` — remove an edge.

A delegated objective is credited only while the provider control stays verified; if the provider control regresses or a refined mechanism no longer satisfies the consumer, the edge breaks and a finding is raised on the consumer.

## Tags (grouping)

A *tag* is an overlapping, semantics-free grouping of models — for audit scopes, ad-hoc selections, or portfolios. It is a label, not a relationship: a model may carry MANY tags, and a tag never affects posture or credit (that's what delegation and composition are for). Use tags to organize and to get an aggregate risk view across a chosen set of models. Tags and systems are both *groups*; the `kind` param on the group tools selects which kind.

- `create_group(kind="tag")` / `delete_group` — create or remove a tag (deleting affects the grouping only, never the member models).
- `add_model_to_group(kind="tag")` / `remove_model_from_group` — manage membership; a model can be in many tags at once.
- `list_groups(kind="tag")` / `list_model_groups` — browse tags, or a model's tags.
- `get_risk_view` — aggregate per-CO risk across a tag's members (pass the tag/group as scope). Delegation-aware, so a CO mitigated via a verified cross-model delegation reads as covered, consistent with the per-model assessment.

A tag can also be a **compliance / audit scope** spanning several models: `select_compliance_frameworks` scoped to the tag selects frameworks for the tag and propagates them to its members; `get_compliance_report` scoped to the tag gives cross-model requirement coverage; `export_report` scoped to the tag produces the signed auditor HTML (member reports + cross-model dependency graph + attestation status) — the tag equivalents of the system-level compliance report and auditor export.

## Functional conformance

Functional conformance proves a feature does what it was *specified* to do — the parallel of security controls, verified by the same assertion + CI engine. Capabilities are the behaviours the feature must deliver; each is tested against a taxonomy of operating conditions (nominal, boundary, dependency-failure, …), and a Functional Objective is a Given-When-Then acceptance criterion. Two ways to establish coverage:

**Generate (top-down).** `generate_functional_objectives` derives capabilities, objectives, and the concrete tests to write; `get_scan_prompt` (pass the functional kind) returns the per-test brief; implement each test, register it with `add_functional_test`, then submit `TEST_EXISTS` + `TEST_PASSES` evidence with `submit_functional_test_assertions` so CI verifies it.

**Import (bottom-up) — bring the tests you already have.** `import_functional_tests` registers your existing codebase tests (optionally with the objectives they cover; the platform verifies each association is applicable before accepting it). For tests you don't map yourself, `suggest_functional_test_mappings` proposes which objective each one actually proves (judged on behaviour, with a confidence) and `associate_functional_test` confirms a mapping — so an existing suite counts toward conformance, not only Mipiti-specified tests.

- `get_functional_coverage` / `check_functional_gaps` — the Capability × Condition coverage report and the actionable gaps (uncovered cells, failing/untested objectives).
- `set_functional_satisfaction_groups` / `get_functional_satisfaction_groups` — when several tests must *together* prove an objective, group them (within a group all must pass; any complete group proves the objective).
- `get_functional_test_sufficiency` — whether a test's submitted evidence is sufficient to prove the objective it targets.
"""

_INSTRUCTIONS_COMPLIANCE = """\

## Compliance

1. `list_compliance_frameworks` — available frameworks (SOC 2, ISO 27001, etc.).
2. `import_compliance_framework` — import a customer-specific framework (regulatory, contractual, or internal program not covered by the 11 built-ins). Accepts a JSON body with `name`, `requirements`, and the optional `level_definitions` per-level legend.
3. `select_compliance_frameworks` — activate frameworks for a model (or, by scope, for a system or tag/group). **Automatically triggers auto-remediation**: maps existing controls, excludes non-applicable requirements by taxonomy, and suggests/applies new entities for remaining gaps. Returns `auto_remediate_jobs` with job IDs for polling.
4. `get_compliance_report` — coverage report for a model, system, or tag/group by scope (run after auto-remediation completes).
5. `auto_remediate_compliance` — re-trigger auto-remediation manually (e.g. after model changes).
6. `auto_map_controls` — map controls to framework requirements (runs automatically during auto-remediation, but can be triggered independently).
7. `map_control_to_requirement` — manually map a specific control to a specific requirement (use when auto-mapping misses or misassigns).

### Per-entity grades

Some frameworks (IEC 62443, ISO/SAE 21434, NIST CSF, FIPS 140-3, Common Criteria) carry per-entity level grades alongside the control-to-requirement mapping:

- `edit_component` with `target_sl` / `eal` / `fips_level` — set per-component IEC 62443 SL (1-4), CC EAL (1-7), FIPS 140-3 (1-4). Orthogonal axes; set whichever the customer program requires.
- `set_control_objective_cal` — set per-CO ISO/SAE 21434 Cybersecurity Assurance Level (1-4). Lives on the CO identity table; survives soft-delete.
- `update_organization` — set per-org IEC 62443-4-1 Maturity Level (1-5) and NIST CSF Tier (1-4). Admin-only.

## Systems and workspaces

- `list_workspaces` — list workspaces the current user can access. Use to find the right workspace when working across team contexts.
- `list_groups(kind="system")` / `get_group` — browse and retrieve system groups. Systems and tags are both *groups*; the `kind` param selects which kind.
- `create_group(kind="system")` / `add_model_to_group(kind="system")` — group related models into a system.
- `get_system_dependencies` — view cross-model dependency graph. Shows which assumptions are linked to other models and whether they are satisfied.
- `link_system_dependency` — link an external assumption to a target model in the same system. Makes it a cross-model dependency that appears as a compliance requirement on the target model. Two independent satisfaction paths: auto-attestation from target controls (no manual action needed), or manual attestation via `submit_attestation`. Either alone suffices.
- `select_compliance_frameworks` / `get_compliance_report` (both scoped to the system) — cross-model compliance reporting.

## Components

Components bridge security architecture (trust boundaries) to code organization (repos). Add components to a model to scope controls to specific codebases AND to ground the deterministic reachability composer's asset-boundary derivation.

- `add_component` — create a component with name, repo_url, and optional path (for monorepos) and trust_boundary_ids.
- `edit_component` — modify a component; delete one with `remove_entity(entity_type="component")`.
- `get_controls` with `component_id` — filter controls by component.
- `assign_to_components` — link an asset (or a control) to one or more components. For an asset this drives the reachability composer's per-CO verdicts.

### When to populate components

`generate_threat_model` proposes speculative components (with `repo_url=""`) when no topology has been supplied. These are a starting point — refine them as code grounding emerges:

- **Existing codebase**: when you've scanned the repo and know the real services, call `add_component` (with grounded `repo_url` and `path`) BEFORE `generate_threat_model`. The generation prompts will scope assets and boundaries to the components you supplied. Alternatively, call `generate_threat_model` first and then `edit_component` on each speculative component the LLM proposed, swapping `repo_url` to the real URL.
- **Planning conversation, no code yet**: call `generate_threat_model` directly; the LLM-proposed speculative components serve as a topology starting point the user/developer refines as the design firms up. `repo_url` stays empty until code exists; the coherence report flags `component_unbound` findings on speculative components so they're visible to auditors.

A component with empty `repo_url` is the natural signal "speculative — not yet bound to code." A component with a populated `repo_url` is grounded. There is no separate status field — the binding is the state.

But an empty `repo_url` covers two different things, and the component's trust boundary tells them apart. A component in one of YOUR internal zones (your own backend/frontend/service repos) is your code — ground it to the repo. A component in an EXTERNAL trust zone — e.g. a third-party service, the customer's IdP, or other infrastructure you call but do not own — has no repo of yours; leave it unbound, where `component_unbound` is the correct permanent marker of an external dependency, not a TODO. The test is the trust boundary, never "does some client code touch it": client code for almost every dependency lives in your repo, so that alone never justifies binding an external component.
"""

_INSTRUCTIONS_ASYNC = """\

## Long-running operations

`generate_threat_model`, `refine_threat_model`, `auto_remediate_compliance`, `auto_map_controls`, `regenerate_controls`, and `check_control_gaps` run LLM pipelines that may take several minutes. They block until complete and report progress automatically — no polling needed for the operation itself.

**Controls may be generated asynchronously.** `generate_threat_model` and `refine_threat_model` return the model as soon as it is built, but the implementation controls can then be authored in the background. If the result carries a `controls_status` other than `complete` (e.g. `queued`, `generating`, `deferred`), the controls are NOT ready yet — do not report them as done. Poll `get_control_generation_status(model_id)` (it returns `terminal` and a `hint`) until the status is terminal, then read the controls with `get_controls`. `deferred` means the workspace's daily background-analysis budget is used up; generation resumes automatically at the daily reset — surface that, no action needed.
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
        # Empty client_version is treated as stale (rejected) — the prior
        # ``if client_version and ...`` guard let agents bypass the safety
        # check by omitting the field. The pin exists so the server can
        # refuse calls under a stale tool catalog (renamed params, new
        # required fields, removed tools); a bypass via empty defeats
        # that guarantee.
        if client_version != _SERVER_VERSION:
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


async def _confirm_import(ctx: Context, controls: list[dict], dup_count: int) -> bool:
    """Confirm a mutating control import with the user via MCP elicitation.

    Summarizes what will be saved and lets the user approve or cancel in their
    client (e.g. a terminal prompt). If the client does not support elicitation,
    proceed — the agent invoked this tool deliberately on the user's behalf.
    """
    header = f"About to import {len(controls)} control(s) into the threat model"
    if dup_count:
        header += f" ({dup_count} duplicate(s) of existing controls skipped)"
    lines = [header + ":"]
    for c in controls[:10]:
        lines.append(f"  • {str(c.get('description', ''))[:120]}")
    if len(controls) > 10:
        lines.append(f"  … and {len(controls) - 10} more")
    message = "\n".join(lines)
    try:
        result = await ctx.elicit(
            message=message, response_type=["Apply import", "Cancel"],
        )
    except Exception:
        # Client doesn't support elicitation — proceed (agent-initiated).
        return True
    return (
        getattr(result, "action", None) == "accept"
        and getattr(result, "data", None) == "Apply import"
    )


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
    parent_id: str | None = None,
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
        parent_id: Optional ID of an existing model to wire the new
            model under as a child on the recursive composition tree.
            The child then inherits the parent's topology and
            participates in composition (delta / inherited control
            credit). Default None — the model is created flat.

    Return shape (normal generation):
        ``{"model_id", "version", "title", "asset_count",
           "attacker_count", "control_objective_count"}``, and — when the
        workspace bounds background analysis spend — a ``governor`` object
        (``{"status": "ok"|"warning"|"exhausted", "exhausted", "resets_at",
        ...}``). When ``governor.status`` is ``warning`` or ``exhausted``,
        relay it to the user: analysis is nearing or at today's budget and
        queued background work resumes at ``governor.resets_at`` — it is never
        dropped. Absent when no budget applies.

        May also carry ``controls_status`` (+ ``controls_expected``) when
        controls are authored asynchronously: if it is anything other than
        ``complete``, the controls aren't ready yet — poll
        ``get_control_generation_status(model_id)`` until terminal, then read
        the controls. Absent when controls were built inline.

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
            parent_id=parent_id,
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
        # `model_id` is the persisted model id; `threat_model.id` is the
        # generated in-memory id, which can be present even when the model was
        # not saved — returning it yields an id that 404s on the next fetch.
        # Prefer `model_id`, and if it is absent treat the generation as not
        # persisted rather than reporting an unusable id.
        model_id = getattr(result, "model_id", "") or ""
        if not model_id:
            raise RuntimeError(
                "Threat model was generated but not saved (no model id "
                "returned). This is usually a transient storage error — please "
                "retry generate_threat_model."
            )
        gov = getattr(result, "governor", None)
        cs = getattr(result, "controls_status", None)
        ce = getattr(result, "controls_expected", None)
        return {
            "model_id": model_id,
            "version": tm.version,
            "title": tm.title,
            "asset_count": len(tm.assets),
            "attacker_count": len(tm.attackers),
            "control_objective_count": len(tm.control_objectives),
            **({"governor": gov} if gov else {}),
            # Async control generation: when present, controls are being authored
            # in the background — poll get_control_generation_status until the
            # status is terminal, then read the controls.
            **({"controls_status": cs} if cs else {}),
            **({"controls_expected": ce} if ce is not None else {}),
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
      path is ``remove_entity (entity_type="asset")`` / ``remove_entity (entity_type="attacker")`` (soft-delete).
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
          governor?: {status, exhausted, resets_at, ...},
        }

    ``*_count`` includes soft-deleted / tombstoned entries;
    ``live_*_count`` excludes them. Agents summarizing the result
    should typically quote the live counts unless specifically
    looking at history.

    A ``governor`` object is present when the workspace bounds background
    analysis spend; when ``governor.status`` is ``warning`` or ``exhausted``,
    relay it — queued background work resumes at ``governor.resets_at`` and is
    never dropped.
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
        # Prefer the persisted `model_id` over the in-memory `threat_model.id`
        # (see generate_threat_model). An empty `model_id` means the refine did
        # not persist, so surface that instead of reporting a stale success.
        model_id = getattr(result, "model_id", "") or ""
        if not model_id:
            raise RuntimeError(
                "Refine completed but was not saved (no model id returned). "
                "This is usually a transient storage error — please retry "
                "refine_threat_model."
            )
        return {
            "model_id": model_id,
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
            **({"governor": _gov} if (_gov := getattr(result, "governor", None)) else {}),
            **({"controls_status": _cs}
               if (_cs := getattr(result, "controls_status", None)) else {}),
            **({"controls_expected": _ce}
               if (_ce := getattr(result, "controls_expected", None)) is not None else {}),
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
    """Ask a natural-language question about an existing threat model.

    Read-only; no side effects (no new version, no mutation). Uses AI to answer questions grounded in the model's assets, attackers, control objectives, assumptions, and current security posture, returning ``{model_id, answer}`` where ``answer`` is prose.

    Use this for interpretation or summary questions ("what are the biggest gaps?", "which attackers target the token store?"). Do NOT use it to change the model — use ``refine_threat_model`` for that — and prefer ``get_threat_model`` / ``assess_model`` when you need structured data (entity lists, coverage counts) rather than a written answer.

    Args:
        model_id: ID of the threat model to query.
        question: The natural-language question to ask.
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
    """List saved threat models in the current workspace.

    Read-only; no side effects. Returns ``{items: [{id, title, version, created_at, ...}], count}``. Use this to discover model IDs to pass to other tools, or for a portfolio overview.

    Args:
        source: Filter by the system that created each model. One of "web", "mcp", "jira", "api". Omit (default "") to list all models regardless of source.
        include_assessment_summary: If True, include an `assessment_summary` object per model (counts of mitigated / at_risk / unassessed control objectives plus a human-readable `message`). Use for aggregate posture queries across the workspace in a single call (e.g. "which of my models are at risk?") instead of calling `assess_model` once per model. Adds roughly 100 bytes per model. Default False.
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
async def set_threat_model_parent(
    server_version: str,
    model_id: str,
    parent_id: str | None,
) -> dict:
    """Set (or clear) a model's parent on the recursive composition tree.

    The composition substrate (Layer 0) builds an ancestor chain from
    each model's ``parent_id`` so child models inherit topology, control
    objectives, and other entities from their ancestors. Use this tool
    when wiring a child model under a platform / system / shared-services
    ancestor, or when re-rooting a model after a re-org.

    Pass ``parent_id=None`` to clear the parent (the model becomes a
    tree root). The server rejects cycles (you cannot make a descendant
    your parent) and over-deep chains (depth bounded by the platform's
    configured maximum tree depth) with HTTP 400. Bumps the model version on
    success.

    Returns the updated threat model.

    Args:
        model_id: ID of the threat model whose parent is being set.
        parent_id: ID of the new parent model, or ``None`` to clear.
    """
    try:
        result = await _get_client().set_parent(model_id, parent_id)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def declare_foundation(
    server_version: str,
    model_id: str,
    provides: list[dict],
    visibility: str = "workspace",
) -> dict:
    """Mark a model as a shared foundation that advertises providable controls.

    Mutating: records this model as a foundation and stores its advertised controls; other models can then delegate to them (see ``propose_attach_foundation`` / ``attach_foundation``). A foundation is a shared service (auth, logging, a shared datastore) whose controls other models can rely on.

    Each entry in ``provides`` advertises one of THIS model's controls as providable: ``{"control_id": "CTRL-07", "capability_label": "Validates session tokens", "description": "..."}``. A capability always advertises a control (a proven mechanism), never an objective.

    Args:
        model_id: ID of the model to declare as a foundation.
        provides: List of advertised-control dicts. ``control_id`` is required per entry; ``capability_label`` and ``description`` describe what the control provides to consumers.
        visibility: Who may delegate to this foundation. "workspace" (default) makes it discoverable to every model in the workspace; "explicit" limits it to models explicitly attached.
    """
    try:
        return await _get_client().declare_foundation(model_id, provides, visibility)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_reliance(server_version: str, model_id: str) -> dict:
    """List a model's cross-model dependency edges, in both directions.

    Read-only; no side effects. Returns ``{model_id, as_consumer: [...], as_provider: [...]}``. Consumer edges are this model's declared delegations / reliances on other models' controls; provider edges are other models relying on this one (its blast radius if its controls change).

    Use this to inspect existing dependencies before creating or deleting edges (``create_reliance`` / ``attach_foundation`` / ``delete_reliance``), or to understand what breaks if this model's controls change.

    Args:
        model_id: ID of the model to inspect.
    """
    try:
        return await _get_client().list_reliance(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def create_reliance(
    server_version: str,
    model_id: str,
    provider_model_id: str,
    provider_control_id: str,
    mode: str,
    source_objective_id: str = "",
    source_control_id: str = "",
) -> dict:
    """Declare a cross-model dependency: this model relies on a provider control.

    Two modes (the target is ALWAYS a provider control — credit terminates at a
    proven mechanism):
    - ``delegated``: this model does NOT implement an objective locally; it is
      handled entirely by the provider's control. Pass ``source_objective_id``.
    - ``relied_upon``: this model has its OWN control whose validity depends on
      the provider's control. Pass ``source_control_id``.

    The provider must be a model in the SAME workspace as the consumer (reliance
    is workspace-scoped and does not reach across workspace boundaries). The edge
    enters ``draft`` and runs LLM semantic validation; it carries no credit until
    confirmed via ``confirm_reliance`` (and only when validation returned
    ``valid``). Returns the created edge.

    Args:
        model_id: the consumer model declaring the dependency.
        provider_model_id: the model whose control satisfies the dependency.
        provider_control_id: the provider's control (the credit terminus).
        mode: "delegated" or "relied_upon".
        source_objective_id: consumer objective id (required for "delegated").
        source_control_id: consumer control id (required for "relied_upon").
    """
    try:
        return await _get_client().create_reliance(
            model_id, provider_model_id, provider_control_id, mode,
            source_objective_id, source_control_id,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def confirm_reliance(
    server_version: str,
    edge_id: str,
    accept_partial_as_relied_upon: bool = False,
) -> dict:
    """Promote a draft reliance edge to active (the credit-soundness gate).

    Refuses unless LLM validation returned ``valid``. A ``partial`` result or a
    mode mismatch is refused (never silently credited). Returns the updated edge.

    Args:
        edge_id: ID of the reliance edge to confirm.
        accept_partial_as_relied_upon: reserved for partial-coverage handling.
    """
    try:
        return await _get_client().confirm_reliance(edge_id, accept_partial_as_relied_upon)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_reliance(server_version: str, edge_id: str) -> dict:
    """Delete a cross-model reliance / delegation edge. Destructive and immediate.

    Mutating: permanently removes the edge. Any credit the consumer model derived from it (a delegated objective or a relied-upon control) is withdrawn, which can move the consumer's coverage/posture. Does not affect either model's own controls. Returns ``{deleted: True, edge_id}``.

    Use ``list_reliance`` to find the edge_id first. To pause an edge without deleting, there is no toggle — deletion is the only removal path.

    Args:
        edge_id: ID of the reliance edge to delete.
    """
    try:
        await _get_client().delete_reliance(edge_id)
        return {"deleted": True, "edge_id": edge_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def propose_attach_foundation(
    server_version: str,
    model_id: str,
    foundation_model_id: str,
) -> dict:
    """Propose which of this model's objectives each foundation capability covers.

    Read-only: returns candidate (objective ↔ provider control) pairs with a
    match score. Nothing is created or credited. Feed the chosen subset to
    ``attach_foundation``.

    Args:
        model_id: the consumer model.
        foundation_model_id: the foundation to delegate to.
    """
    try:
        return await _get_client().propose_attach_foundation(model_id, foundation_model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def attach_foundation(
    server_version: str,
    model_id: str,
    foundation_model_id: str,
    selections: list[dict],
) -> dict:
    """Create draft delegation edges for selected (objective, control) pairs.

    ``selections`` is a list of ``{"source_objective_id": ..., "provider_control_id": ...}``
    (typically the operator-confirmed subset of ``propose_attach_foundation``).
    Each becomes a ``delegated`` draft edge that runs LLM validation; none
    carries credit until separately confirmed. Returns ``{created, failed}``.

    Args:
        model_id: the consumer model.
        foundation_model_id: the foundation to delegate to.
        selections: list of {source_objective_id, provider_control_id} dicts.
    """
    try:
        return await _get_client().attach_foundation(
            model_id, foundation_model_id, selections,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_threat_model(server_version: str, model_id: str) -> dict:
    """Delete a threat model and all associated data. Destructive and permanent — cannot be undone.

    Mutating: removes the model along with every version, its controls, assertions, findings, attestations, and tag/reliance memberships. Reliance edges from other models that pointed at this one are invalidated, which can move those consumers' posture.

    Confirm intent before calling. To keep a copy first, use ``export_report (scope="model", format="archive")`` (a self-contained, re-importable JSON archive). Returns ``{deleted: True, model_id}``.

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
      an entity via ``restore_entity (entity_type="asset")`` / ``restore_entity (entity_type="attacker")``.
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
async def import_threat_model_archive(
    server_version: str,
    envelope: dict,
    workspace_id: str,
) -> dict:
    """Import a JSON audit archive (from ``export_report (scope="model", format="archive")``)
    into a target workspace.

    Mutating: creates a NEW threat model in the target workspace. Requires
    write access to that workspace. A fresh model_id is assigned on every
    import, so the same envelope can be imported any number of times
    without collisions; title collisions in the target workspace
    auto-suffix ``(imported YYYY-MM-DD)``. Non-destructive — never
    overwrites or touches an existing model.

    Use to move or clone a model between workspaces or across instances;
    the envelope round-trips through ``export_report (scope="model", format="archive")``
    first.

    Args:
        envelope: The full archive dict returned by
            ``export_report (scope="model", format="archive")``.
        workspace_id: Target workspace to import into.

    Returns:
        ``{"model_id": "<new id>"}`` — the id of the newly created model.
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
async def get_control_generation_status(
    server_version: str,
    model_id: str,
    ctx: Context,
) -> dict:
    """Poll the async control-generation status for a threat model.

    When ``generate_threat_model`` / ``refine_threat_model`` return a
    ``controls_status`` other than ``complete``, controls are being authored in
    the background — poll this until a terminal state, then read the controls.

    Return shape: ``{status, mode, target_cos, ready_cos, error_message,
    elapsed_seconds}`` (or ``{status: "none"}`` when controls were built inline).
    ``status`` is ``queued | generating | deferred | complete | failed |
    skipped | none``:
    - ``deferred`` — today's background-analysis budget is used up; generation
      resumes automatically at the daily reset (relay this to the user).
    - ``failed`` — ``error_message`` says why (e.g. insufficient credits).
    - ``ready_cos`` / ``target_cos`` — coverage progress.
    - ``elapsed_seconds`` — time since queued; if it stays ``queued`` with a
      large elapsed, generation may not be progressing — surface that instead of
      polling forever.

    Read-only; no side effects (polling does not trigger or alter generation).

    Args:
        model_id: ID of the threat model whose control-generation status to poll.
    """
    try:
        return _dump(
            await _get_client().get_control_generation_status(model_id))
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
    """Regenerate controls from the model's control objectives. Mutating.

    Re-authors controls from the current COs. Controls whose descriptions
    survive regeneration unchanged KEEP their implementation status,
    evidence, notes, assertions, and Jira / compliance mappings. Controls
    whose descriptions change or disappear are soft-deleted (still
    queryable via ``get_controls(include_deleted=True)``). When ``co_ids``
    is given, only those COs' controls are regenerated — all other controls
    are left as-is.

    May run as a background job; this tool waits for completion and returns
    the final result. To rebuild everything, omit ``co_ids``. To fix only
    stale/orphaned CO mappings without re-authoring control text, prefer
    ``remap_control`` (mechanical, no LLM).

    Args:
        model_id: ID of the threat model.
        mode: "batch" (default) or "per_co" (most thorough — one LLM call
            per CO).
        batch_size: COs per batch in batch mode (default 15). Smaller =
            more accurate and more granular progress, but more LLM calls.
        co_ids: Optional comma-separated CO IDs to regenerate (e.g.
            "CO1,CO5"). Omit to regenerate all controls.

    The result includes a ``governor`` object when the workspace bounds
    background-analysis spend; when ``governor.status`` is ``warning`` or
    ``exhausted``, relay it — queued background re-evaluation resumes at
    ``governor.resets_at`` and is never dropped.
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
    """Update the implementation status of a security control. Mutating.

    Sets the control's status to "implemented" or "not_implemented".
    Marking a control "implemented" REQUIRES at least one assertion on the
    control — check its ``assertion_count`` (via ``get_controls``) first and
    submit assertions with ``submit_assertions`` if it is zero, or the call
    is rejected.

    Args:
        model_id: ID of the threat model the control belongs to.
        control_id: ID of the control to update (e.g. "CTRL-01").
        status: New status — "implemented" or "not_implemented".
        implementation_notes: Optional free-text notes recorded with the
            status change.
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
    ctx: Context,
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

    A refinement is rejected when the proposed description would reduce the
    protection the control currently states for an objective it is mapped to;
    ``per_co`` names each objective and explains why. This is a decision, not a
    transient error — re-wording the same narrowing will not pass it, and it
    applies however well-motivated the narrowing is. A control is a requirement
    that must be met to cover its objectives, so evidence that the system does
    not currently meet it means the control is UNMET, never that the control
    should ask for less.

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
        client = _get_client()
        # Runs as a background job (strong-LLM CO sufficiency check); poll it so
        # the work stays off the backend event loop and the transport stays warm.
        started = await client.start_refine_control(
            model_id, control_id,
            description.strip(), justification.strip(),
            codebase_findings=codebase_findings.strip(),
        )
        return await _await_backend_job(client, started["job_id"], ctx)
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
async def apply_control_changeset(
    server_version: str,
    model_id: str,
    ops: str,
    change_reason: str,
) -> dict:
    """Apply a batch of control operations atomically as ONE transaction.

    Use this to reorganize a model's controls in a single step — for example
    to deduplicate controls (remap several onto the right objectives and delete
    the redundant ones at once), instead of many separate calls. All operations
    commit together or not at all.

    Mapping-only: remap/delete/set_groups change objective mappings and retire
    controls but never re-author a control's description, so a kept or reused
    control keeps its status, evidence, and assertions. The orphan guard is
    evaluated on the FINAL state of the batch, so a delete paired with a
    covering remap or add in the same changeset is allowed; a changeset that
    would leave any previously-covered control objective uncovered is rejected
    as a whole and nothing is written.

    Args:
        model_id: ID of the threat model.
        ops: JSON array of operation objects. Each object has an "op" of
            "remap", "delete", "add", or "set_groups":
              - remap:      {"op": "remap", "control_id": "CTRL-03",
                             "co_ids": ["CO1", "CO2"]}
              - delete:     {"op": "delete", "control_id": "CTRL-09",
                             "reason": "duplicate of CTRL-03"}
              - add:        {"op": "add", "description": "...",
                             "co_ids": ["CO5"], "mitigation_group": 1}
              - set_groups: {"op": "set_groups", "co_id": "CO1",
                             "groups": {"1": ["CTRL-03"], "2": ["CTRL-04"]}}
        change_reason: Why this reorganization is appropriate (min 10 chars).
            Recorded on every affected control's version history.
    """
    import json as _json

    try:
        parsed_ops = _json.loads(ops)
    except (ValueError, TypeError) as exc:
        raise ToolError("ops must be a JSON array of operation objects.") from exc
    if not isinstance(parsed_ops, list) or not parsed_ops:
        raise ToolError("ops must be a non-empty JSON array.")
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        return _dump(await _get_client().apply_control_changeset(
            model_id, parsed_ops, change_reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def model_coherence_report(
    server_version: str,
    model_id: str,
    co_id: str = "",
) -> dict:
    """Static-analysis report on coherence between the model's
    component declarations, the code-binding strings on its controls
    and assertions, and the structural reachability of every CO.

    Pass ``co_id`` to scope the report to findings carrying that CO id
    (the ``co_*`` reachability findings + the attestation cross-link
    findings). Component- and assertion-level findings without a CO
    binding are excluded in single-CO mode. 404 if the CO doesn't
    exist on the model.

    The report carries up to twelve finding types, grouped below by
    concern. Each finding includes the entity IDs it concerns
    (``co_id``, ``asset_id``, ``attacker_id``, ``component_id``, etc.)
    so the agent can dispatch the resolution tool directly without
    re-fetching the model.

    Component / assertion bindings:
    - ``control_component_unknown`` — control references a component
      ID that no longer exists. Resolve: ``assign_to_components (target_type="control")``.
    - ``asset_component_unknown`` — asset references a missing
      component. Resolve: ``edit_asset`` (with corrected
      ``component_ids``).
    - ``assertion_repo_mismatch`` — an assertion's ``repo`` does not
      match the ``repo_url`` of any component scoping its control.
      Resolve: rebind the assertion or rescope the control.
    - ``assertion_repo_orphan`` — an assertion has a ``repo`` but its
      control is unscoped. Resolve: ``assign_to_components (target_type="control")``
      to scope the control, or correct the assertion's repo.
    - ``control_unscoped_with_scoped_assertions`` — control is
      unscoped, but its assertions all carry a single component's
      ``repo``. Resolve: ``assign_to_components (target_type="control")`` to that
      component.
    - ``component_unbound`` — a component has no ``repo_url``. Two
      cases, told apart by the component's trust boundary. An
      internal-zone component (your own code) that isn't linked yet:
      resolve with ``edit_component`` pointing at the real repo. An
      external-zone component (e.g. a third-party service, the
      customer's IdP, or other external infrastructure you call but
      don't own): leave it
      unbound — the finding is a permanent, auditor-visible external-
      dependency marker, NOT a TODO. Never bind an external component
      to your repo to silence this; "some client code touches it" is
      not a reason to bind (that client code lives in your repo for
      every dependency).

    Reachability findings (deterministic composer; indeterminate
    verdicts surface as findings, never auto-decided by an LLM):
    - ``co_attacker_unpositioned`` — the CO's attacker has no
      positioned trust boundaries. Resolve by REPAIRING THE MODEL:
      ``edit_attacker`` (set ``trust_boundary_ids``).
    - ``co_asset_unbounded`` — the CO's asset has no component-derived
      trust boundaries. Resolve by REPAIRING THE MODEL:
      ``assign_to_components (target_type="asset")`` or ``edit_asset``
      (with ``component_ids``).
    - ``co_no_shared_boundary`` — attacker and asset boundaries do
      not intersect. Resolve by REPAIRING THE MODEL: re-position the
      attacker via ``edit_attacker``, or scope the asset to a shared
      component via ``assign_to_components (target_type="asset")``.

      An indeterminate verdict means the derivation could not decide, so the
      first move is to supply the structure it is missing. It does NOT mean
      the objective is inapplicable, and asserting that it is would answer a
      structural question with a judgment.

      ``co_no_shared_boundary`` can also fire where the connecting structure
      genuinely does not exist rather than merely going unstated, so supplying
      it is the first thing to try, not a guaranteed resolution. If the
      boundaries really do not meet, that is still a modelling answer.

      If the objective genuinely does not apply to this system, that is a
      separate claim: record it with ``create_co_disposition``, which keeps
      the objective visible, owned and expiring rather than hiding it.
    - ``co_missing_entity`` — the CO references a missing
      asset/attacker; model state inconsistent. Resolve: restore
      the entity (``restore_entity (entity_type="asset")`` / ``restore_entity (entity_type="attacker")``) or
      remove the orphaned CO via ``refine_threat_model``.

    Use this before relying on component-scoped control discovery,
    when assertion verification fails for path/repo reasons, or to
    enumerate structural-completeness gaps the operator should
    address before treating the model as audit-ready. ``get_reachability_verdicts``
    exposes the underlying composer verdicts directly when the
    finding-shape summary isn't enough.

    Args:
        model_id: ID of the threat model.
        co_id: Optional CO id to scope the report to a single CO.
    """
    try:
        return _dump(
            await _get_client().model_coherence_report(model_id, co_id=co_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


# === Composition (recursive-tree effective model) ===
#
# Read-only views over the *effective* model — own entities composed with
# everything inherited from ancestor threat models on the recursive tree.
# When composition is not available for the deployment, every tool below
# returns its stable empty shape with ``flag_enabled: false`` so agents can
# detect the disabled state without separate code paths or 404 handling.


@mcp.tool()
async def get_composition_overview(
    server_version: str,
    model_id: str,
) -> dict:
    """Composition index for a model — counts, tree metadata, warnings.

    Read-only; no side effects. Cheapest call in the composition surface
    (~1-2KB). Use it first to learn whether composition is available for
    this model, where the model sits on the recursive tree (parent +
    ancestor chain + child ids), how many own vs inherited entities and
    COs there are per kind, and whether any structural warnings (cycle,
    parent missing, max depth exceeded) need surfacing before drilling
    into sub-resources.

    Return shape::

        {
          model_id, model_version, flag_enabled,
          tree: {parent_id, ancestor_chain, depth, child_ids},
          counts: {
            entities: {kind: {own, inherited}, ...},
            control_objectives: {total, live, covered, uncovered,
              indeterminate, by_origin: {own, cross, inherited}},
            reconciliation_candidates: {certain, heuristic},
          },
          warnings: [str, ...],
        }

    When composition is not available on the backend, the same shape is
    returned with all counts zeroed and ``flag_enabled: false`` — detect
    that rather than handling an error.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().composition_index(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_effective_entities(
    server_version: str,
    model_id: str,
    page: int = 1,
    page_size: int = 100,
    kind: str | None = None,
) -> dict:
    """Effective entity set (own ⊕ inherited) keyed by kind.

    Returns the entity set this model sees after composition with
    ancestors: trust boundaries, components, assets, attackers, and
    (when applicable) attack paths. Each entry carries its provenance —
    whether it originates on this model or is inherited from an
    ancestor — plus a fully-qualified id so cross-model references are
    unambiguous.

    Pair with ``list_effective_control_objectives`` and
    ``get_effective_coverage`` to see how inherited topology contributes
    to coverage credit.

    Return shape::

        {
          model_id, flag_enabled,
          kinds: {
            trust_boundaries: [{kind, qualified_id, owner_model_id,
              owner_title, origin, entity}, ...],
            components: [...], assets: [...], attackers: [...], ...
          },
          total, page, page_size,
        }

    When composition is disabled on the backend, ``kinds`` is returned
    with every kind mapped to an empty list and ``flag_enabled: false``.

    Omitting ``page`` / ``page_size`` defaults to ``page=1,
    page_size=100`` — the response is paginated and no longer returns
    every entity in a single call.

    Args:
        model_id: ID of the threat model.
        page: 1-indexed page number (default ``1``).
        page_size: entries per page (default ``100``).
        kind: optional single entity kind to restrict the response to
            (e.g. ``"attackers"``, ``"assets"``, ``"components"``,
            ``"trust_boundaries"``). When omitted, all kinds are
            returned.
    """
    try:
        return _dump(
            await _get_client().composition_entities(
                model_id,
                page=page,
                page_size=page_size,
                kind=kind,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_effective_control_objectives(
    server_version: str,
    model_id: str,
) -> dict:
    """Effective control objectives with origin classification.

    Returns every CO visible on the effective model, each tagged with
    its origin: ``own`` (authored on this model), ``cross`` (an inherited
    CO whose asset or attacker is local to this model), or ``inherited``
    (purely inherited from an ancestor). Use this to see what control
    objectives the model is on the hook for — including those it
    inherits — before reading coverage or reach.

    Return shape::

        {
          model_id, flag_enabled,
          control_objectives: [
            {co_qid, asset_qid, attacker_qid,
             security_properties: ["C"|"I"|"A"|"U", ...],
             origin: "own"|"cross"|"inherited"},
            ...
          ],
        }

    When composition is disabled on the backend, returns an empty list
    and ``flag_enabled: false``.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(
            await _get_client().composition_control_objectives(model_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_effective_coverage(
    server_version: str,
    model_id: str,
    page: int = 1,
    page_size: int = 100,
    origin: str | None = None,
) -> dict:
    """Effective coverage rollup with credited inheritance.

    Read-only. Per effective CO: whether it is covered, how much credit
    comes from controls owned by this model vs inherited from ancestors,
    and the list of contributing controls (with the owning model id,
    origin tag, verification status, and mitigation group). This is the
    surface that drives the composition view's coverage / compliance
    numbers — it reflects composed (own ⊕ inherited) math, NOT the
    per-model coverage shown by ``get_verification_report``.

    Return shape::

        {
          model_id, flag_enabled,
          coverage: [
            {co_qid, is_covered, own_credit, inherited_credit,
             contributing_controls: [{control_id, owner_model_id,
               origin, is_verified, mitigation_group}, ...]},
            ...
          ],
          total, page, page_size,
        }

    When composition is not available on the backend, ``coverage`` is
    empty and ``flag_enabled: false``.

    Paginated: omitting ``page`` / ``page_size`` defaults to ``page=1,
    page_size=100`` — a single call no longer returns every coverage row.

    Args:
        model_id: ID of the threat model.
        page: 1-indexed page number (default ``1``).
        page_size: coverage rows per page (default ``100``).
        origin: filter coverage rows by contributing-control origin — one
            of ``"own" | "cross" | "inherited"``. When omitted, rows with
            any origin mix are returned.
    """
    try:
        return _dump(
            await _get_client().composition_coverage(
                model_id,
                page=page,
                page_size=page_size,
                origin=origin,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_effective_attack_paths(
    server_version: str,
    model_id: str,
) -> dict:
    """Effective AttackPath set + lifted missing/dangling suggestions.

    AttackPaths inherit from ancestors with the same own / inherited
    provenance as other entities. The ``suggestions`` block is the
    missing-path / dangling-path delta computed against the *composed*
    effective topology — a child sees the inherited baseline claims, the
    composed reach surface, and the delta against both.

    Return shape::

        {
          model_id, flag_enabled,
          effective_paths: [{kind, qualified_id, owner_model_id,
            owner_title, origin, entity}, ...],
          lattice_positions: int,
          authored_paths: int,
          suggestions: {missing_path: [...], dangling_path: [...]},
        }

    When composition is disabled on the backend, ``effective_paths`` is
    empty, the counts are zero, ``suggestions`` is empty, and
    ``flag_enabled: false``.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().composition_attack_paths(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


_RECONCILIATION_KINDS = {"assets", "attackers", "components"}


@mcp.tool()
async def apply_certain_reconciliation_match(
    server_version: str,
    model_id: str,
    kind: str,
    own_qid: str,
    inherited_qid: str,
    confirm_heuristic: bool = False,
) -> dict:
    """Apply a certain-tier reconciliation candidate. Mutates state.

    Soft-deletes the descendant's own duplicate entity; the inherited
    entity becomes the canonical surface for the effective-model
    resolver. Use after surveying candidates via
    ``list_reconciliation_candidates``. Certain-tier candidates apply
    directly; heuristic-tier candidates need operator review of the
    structural divergence and are refused server-side unless
    ``confirm_heuristic=True`` is passed to acknowledge the divergence.

    The server re-validates the candidate against current live state
    before applying; if the model has moved since the candidate was
    detected, returns 400 and the operator should refresh the candidate
    list and retry. Bumps model version and emits an activity event on
    success.

    Args:
        model_id: ID of the descendant threat model the duplicate is on.
        kind: Entity kind — one of ``"assets"``, ``"attackers"``,
            ``"components"``.
        own_qid: Qualified id of the descendant's own duplicate (e.g.
            ``"child:A1"``).
        inherited_qid: Qualified id of the canonical entity on the
            ancestor (e.g. ``"parent:A1"``).
        confirm_heuristic: Acknowledge and apply a heuristic-tier
            candidate despite its structural divergence. Default False
            — heuristic-tier matches are refused server-side without
            this flag. Leave False for certain-tier candidates.

    Returns the post-mutation model envelope::

        {"model": <ThreatModel>,
         "controls_carried": int,
         "controls_orphaned": int,
         "orphaned_control_ids": [str, ...]}

    Errors: 400 on stale candidates, or heuristic-tier candidates without
    ``confirm_heuristic``; 404 if the model isn't found; 503 if
    composition is not available on the backend.
    """
    if kind not in _RECONCILIATION_KINDS:
        raise ToolError(
            "kind must be one of 'assets', 'attackers', 'components'.",
        )
    if not own_qid or not own_qid.strip():
        raise ToolError("own_qid is required and must be non-empty.")
    if not inherited_qid or not inherited_qid.strip():
        raise ToolError("inherited_qid is required and must be non-empty.")
    if ":" not in own_qid:
        raise ToolError(
            "own_qid must be a qualified id of the form '<owner>:<local_id>'.",
        )
    if ":" not in inherited_qid:
        raise ToolError(
            "inherited_qid must be a qualified id of the form "
            "'<owner>:<local_id>'.",
        )
    try:
        return _dump(
            await _get_client().apply_certain_reconciliation_match(
                model_id, kind, own_qid, inherited_qid,
                confirm_heuristic=confirm_heuristic,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def reject_reconciliation_candidate(
    server_version: str,
    model_id: str,
    kind: str,
    own_qid: str,
    inherited_qid: str,
) -> dict:
    """Reject a reconciliation candidate. Mutates state.

    Records the operator's "these are NOT duplicates" decision at org
    scope so the candidate detector filters this pair out of the active
    queue on subsequent reads. Idempotent on the natural key
    ``(model_id, kind, own_qid, inherited_qid)`` — re-rejecting an existing
    pair returns the same row. Use when ``list_reconciliation_candidates``
    surfaces a pair that looks like a duplicate but the operator has
    confirmed it is not.

    Persistence is at org scope, not model state — the rejection is durable
    across sessions and teammates but does NOT bump model version.

    Args:
        model_id: ID of the descendant threat model.
        kind: Entity kind — one of ``"assets"``, ``"attackers"``,
            ``"components"``.
        own_qid: Qualified id of the descendant's own entity (e.g.
            ``"child:A1"``).
        inherited_qid: Qualified id of the ancestor's entity (e.g.
            ``"parent:A1"``).

    Returns the persisted record::

        {"id": str, "model_id": str, "kind": str, "own_qid": str,
         "inherited_qid": str, "rejected_by": str,
         "rejected_at": <ISO-8601>}

    Use the ``id`` field with ``unreject_reconciliation_candidate`` if the
    operator changes their mind.

    Errors: 404 if the model isn't found; 503 if composition is not
    available on the backend, or the rejection store is not configured.
    """
    if kind not in _RECONCILIATION_KINDS:
        raise ToolError(
            "kind must be one of 'assets', 'attackers', 'components'.",
        )
    if not own_qid or not own_qid.strip():
        raise ToolError("own_qid is required and must be non-empty.")
    if not inherited_qid or not inherited_qid.strip():
        raise ToolError("inherited_qid is required and must be non-empty.")
    if ":" not in own_qid:
        raise ToolError(
            "own_qid must be a qualified id of the form '<owner>:<local_id>'.",
        )
    if ":" not in inherited_qid:
        raise ToolError(
            "inherited_qid must be a qualified id of the form "
            "'<owner>:<local_id>'.",
        )
    try:
        return _dump(
            await _get_client().reject_reconciliation_candidate(
                model_id, kind, own_qid, inherited_qid,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def unreject_reconciliation_candidate(
    server_version: str,
    model_id: str,
    rejection_id: str,
) -> dict:
    """Remove a persisted reconciliation rejection. Mutates state.

    The pair becomes eligible to surface in the active candidate queue
    again on the next read of ``list_reconciliation_candidates``. Use when
    the operator changes their mind about a prior rejection — the surrogate
    ``rejection_id`` comes from ``rejections[*].id`` on
    ``list_reconciliation_candidates (disposition="rejected")`` (or the return value of
    ``reject_reconciliation_candidate``).

    Does NOT bump model version (rejection is org state, not model state).

    Args:
        model_id: ID of the descendant threat model the rejection is on.
        rejection_id: Surrogate id of the persisted rejection.

    Returns ``{"ok": True}`` on success.

    Errors: 404 if no rejection with that id exists on the model; 503 if
    composition is not available on the backend, or the rejection store is
    not configured.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not rejection_id or not rejection_id.strip():
        raise ToolError("rejection_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().unreject_reconciliation_candidate(
                model_id, rejection_id,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def lift_composition_entity(
    server_version: str,
    model_id: str,
    kind: str,
    local_id_a: str,
    local_id_b: str,
    descendant_a_id: str,
    descendant_b_id: str,
    lca_model_id: str,
    lca_descendant_ids: Optional[List[str]] = None,
    acknowledged_third_party_subtrees: Optional[List[str]] = None,
    field_resolutions: Optional[Dict[str, str]] = None,
    attached_state_resolutions: Optional[Dict[str, str]] = None,
    skip_overapplication_gate: bool = False,
) -> dict:
    """Promote a shared-anchor entity from two sibling descendants to their
    lowest common ancestor. Mutates state across THREE models.

    The operator has confirmed (via the composition lift-candidate view)
    that the entity ``local_id_a`` on ``descendant_a_id`` and the entity
    ``local_id_b`` on ``descendant_b_id`` are the same logical thing and
    should be modeled once on the LCA. The route's ``model_id`` is the
    operator's current context model — typically the LCA, but the server
    accepts any ancestor of both descendants.

    Conflict resolution. The server re-detects field-level and
    attached-state conflicts against current live state before applying.
    If new conflicts have surfaced since the operator's last candidate
    fetch, the call returns 400 with the missing conflict keys; refresh
    the lift-candidate view and resubmit with resolutions covering every
    key. Each entry in ``field_resolutions`` / ``attached_state_resolutions``
    is ``"keep_a"`` | ``"keep_b"`` | ``"keep_both"`` (union for list/set
    fields; falls back to B for scalars).

    Over-application gate. The lift extends visibility to every descendant
    of the LCA, not just the two source descendants. The server runs an
    over-application gate that refuses lifts touching descendants outside
    an acknowledged set; pass ``acknowledged_third_party_subtrees`` to
    acknowledge specific subtrees, or ``skip_overapplication_gate=True`` to
    override entirely after explicit operator confirmation.

    Each affected model (LCA + both descendants) bumps version and emits a
    ``model_refined`` activity event; a structured ``lift_applied`` event
    with the full ``lift_event`` payload lands on the LCA. The audit pack
    surfaces this under ``lift_history``. Reverse it with
    ``undo_composition_event (event_type="lift")`` (preview first via
    ``preview_undo_composition (event_type="lift")``); the inverse operation is
    ``split_composition_entity``.

    Args:
        model_id: Operator's context model — the model whose composition
            view surfaced the candidate. Treated as a route anchor only;
            doesn't have to be the LCA.
        kind: Entity kind — one of ``"assets"``, ``"attackers"``,
            ``"components"``.
        local_id_a: Local id of the entity on ``descendant_a_id``.
        local_id_b: Local id of the entity on ``descendant_b_id``.
        descendant_a_id: First source descendant model id.
        descendant_b_id: Second source descendant model id.
        lca_model_id: Target ancestor model id (the LCA, or any ancestor
            higher up the chain).
        lca_descendant_ids: Optional snapshot of the LCA's descendant set
            used by the over-application gate. Omit to let the server
            compute it via BFS.
        acknowledged_third_party_subtrees: Optional list of subtree roots
            the operator has acknowledged as in-scope for the lift.
        field_resolutions: Optional per-field resolution map (e.g.
            ``{"description": "keep_both", "tags": "keep_a"}``).
        attached_state_resolutions: Optional per-state-key resolution map
            (e.g. ``{"state:assertions/AS3": "keep_b"}``).
        skip_overapplication_gate: When True, bypass the gate after
            explicit operator confirmation. Default False.

    Returns::

        {"lift_id": str,
         "lca_model": <ThreatModel>,
         "descendant_a_model": <ThreatModel>,
         "descendant_b_model": <ThreatModel>,
         "applied_migrations": [...],
         "lift_event": {...}}

    Errors: 400 if required fields are missing, no LCA exists, conflict
    resolutions are stale, or the lift is structurally refused
    (eligibility / over-application gate); 404 if the route model or
    either source descendant is missing; 503 if composition is not
    available on the backend.
    """
    if kind not in _RECONCILIATION_KINDS:
        raise ToolError(
            "kind must be one of 'assets', 'attackers', 'components'.",
        )
    if not local_id_a or not local_id_a.strip():
        raise ToolError("local_id_a is required and must be non-empty.")
    if not local_id_b or not local_id_b.strip():
        raise ToolError("local_id_b is required and must be non-empty.")
    if not descendant_a_id or not descendant_a_id.strip():
        raise ToolError("descendant_a_id is required and must be non-empty.")
    if not descendant_b_id or not descendant_b_id.strip():
        raise ToolError("descendant_b_id is required and must be non-empty.")
    if not lca_model_id or not lca_model_id.strip():
        raise ToolError("lca_model_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().lift_composition_entity(
                model_id,
                kind,
                local_id_a,
                local_id_b,
                descendant_a_id,
                descendant_b_id,
                lca_model_id,
                lca_descendant_ids=lca_descendant_ids,
                acknowledged_third_party_subtrees=acknowledged_third_party_subtrees,
                field_resolutions=field_resolutions,
                attached_state_resolutions=attached_state_resolutions,
                skip_overapplication_gate=skip_overapplication_gate,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def split_composition_entity(
    server_version: str,
    model_id: str,
    kind: str,
    ancestor_local_id: str,
    target_descendants: List[str],
) -> dict:
    """Push an ancestor-owned entity down to one or more descendants and
    soft-delete the ancestor's copy. Mutates state across the ancestor +
    every target descendant.

    Inverse of ``lift_composition_entity``. Use when an entity that
    currently lives on an ancestor is in fact descendant-specific and
    should be modeled separately per descendant — the operator chooses
    which descendants take a copy. A new local id is minted on each
    target; attached state on the ancestor's entity (assertions, jira
    mappings, risk acceptances, etc.) is duplicated to every target.

    The route's ``model_id`` IS the ancestor (the entity being split lives
    on it). Each affected model (ancestor + every target descendant) bumps
    version and emits a ``model_refined`` activity event; a structured
    ``split_applied`` event with the full ``split_event`` payload lands on
    the ancestor. The audit pack surfaces this under ``split_history``.

    Args:
        model_id: Ancestor model id — the entity to split lives here.
        kind: Entity kind — one of ``"assets"``, ``"attackers"``,
            ``"components"``.
        ancestor_local_id: Local id of the entity on the ancestor.
        target_descendants: Non-empty list of descendant model ids that
            should each take a copy.

    Returns::

        {"split_id": str,
         "ancestor_model": <ThreatModel>,
         "descendant_models": [<ThreatModel>, ...],
         "applied_duplications": [...],
         "split_event": {...}}

    Errors: 400 if required fields are missing or the split is
    structurally refused; 404 if the ancestor or any target descendant is
    missing; 503 if composition is not available on the backend.
    """
    if kind not in _RECONCILIATION_KINDS:
        raise ToolError(
            "kind must be one of 'assets', 'attackers', 'components'.",
        )
    if not ancestor_local_id or not ancestor_local_id.strip():
        raise ToolError("ancestor_local_id is required and must be non-empty.")
    if not target_descendants:
        raise ToolError(
            "target_descendants is required and must be a non-empty list.",
        )
    try:
        return _dump(
            await _get_client().split_composition_entity(
                model_id,
                kind,
                ancestor_local_id,
                target_descendants,
            ),
        )
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
    ctx: Context,
    defense_in_depth: str = "",
    justification: str = "",
) -> dict:
    """Declaratively set the mitigation-group structure for a control objective. Mutating; runs as a polled background job (an LLM sufficiency check evaluates whether the new structure satisfies the CO) and returns once complete.

    Replaces ALL mitigation-group assignments for this CO. Call
    ``get_mitigation_groups`` first to see the current structure and the
    unmapped controls available for assignment.

    Mitigation groups define alternative paths to satisfy a CO:
    - Within a group: AND — all controls must be implemented.
    - Across groups: OR — any one complete group mitigates the CO.
    - Defense-in-depth: tracked but not required for mitigation.

    Args:
        model_id: ID of the threat model.
        co_id: ID of the control objective (e.g., "CO5").
        groups: JSON object mapping group numbers to control-ID lists.
            Example: '{"1": ["CTRL-01", "CTRL-02"], "2": ["CTRL-03"]}'.
        defense_in_depth: Comma-separated control IDs tracked as
            defense-in-depth (not required for mitigation). Example:
            "CTRL-04,CTRL-05".
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
        client = _get_client()
        # Runs as a background job (strong-LLM CO sufficiency check); poll it so
        # the work stays off the backend event loop and the transport stays warm.
        started = await client.start_set_mitigation_groups(
            model_id, co_id, parsed_groups, did_list, justification.strip(),
        )
        return await _await_backend_job(client, started["job_id"], ctx)
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
    """Attach an auxiliary evidence item (doc, link, or artifact reference) to a control. Mutating.

    Evidence is contextual metadata only — it does NOT count toward a
    control's implementation status; only assertions prove controls.
    Use ``remove_evidence`` to detach an item.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        type: Evidence type — one of "code", "test", "config",
            "document", "link" (default "code").
        label: Human-readable description of the evidence (required).
        url: Optional file path or URL pointing at the artifact.
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
    """Remove one evidence item from a control by its position in the control's evidence array. Mutating.

    Evidence is auxiliary metadata (see ``add_evidence``); removing it
    does not affect the control's implementation status or any
    assertions. To find the index, read the control via ``get_controls (control_id=...)``
    and count its ``evidence`` array from 0.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        evidence_index: Zero-based position of the item to remove within
            the control's ``evidence`` array (default 0 = first item).
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

    Accepts structured JSON or free-text. Controls are auto-mapped to COs and
    deduplicated against existing ones. The parse/map/dedup runs as a background
    job (polled for progress), then — because this mutates the model — you are
    asked to confirm before the controls are saved.

    Args:
        model_id: ID of the threat model.
        controls_json: JSON array of {description, co_ids?, framework_refs?}.
        free_text: Free-text controls (narrative/CSV/bullets).
        source_label: Origin label (e.g., "ISO 27001").
        auto_map: Auto-map controls to COs using LLM (default: True).

    The confirm result includes a ``governor`` object when the workspace bounds
    background analysis spend; when ``governor.status`` is ``warning`` or
    ``exhausted``, relay it — queued background re-evaluation resumes at
    ``governor.resets_at`` and is never dropped.
    """
    try:
        client = _get_client()
        # 1. Preview as a background job: parse / auto-map / dedup runs off the
        #    backend event loop; polling keeps the transport warm.
        started = await client.start_import_preview(
            model_id, controls_json, free_text, source_label, auto_map,
        )
        preview = await _await_backend_job(client, started["job_id"], ctx)
        controls = client.build_import_controls(preview)
        if not controls:
            return {
                "imported": 0,
                "controls": [],
                "message": "Nothing to import: no controls were parsed, or all "
                           "matched controls already in the model.",
            }

        # 2. Confirm with the user (terminal elicitation) before mutating.
        dup_count = len(preview.get("duplicates") or [])
        if not await _confirm_import(ctx, controls, dup_count):
            return {
                "imported": 0,
                "controls": [],
                "message": f"Import cancelled — {len(controls)} control(s) were "
                           "not saved.",
            }

        # 3. Persist (fast, stateless confirm).
        result = await client.import_confirm(
            model_id, controls, source_label or preview.get("source_label", ""),
        )
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_control(
    server_version: str,
    model_id: str,
    control_id: str,
    reason: str = "",
) -> dict:
    """Soft-delete a security control, optionally with a justification. Destructive (mutating): the control is retired, not permanently erased.

    Blocks with HTTP 409 when the control is the ONLY control covering
    any control objective — removing it would leave that CO uncovered.
    Add a replacement control (or refine the threat model) before
    deleting.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to delete.
        reason: Optional justification recorded in the audit trail
            (recommended).
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
    """Analyze control coverage and surface control objectives that lack sufficient controls. Read-only (does not mutate the model); runs as a polled background job and uses LLM reasoning.

    Complements the deterministic ``assess_model`` (which scores each
    CO's mitigated / at_risk / unassessed status from control
    implementation state) by reasoning about which COs are under-covered
    and where new controls are needed. Use this to decide what controls
    to add; use ``assess_model`` to score the current state.

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
async def assess_model(
    server_version: str,
    model_id: str,
    summary_only: bool = False,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Run the deterministic assurance assessment over a threat model. Read-only — no LLM calls, no mutation.

    Evaluates each control objective from its controls' implementation
    status and returns summary counts (mitigated / at_risk /
    unassessed) plus progressive metrics (defined / implemented /
    verified). For LLM-based reasoning about *which* COs are
    under-covered and what controls to add, use ``check_control_gaps``
    instead.

    Use summary_only=True to get just the counts without per-CO
    assessments.

    Args:
        model_id: ID of the threat model to assess.
        summary_only: If True, return only summary counts (no per-CO details).
        status: Optional filter — "mitigated", "at_risk", or "unassessed".
        offset: Skip the first N control objectives.
        limit: Max control objectives to return (0 = all).
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
    ctx: Context,
    description: str = "",
    security_properties: Optional[str] = None,
    notes: str = "",
    component_ids: Optional[str] = None,
) -> dict:
    """Add a new asset to a threat model. Creates a new version.

    **Authoring contract**: name the *data or resource being
    protected* and the security property at stake (Confidentiality /
    Integrity / Availability / Usage) — not a mechanism, control, or
    capability. Name the thing whose exposure or corruption is the
    harm (e.g. "per-organization key-wrapping material", not "KMS
    encryption"). An asset phrased as a mechanism is flagged with a
    ``quality_warning`` and the control objectives derived from it may
    be under-specified.

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
        client = _get_client()
        started = await client.start_add_asset(model_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_asset(
    server_version: str,
    model_id: str,
    asset_id: str,
    ctx: Context,
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

    When changing identity fields, hold to the asset authoring
    contract: name the *data/resource protected* and its security
    property, not a mechanism — otherwise the result is flagged with a
    ``quality_warning`` (see ``add_asset``).

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

    Editing a soft-deleted asset is rejected — ``restore_entity (entity_type="asset")``
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
        client = _get_client()
        started = await client.start_edit_asset(model_id, asset_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
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
    ctx: Context,
    position: str = "",
    archetype: str = "",
    trust_boundary_ids: Optional[str] = None,
) -> dict:
    """Add a new attacker to a threat model. Creates a new version.

    **Authoring contract**: ``capability`` names the *operations the
    attacker can perform from its position* and what they achieve —
    not just the access or vantage point. Phrase it as "From
    [position], the attacker can [concrete operations] …" (e.g. "From
    the network path between the API server and the database, the
    attacker can read and alter requests and responses to exfiltrate
    data in transit or inject forged responses"). A capability that
    states only access is flagged with a ``quality_warning`` and the
    control objectives derived from it may be under-specified.

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
        client = _get_client()
        started = await client.start_add_attacker(model_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_attacker(
    server_version: str,
    model_id: str,
    attacker_id: str,
    ctx: Context,
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
    attest_position: Optional[bool] = None,
    change_reason: Optional[str] = None,
) -> dict:
    """Edit an existing attacker. Only provided fields changed.

    When changing identity fields, hold to the attacker authoring
    contract: ``capability`` names the *operations performable from
    the position* ("From [position], the attacker can [operations] …"),
    not just access — otherwise the result is flagged with a
    ``quality_warning`` (see ``add_attacker``).

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
        trust_boundary_ids: Comma-separated trust boundary IDs — the boundaries
            this attacker has crossed (its position). Replaces the existing set.
            Changing it operator-attests the position, which lets reachability
            trust it for a decisive verdict.
        attest_position: Operator-attest the attacker's current position without
            changing it — e.g. to confirm a fully external attacker's empty
            crossed set so an objective blocked on an unpositioned attacker can
            be resolved. Pass ``true`` to attest.
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
    if attest_position is not None:
        body["attest_position"] = attest_position
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
        client = _get_client()
        started = await client.start_edit_attacker(model_id, attacker_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def reevaluate_threat_model_factors(
    server_version: str,
    model_id: str,
    ctx: Context,
    change_reason: Optional[str] = None,
) -> dict:
    """Re-run the LLM factor judgment on every asset and attacker in
    a threat model. Useful for re-baselining factors after a bug fix
    or feature-description change, without regenerating the whole
    model (which would destroy controls, assertions, components).

    Each entity's factors and rationale are replaced with a fresh
    LLM-judged decomposition; the composed impact / likelihood is
    re-derived deterministically from the new factors. Each re-rating
    is recorded as a rating revision in the audit trail with
    ``change_reason`` (default: "LLM factor re-evaluation") so the
    starting-point regeneration is distinguishable from operator-
    supplied factor overrides via ``edit_asset`` / ``edit_attacker``.

    The platform's LLM factor judgment is a *starting point*. For
    deployment-specific factor adjustments (e.g., elevated
    regulatory_scope because your tenant is HIPAA-covered, or
    Commodity prevalence because your endpoint is public-internet
    exposed), use ``edit_asset`` / ``edit_attacker`` afterward with a
    ``change_reason`` documenting the operator override.

    Per-entity soft-fail: an LLM failure on one entity is recorded in
    the response's ``failed_entities`` list (with ``id``, ``kind``, and
    ``reason``); the remaining entities are still re-evaluated and
    their rating revisions persisted as they complete. The endpoint
    returns 503 only when *every* live entity failed — in which case
    nothing was persisted; retry when the evaluator is reachable.

    Soft-deleted assets and attackers are skipped.

    Args:
        model_id: ID of the threat model to re-rate.
        change_reason: Optional override of the audit-trail reason
            (default: "LLM factor re-evaluation"). Use this to thread
            a higher-level reason like "Re-eval after refinement bug
            fix shipped in vN.N.N" when running the tool as part of a
            broader workflow.

    Returns:
        Dict with:
        - model_id
        - assets_reevaluated: count of assets re-rated successfully
        - attackers_reevaluated: count of attackers re-rated
          successfully
        - deltas.assets / deltas.attackers: per-entity before/after
          factor values and composed rating (only successful entities)
        - failed_entities: list of ``{"id", "kind", "reason"}`` entries
          for per-entity LLM failures; ``[]`` on the happy path
    """
    try:
        client = _get_client()
        # Runs as a background job (scales with entity count); poll it so the
        # work stays off the backend event loop and the transport stays warm.
        started = await client.start_reevaluate_factors(
            model_id, change_reason=change_reason,
        )
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_verdict_divergence(
    server_version: str,
    model_id: str,
    kind: str = "",
    include_dismissed: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Where the LLM's verdicts disagree with the model's authored state.

    Two coverage divergence kinds, distinguished by the LLM's ``p_covers``
    (probability the control covers the CO), shown as "model confidence":
      - ``missing_mapping``: HIGH p_covers, but the CO is NOT mapped — the LLM
        is confident the control covers it, so it should be mapped. Accepting
        ADDS the mapping.
      - ``spurious_mapping``: LOW p_covers, but the CO IS mapped — the LLM is
        confident the control does NOT cover it, so the mapping is likely wrong
        and inflates apparent coverage. Accepting REMOVES the mapping.
    Only confident rows surface; the uncertain middle band is dropped. So a
    ~100%-confidence row is a strong "add" and a ~0%-confidence row is a strong
    "remove" — both are actionable, in opposite directions.

    Rows are sorted by confidence, so the strongest calls come first. Each
    section is paginated: its ``pagination.filtered_total`` reports the full
    count, so when it exceeds the rows returned, raise ``limit`` (up to 500) or
    page with ``offset`` to review every divergence — not only the first page.

    Also returns ``group_sufficiency`` divergences (observation-only). Apply
    coverage rows with ``accept_coverage_divergences``; set aside rows the
    structural model got right with ``dismiss_verdict_divergences``.

    Args:
        model_id: ID of the threat model.
        kind: Optional filter — "missing_mapping", "spurious_mapping", or
            "group_sufficiency". Empty returns all kinds.
        include_dismissed: When true, return ONLY previously-dismissed rows
            (the undo view) instead of the active list.
        limit: Max rows per section (clamped to 1-500, default 100). Set to
            500 to pull an entire section in one call.
        offset: Skip the first N rows of each section, for pagination.
    """
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    try:
        return _dump(await _get_client().get_verdict_divergence(
            model_id, kind=(kind.strip() or None),
            include_dismissed=include_dismissed,
            limit=limit, offset=offset,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def accept_coverage_divergences(
    server_version: str,
    model_id: str,
    items: str,
    change_reason: str,
) -> dict:
    """Accept a set of coverage divergences as mapping changes, in one batch.

    Each accepted ``missing_mapping`` ADDS its CO to the control; each
    ``spurious_mapping`` REMOVES it. Applied as one version per affected
    control. Each item is validated independently — the response separates
    ``applied`` from ``skipped`` (stale / would-orphan / already in that
    state), so a partial batch still lands its valid items.

    Read the rows first with ``get_verdict_divergence``; to accept only the
    high-confidence ones, filter its coverage rows by ``p_covers`` (near 1.0
    for missing_mapping, near 0.0 for spurious_mapping) before passing them
    here.

    Args:
        model_id: ID of the threat model.
        items: JSON array of {"control_id", "co_id", "kind"} objects, where
            kind is "missing_mapping" or "spurious_mapping".
        change_reason: Why these mapping changes are appropriate (min 10
            chars). Recorded on every affected control's version history.
    """
    import json as _json

    try:
        parsed = _json.loads(items)
    except (ValueError, TypeError) as exc:
        raise ToolError("items must be a JSON array of divergence objects.") from exc
    if not isinstance(parsed, list) or not parsed:
        raise ToolError("items must be a non-empty JSON array.")
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        return _dump(await _get_client().accept_coverage_divergences(
            model_id, parsed, change_reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def dismiss_verdict_divergences(
    server_version: str,
    model_id: str,
    items: str,
    reason: str,
) -> dict:
    """Dismiss a set of divergences (the structural model was right, the LLM
    was not) WITHOUT changing the model.

    Use for rows you have reviewed and judged not valid. A dismissal is keyed
    to the divergence's current verdict input hash, so it auto-clears (the row
    reappears) once the underlying control or objective changes. Works for
    coverage AND group_sufficiency rows.

    Args:
        model_id: ID of the threat model.
        items: JSON array of {"kind", "co_id", "control_id"?, "group_id"?}
            objects. control_id is required for coverage kinds; group_id for
            group_sufficiency.
        reason: Why these divergences are being set aside (min 1 char).
    """
    import json as _json

    try:
        parsed = _json.loads(items)
    except (ValueError, TypeError) as exc:
        raise ToolError("items must be a JSON array of divergence objects.") from exc
    if not isinstance(parsed, list) or not parsed:
        raise ToolError("items must be a non-empty JSON array.")
    if not reason.strip():
        raise ToolError("reason must not be empty.")
    try:
        return _dump(await _get_client().dismiss_verdict_divergences(
            model_id, parsed, reason.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def retry_verdicts(
    server_version: str,
    model_id: str,
) -> dict:
    """Re-trigger a model's parked verdict re-evals after a transient failure.

    When a verdict re-evaluation fails transiently — a provider outage,
    exhausted credits, or a timeout — it is parked and reads as "unavailable /
    treated as unverified", recovering only after a delay. This forces an
    immediate, non-destructive re-run of ONLY the parked/failed re-eval slots,
    across every verdict kind (coverage, group-sufficiency, per-control
    sufficiency, coherence). It changes no assertions, controls, or verdict
    content, so no IDs churn. Evaluation runs in the background — re-read the
    sufficiency or verification report shortly after to see updated verdicts.

    Prefer this over ``recompute_verdicts`` when verdicts are stuck due to an
    outage: ``recompute_verdicts`` force-enqueues coverage + group-sufficiency
    for the whole model (metered per its estimate) and cannot un-park a job
    whose inputs are unchanged, whereas this re-arms exactly the failed slots
    and covers per-control sufficiency + coherence too.

    Args:
        model_id: ID of the threat model whose parked verdicts to retry.

    Returns:
        Dict with:
        - model_id, model_version
        - retried_slots: number of parked/failed re-eval slots re-armed
          (0 when nothing was parked)
        - governor: spend status — when ``governor.exhausted`` is true, re-runs
          resume automatically at ``governor.resets_at``.
    """
    try:
        return _dump(await _get_client().retry_verdicts(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Compliance ===


@mcp.tool()
async def list_compliance_frameworks(server_version: str) -> dict:
    """List the compliance frameworks available to map controls against.

    Read-only; no side effects. Returns both built-in frameworks (e.g. OWASP
    ASVS) and any custom frameworks in the workspace. Use this to discover
    framework identifiers before ``select_compliance_frameworks`` (activate one
    for a model) or ``import_compliance_framework`` (add a custom one). Takes no
    arguments beyond the version guard.
    """
    try:
        return _dump(await _get_client().list_compliance_frameworks())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def import_compliance_framework(
    server_version: str,
    framework_json: str,
) -> dict:
    """Import a custom compliance framework. Requires PRO tier.

    Use this when your customer's program (regulatory, contractual, or
    internal) is not covered by Mipiti's 11 built-in frameworks. After
    import, the framework is selectable on threat models exactly like
    a built-in.

    Schema (top-level fields):
        - ``name`` (required): framework display name
        - ``version`` (optional): e.g. "1.0"
        - ``description`` (optional): one-paragraph description
        - ``level_definitions`` (optional, level-aware frameworks only):
          map keyed by **stringified integer level** ("1", "2", …)
          because the key IS the cumulative-filter ordinal
          (``level <= target_level``) and the ``level: int`` field on
          every requirement. Non-integer keys are rejected with
          HTTP 400. **Human labels are decoupled** — "Baseline" /
          "Hardened" / "SL3" / "CAL Critical" live in the ``name``
          field, not the key. Each value is
          ``{"name", "description", "source"}``. Ships the per-level
          legend to the LLM prompt and the framework-target UI.
          ``source`` is "authoritative" when paraphrased from the
          published standard, "mipiti_convention" when you defined the
          tiers yourself.
        - ``requirements`` (required, non-empty list): each entry takes
          ``id`` (required), ``description`` (required),
          ``level`` (optional integer, default 1),
          ``chapter_id`` / ``chapter_name`` / ``section_id`` /
          ``section_name`` / ``title`` (optional grouping),
          ``scope`` (optional, "component" default or "system" for
          requirements covered if ANY model satisfies them),
          ``level_specific_text`` (optional map of per-tier text;
          same stringified-integer-key rule as ``level_definitions``).

    Example minimal body::

        {
          "name": "ACME Internal Baseline",
          "version": "2026.1",
          "requirements": [
            {"id": "ACME-1", "description": "All endpoints authenticate", "level": 1},
            {"id": "ACME-2", "description": "TLS 1.3 in transit", "level": 1}
          ]
        }

    Example with per-level legend + per-requirement parameters::

        {
          "name": "ACME Tiered",
          "level_definitions": {
            "1": {"name": "Baseline", "description": "Minimum.",
                  "source": "authoritative"},
            "2": {"name": "Hardened", "description": "Sensitive data.",
                  "source": "mipiti_convention"}
          },
          "requirements": [
            {"id": "ACME-PWD",
             "description": "Passwords meet policy",
             "level": 1,
             "level_specific_text": {
               "1": "Min 8 characters.",
               "2": "Min 14 + MFA required."
             }}
          ]
        }

    Args:
        framework_json: A JSON string containing the framework body.
            (String not dict so the JSON shape stays explicit on the wire.)
    """
    import json as _json

    try:
        parsed = _json.loads(framework_json)
    except _json.JSONDecodeError as exc:
        raise ValueError(f"framework_json is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("framework_json must decode to a JSON object.")
    try:
        return _dump(await _get_client().import_compliance_framework(parsed))
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
    """Manually map one security control to one compliance-framework requirement. Mutating: records a control-to-requirement mapping, which re-derives that requirement's coverage in the compliance report.

    Use for a single, deliberate mapping you are asserting by hand. To let the LLM propose mappings across many requirements at once, use auto_map_controls; to close gaps end-to-end (map + exclude + fill), use auto_remediate_compliance.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        requirement_id: ID of the requirement to map to (e.g. "V2.1.1").
        control_id: ID of the control to map (e.g. "CTRL-01").
        confidence: Provenance label recorded on the mapping: "manual" (default, operator-asserted), "llm" (machine-suggested), or "verified" (human-confirmed).
        notes: Optional free-text note explaining the mapping rationale.
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
    """LLM-map a model's existing controls to a framework's requirements. Requires PRO tier. Mutating: writes control-to-requirement mappings. Runs as a background job (typically 20-45s); this tool waits for completion and returns the result.

    Sits between the manual map_control_to_requirement (one mapping at a time) and the full auto_remediate_compliance loop (which also excludes non-applicable requirements and proposes new entities for remaining gaps). auto_map_controls only creates mappings from controls that already exist — it never adds or excludes entities.

    Args:
        model_id: ID of the threat model.
        framework_id: ID of the compliance framework.
        control_id: Optional single control ID to map; omit to map all of the model's controls.
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


# === Workspaces & Systems ===


@mcp.tool()
async def list_workspaces(server_version: str) -> dict:
    """List the workspaces the current user belongs to.

    Read-only; no side effects. Returns each workspace's id and name. Models,
    controls, and compliance are all scoped to a workspace, so use this to
    discover the workspace context you're operating in. Takes no arguments
    beyond the version guard.
    """
    try:
        return _dump(await _get_client().list_workspaces())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def update_organization(
    server_version: str,
    org_id: str,
    target_ml: Optional[int] = None,
    csf_tier: Optional[int] = None,
    clear_target_ml: bool = False,
    clear_csf_tier: bool = False,
) -> dict:
    """Set per-organization level grades for IEC 62443-4-1 and NIST CSF.

    Admin-only: the backend requires the caller to be an admin in the
    organization (or a superadmin). Non-admins will get a 403; do not
    invoke this tool unless you've verified admin role for the target
    org.

    ``target_ml`` is the IEC 62443-4-1 Maturity Level the organization
    targets for its secure-development program (1-5). ``csf_tier`` is
    the NIST CSF Tier the organization targets for its cybersecurity
    risk-management posture (1-4).

    Because ``None`` on the wire is indistinguishable from "field
    omitted", pass ``clear_target_ml=True`` or ``clear_csf_tier=True``
    to explicitly reset a value to NULL. Omitting both the value and
    its ``clear_*`` flag leaves the existing server-side value
    untouched.

    Args:
        org_id: Organization ID.
        target_ml: IEC 62443-4-1 Maturity Level (1-5), or ``None`` to leave unchanged.
        csf_tier: NIST CSF Tier (1-4), or ``None`` to leave unchanged.
        clear_target_ml: Explicitly reset ``target_ml`` to NULL.
        clear_csf_tier: Explicitly reset ``csf_tier`` to NULL.

    Returns:
        The full organization dict.
    """
    if target_ml is not None and (target_ml < 1 or target_ml > 5):
        raise ToolError("target_ml must be between 1 and 5 (inclusive)")
    if csf_tier is not None and (csf_tier < 1 or csf_tier > 4):
        raise ToolError("csf_tier must be between 1 and 4 (inclusive)")
    try:
        return _dump(await _get_client().update_organization(
            org_id,
            target_ml=target_ml,
            csf_tier=csf_tier,
            clear_target_ml=clear_target_ml,
            clear_csf_tier=clear_csf_tier,
        ))
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

    Components bridge security architecture to code organization. They
    map trust boundaries to repos so controls can be scoped to the
    codebase that implements them. They also drive the deterministic
    reachability composer's asset-boundary derivation: an asset's
    trust-boundary footprint is the union of its components'
    ``trust_boundary_ids``.

    A component with empty ``repo_url`` is either speculative (your own
    code, not linked to a repo yet) or external (e.g. a third-party
    service, the customer's IdP, or other external infrastructure you
    call but don't own).
    The component's trust boundary tells them apart: bind an
    internal-zone component to its repo via ``edit_component``; leave an
    external-zone component unbound — its ``component_unbound`` finding
    is a permanent external-dependency marker, not a gap to close.
    Binding by "some client code touches it" is wrong: client code for
    external dependencies lives in your repo too.

    Args:
        model_id: ID of the threat model.
        name: Component name (e.g., "Backend API", "Auth Worker").
        repo_url: Repository URL (e.g., "github.com/org/backend").
            Empty string is valid for speculative components — pass a
            real URL once you've identified the codebase.
        path: Path within repo for monorepos (e.g., "services/auth").
        trust_boundary_ids: Comma-separated trust boundary IDs that
            this component spans (its deployment zone). Drives reach
            decisions for any asset scoped to this component.
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
    target_sl: Optional[int] = None,
    eal: Optional[int] = None,
    fips_level: Optional[int] = None,
) -> dict:
    """Edit a component's properties.

    Per-component level grades are orthogonal axes — set whichever
    apply to the program the component is in scope for. Leave a field
    unset (``None``) to keep the current server-side value; backend
    treats absent fields as "unchanged".

    Args:
        model_id: ID of the threat model.
        component_id: ID of the component (e.g., "CMP1").
        name: New name (empty = unchanged).
        repo_url: New repo URL (empty = unchanged).
        path: New path (empty = unchanged).
        trust_boundary_ids: New trust boundary IDs (comma-separated, empty = unchanged).
        target_sl: IEC 62443 target Security Level (1-4). For
            industrial / OT components that need a 62443 zone target.
        eal: Common Criteria Evaluation Assurance Level (1-7).
            For components subject to CC certification.
        fips_level: FIPS 140-3 Security Level (1-4) for the
            cryptographic module embedded in this component.
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
    if target_sl is not None:
        fields["target_sl"] = target_sl
    if eal is not None:
        fields["eal"] = eal
    if fips_level is not None:
        fields["fips_level"] = fips_level
    try:
        return _dump(await _get_client().edit_component(model_id, component_id, **fields))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Cross-Model Dependencies ===


@mcp.tool()
async def get_system_dependencies(
    server_version: str,
    system_id: str,
) -> dict:
    """Get the cross-model dependency graph for a system. Read-only; no side effects.

    Returns every assumption in the system's member models that is linked to another member model (a cross-model dependency), with its satisfaction status. A dependency is satisfied when either the target model's mapped controls are implemented or a valid manual attestation exists.

    Use to see which assumptions are met by other models' controls, find unsatisfied dependencies, or check system-level completeness. Create these links with link_system_dependency.

    Args:
        system_id: ID of the system.
    """
    try:
        return _dump(await _get_client().get_system_dependencies(system_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# === System Compliance ===


# === Assertions & Verification ===


_SUBMIT_ASSERTIONS_DOC = f"""\
Submit assertions for a security control or an assumption.

Mutating: persists new assertion records against the target. It does NOT run \
verification itself — assertions are checked later in CI (structurally, then \
semantically) and cryptographically attested; submitting only records the \
claims to be verified. To read existing assertions use list_assertions; to \
remove one use delete_assertion.

Each assertion is a typed, machine-verifiable claim about a system property \
(source code, configuration, infrastructure, or external service settings).

Provide exactly one of control_id or assumption_id:
- control_id: proves a control is implemented (e.g., "CTRL-01")
- assumption_id: proves a system property claim (e.g., "AS5" — asset \
non-applicability, attacker non-applicability, scope decisions)

The feature description is the design specification the model derives from, \
so a claim about it is a claim about the specified design. To verify against \
it instead of a repository file, use target in place of file. Valid on any \
subject (a control, an assumption, a node, a functional test), and accepted \
by the two types whose criterion is a regex over arbitrary text — \
pattern_matches and pattern_absent. It is the natural shape for a \
non-applicability claim, which has no file to point at:
{{"type": "pattern_matches", "params": {{"target": "feature_description", \
"pattern": "password.*TOTP"}}, "description": "..."}}
A target assertion is still bound to a repository: it must carry an explicit \
repo, the "<owner>/<repo>" slug of the CI repository whose verification run \
should check it, or the "no_repo" sentinel, which opts the assertion out of \
every run so no CI run will ever pull it.

Args:
    model_id: ID of the threat model.
    control_id: ID of the control (omit if using assumption_id).
    assumption_id: ID of the assumption (omit if using control_id).
    assertions_json: JSON array of assertion objects. Each object has:
        - type (required): one of the assertion types below
        - params (required): type-specific parameters (file or target + pattern/name/etc.)
        - description (required): human-readable explanation of what this proves
        - repo (required): the "<owner>/<repo>" slug of the CI repository whose verification run should check this assertion — for a file-based assertion, the codebase its file path is resolved against, and what keeps a run for one repo from picking up another repo's claims. An assertion with no repository scope must say so with the "no_repo" sentinel, which opts it out of every run; an empty or missing repo is rejected.

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
    """Submit machine-verifiable assertions for a control or assumption."""
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

    Returns a flat list of assertions. Each assertion carries an ``origin``
    field: "own" for assertions submitted directly against this model's
    control or assumption, "inherited" for assertions contributed through
    model composition (composed models whose assertions apply here).
    Inherited assertions are included in the listing.

    Each assertion also carries three INDEPENDENT verdict fields. Read them
    together — a passing tier check is not the same as sufficient evidence:

    - ``tier1_status`` — mechanical check: the named file, symbol, or
      pattern is actually there. ``"pass" | "fail" | "pending"``.
    - ``tier2_status`` — semantic check: the cited code meaningfully
      implements the claim. ``"pass" | "fail" | "pending"``.
    - ``coherence_status`` — advisory consistency signal across the
      control's evidence set. ``"pending"`` here does NOT block the control
      from verifying, does NOT mean a verdict is missing, and is NOT a
      reason to trigger a recompute.

    An assertion can pass BOTH tiers while its control stays unverified,
    because verification is decided per CONTROL, not per assertion: a
    control verifies only when its assertions collectively cover every
    clause of the control description. Read ``get_sufficiency`` for that
    verdict; never infer it from the tier fields here.

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
    """Permanently delete a single assertion from a control or assumption. Mutating and destructive: the assertion record is removed, not soft-deleted, and its contribution to sufficiency/verification is dropped. It does NOT itself re-run verification; sufficiency is re-evaluated on subsequent reads.

    Use to retract a claim that was submitted in error or that ``get_verification_report`` flagged as misaligned (off-topic for the control's current description). To add assertions use ``submit_assertions``; to inspect them first use ``list_assertions``. Only "own" assertions can be removed here — inherited assertions come from composed models and must be managed on their source model.

    Args:
        model_id: ID of the threat model.
        assertion_id: ID of the assertion to delete.
        control_id: ID of the control the assertion belongs to (omit if it belongs to an assumption).
        assumption_id: ID of the assumption the assertion belongs to (omit if it belongs to a control).
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
    """Sufficiency verdict for a single control: whether its submitted assertions collectively cover every aspect of the control. Read-only.

    Returns the LLM sufficiency status and reasoning for one control, evaluated server-side from the current assertion set (no CI round-trip). Use this for a focused check on one control after submitting assertions; for the whole-model rollup with tier1/tier2 pass/fail counts and drift/misalignment details across all controls, use ``get_verification_report`` instead. A verdict may be reported as stale when the control description or assertion set changed since it was last computed, in which case a fresh evaluation is triggered automatically — call again shortly for the updated result.

    This is the surface that explains a control stuck at
    ``verification_status: "partially_verified"``. Returns ``status``
    (``"sufficient" | "insufficient" | "pending" | "stale"``) and, when
    insufficient, a ``details`` breakdown naming EACH uncovered clause of
    the control description and what evidence would close it — a concrete
    work list, not a score. Act on it by submitting the named assertions
    with ``submit_assertions``; if a clause is uncloseable because the
    control describes a mechanism the system does not actually use, that
    is a signal to ``refine_control`` instead of manufacturing evidence.

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
    """Record negative findings (gaps discovered while scanning a codebase against a model's controls). Mutating: persists new finding records against the model.

    Use after a gap-discovery scan (see ``get_scan_prompt``) to log where expected control evidence was NOT found. Findings are the negative counterpart to assertions (positive proof via ``submit_assertions``): a finding says "I looked here for this and it was missing." Once submitted, drive a finding through its lifecycle with ``update_finding`` and review them with ``list_findings``.

    Args:
        model_id: ID of the threat model.
        findings_json: JSON string of an **array** of finding objects. Each object should carry:
            - ``control_id`` (str): the control the gap relates to.
            - ``title`` (str): short summary of the gap.
            - ``description`` (str): what is missing and why it matters.
            - ``severity`` (str): finding severity (e.g., "low"/"medium"/"high"/"critical").
            - ``checked_locations`` (list): files/paths inspected.
            - ``checked_patterns`` (list): patterns/signals searched for.
            - ``expected_evidence`` (str): what implemented evidence would have looked like.
            Must parse as a JSON array; a single object or malformed JSON is rejected.
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
    """List negative findings recorded on a threat model. Read-only.

    Returns finding rows with their lifecycle status; use to triage gaps or to find a ``finding_id`` for ``update_finding`` / ``preview_finding_remediation``. Each row carries an ``origin`` ("own" for findings recorded on this model, "inherited" for findings contributed through model composition, with ``inherited_from_*`` context); inherited findings are included in the listing.

    Args:
        model_id: ID of the threat model.
        control_id: Optional filter to findings on one control. Empty (default) returns findings for all controls.
        status: Optional lifecycle filter, one of "discovered", "acknowledged", "remediated", "verified", "dismissed". Empty (default) returns all statuses.
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
    """Advance a finding through its lifecycle. Mutating: updates the finding's status and metadata.

    Use to acknowledge, remediate, verify, or dismiss a finding previously recorded by ``submit_findings`` / ``list_findings``. This records a manual status transition; for gaps whose kind has an automatic fix, ``preview_finding_remediation`` + ``apply_finding_remediation`` perform the actual cleanup instead.

    Args:
        model_id: ID of the threat model.
        finding_id: ID of the finding to update.
        status: New lifecycle status, one of "discovered", "acknowledged", "remediated", "verified", "dismissed".
        notes: Optional free-text notes recorded on the finding.
        reason: Optional rationale; required when dismissing (status="dismissed").
        remediation_assertion_ids: Optional comma-separated assertion IDs that evidence the fix, linking the remediation to the assertions that prove it. Empty by default.
    """
    try:
        return _dump(await _get_client().update_finding(
            model_id, finding_id, status, notes, reason, remediation_assertion_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def preview_finding_remediation(
    server_version: str,
    finding_id: str,
) -> dict:
    """Preview what the platform would do to remediate a finding.

    Read-only. Returns a structured diff describing the changes a
    subsequent apply_finding_remediation call would make. Use this
    BEFORE apply_finding_remediation to show the operator exactly
    what cleanup will happen, and get explicit confirmation before
    committing.

    The exact shape of the diff depends on the finding's kind. For
    kind=structural_duplicate_controls, you get back which controls
    would be kept, which dropped, and the union of CO mappings +
    framework refs that would land on the survivor.

    Returns 404 if the finding doesn't exist; 422 if the finding's
    kind has no automatic remediation handler.

    Args:
        finding_id: ID of the finding to preview remediation for.
    """
    try:
        return _dump(await _get_client().preview_finding_remediation(finding_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def apply_finding_remediation(
    server_version: str,
    finding_id: str,
    justification: str,
    ctx: Context,
) -> dict:
    """Apply the remediation for a finding. Mutates state.

    Commits the changes preview_finding_remediation showed. The
    justification is recorded in the audit trail and shown in any
    future review of why this cleanup was run.

    DO NOT call this without first calling
    preview_finding_remediation and showing the operator the diff.
    The agent's role is to surface what's about to happen and get
    explicit operator confirmation; the platform records who acted
    but doesn't enforce the preview-then-apply norm — the agent does.

    Returns 404 if the finding doesn't exist; 409 if the finding is
    already remediated or dismissed; 400 if justification is empty;
    422 if the finding's kind has no automatic remediation handler.

    Args:
        finding_id: ID of the finding to remediate.
        justification: One-line operator rationale recorded on the
            audit trail. Must be non-empty.
    """
    if not justification or not justification.strip():
        raise ToolError(
            "justification is required and must be non-empty. Pass the "
            "operator's one-line rationale (e.g., \"cleaning up duplicates "
            "from pre-fix trigger bug\") so the audit trail records why "
            "the remediation ran."
        )
    try:
        client = _get_client()
        # Runs as a background job (remediation handler's strong-LLM step scales
        # with the finding's blast radius); poll it so the work stays off the
        # backend event loop and the transport stays warm.
        started = await client.start_apply_finding_remediation(
            finding_id, justification,
        )
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Findings / Risk aggregates ===


@mcp.tool()
async def get_findings_risks(server_version: str) -> dict:
    """Workspace-scoped triage dashboard: open findings, active risk
    acceptances, and at-risk Control Objectives across every model
    the workspace can access.

    Use this as the entry point when an operator asks "what's open?"
    or "what should I work on next?" — one round-trip returns all
    three categories with model context and risk dimensions
    (severity, status, risk_tier, owner, review_by) so the agent can
    triage without per-model fan-out. The endpoint is read-only and
    fast; it composes from existing per-model queries server-side.

    Returns the envelope verbatim: ``{workspace_id, evaluated_at,
    models, findings, risk_acceptances, at_risk_cos, summary}``.
    ``summary`` carries totals (``open_findings``, ``total_findings``,
    ``active_risk_acceptances``, ``total_risk_acceptances``,
    ``at_risk_cos``) for quick health-check responses.
    """
    try:
        return _dump(await _get_client().get_findings_risks())
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_remediation_leverage(server_version: str, model_id: str) -> dict:
    """Remediation-leverage plan for a model: which controls to implement
    first to close the most control objectives with the least work.

    Returns the model's not-yet-satisfied controls ranked by how many
    control objectives each one closes (``ranked``), plus a greedy
    minimal fix order — the sequence of controls that reaches the most
    mitigated objectives with the fewest controls (``greedy_plan``) — and
    a ``summary`` of the collapse (total objectives, currently mitigated,
    how many controls the plan needs). Use to prioritize implementation
    work: a single call tells the agent which controls give the highest
    leverage, so it can tackle the shortest path to coverage instead of
    fixing objectives one at a time. Read-only.

    Composed models: each entry in ``ranked`` and ``greedy_plan`` also
    carries its owning model — ``owner_model_id`` and ``owner_model_title``
    — and an ``inherited`` flag. ``inherited`` is true when the control is
    authored on an ancestor model, meaning the fix lands on that model
    rather than the one being assessed; ``summary.inherited_candidate_controls``
    counts them. Surface the owning model so the operator knows which
    high-leverage fixes belong to a parent model. A flat (non-composed)
    model reports every control as owned by the assessed model.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return await _get_client().get_remediation_leverage(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_risk_acceptances(server_version: str, model_id: str) -> dict:
    """List all risk acceptances on a specific threat model — risks
    that an operator explicitly accepted instead of mitigating.

    Each entry carries the CO id, owner, justification, status
    (``active`` / ``expired`` / ``revoked``), and the review
    deadline. Use to inspect which gaps were intentionally accepted
    versus genuinely unaddressed when triaging at-risk COs.

    Returns risk acceptances ONLY. An objective declared not applicable is a
    different claim — it is not an accepted risk, and counting it as one would
    read a "does not apply here" as "we are carrying this exposure". Use
    ``list_co_dispositions`` to see those, or both together.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().list_risk_acceptances(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def create_risk_acceptance(
    server_version: str,
    model_id: str,
    control_objective_id: str,
    owner: str,
    justification: str,
    review_by: str,
) -> dict:
    """Record that an operator explicitly ACCEPTS the residual risk on a control
    objective instead of mitigating it — the write counterpart to
    ``list_risk_acceptances``.

    Use when a control objective's residual risk is a deliberate, documented
    decision rather than an unaddressed gap: the acceptance carries an owner, a
    justification, and a review deadline, and reads as ``active`` until it
    expires or is revoked. Prefer this over leaving a known-and-accepted risk
    implicit — it makes the decision auditable and forces a revisit by the
    deadline. An accepted objective is still surfaced (as accepted, not
    unaddressed) when triaging at-risk objectives.

    Args:
        model_id: ID of the threat model.
        control_objective_id: The control objective whose residual risk is accepted.
        owner: Who owns the acceptance (name / role).
        justification: Why the risk is accepted (the rationale of record).
        review_by: ISO 8601 date to revisit the acceptance (e.g. "2027-02-06T00:00:00Z").
    """
    try:
        return _dump(await _get_client().create_risk_acceptance(
            model_id,
            control_objective_id=control_objective_id,
            owner=owner,
            justification=justification,
            review_by=review_by,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def create_co_disposition(
    server_version: str,
    model_id: str,
    control_objective_id: str,
    owner: str,
    justification: str,
    review_by: str,
) -> dict:
    """Record that a control objective DOES NOT APPLY to this system — a signed,
    expiring judgment, not a dismissal.

    The sibling of ``create_risk_acceptance``, and the distinction between them
    is the claim being made. A risk acceptance says *the exposure is real and we
    are carrying it*. A disposition says *this objective does not apply here at
    all* — the asset is not handled the way the objective assumes, the attacker
    position does not exist in this deployment, the capability is not present.

    **The objective is not removed.** It stays in the control-objective matrix,
    stays in every coverage count, and is reported in its own class alongside
    the owner and justification recorded here. That is the point: a reviewer can
    see the judgment and challenge it. An objective that simply vanished would
    be indistinguishable from one nobody modelled.

    What it does change is work: no controls are generated for the objective and
    no coverage gap is raised against it, because an objective that does not
    apply is not a gap.

    ``review_by`` is required and is not a formality — the claim stops applying
    on that date, and the objective returns to whatever posture its controls
    give it, gap included. Choose a date by which someone can realistically
    re-check that the claim still holds.

    Use ``create_risk_acceptance`` instead when the objective DOES apply and the
    exposure is being carried deliberately. If an objective is only unaddressed
    rather than inapplicable, neither tool is right — add controls.

    Args:
        model_id: ID of the threat model.
        control_objective_id: The objective being declared not applicable.
        owner: Who owns the judgment (name / role). They answer for it.
        justification: Why the objective does not apply to this system.
        review_by: ISO 8601 date the claim expires (e.g. "2027-02-06T00:00:00Z").
    """
    try:
        return _dump(await _get_client().create_risk_acceptance(
            model_id,
            control_objective_id=control_objective_id,
            owner=owner,
            justification=justification,
            review_by=review_by,
            kind="not_applicable",
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_co_dispositions(
    server_version: str,
    model_id: str,
    kind: str = "",
) -> dict:
    """List the signed judgments recorded against this model's control
    objectives — risk acceptances, not-applicable dispositions, or both.

    Read-only. Each entry carries the objective it names, the owner who signed
    it, the justification, the dates, and its status. Expired and revoked
    entries are included: a decision that lapsed is part of the audit trail, and
    hiding it would leave a reader unable to tell a judgment that was reviewed
    from one that was never made.

    Read this before authoring a new judgment on an objective — an existing one
    may already cover it, or may have expired and need re-signing rather than
    duplicating.

    Args:
        model_id: ID of the threat model.
        kind: Optional filter — "risk_accepted" or "not_applicable". Omit for
            both. Case and surrounding whitespace do not matter. A value that
            is neither is rejected by name rather than matched against
            nothing, so a typo cannot come back as an empty list you would
            read as "none recorded".
    """
    wanted = (kind or "").strip().lower() or "all"
    if wanted not in ("risk_accepted", "not_applicable", "all"):
        raise ToolError(
            f'Unknown kind {kind!r}. Valid values: not_applicable, '
            f'risk_accepted (or omit for both).'
        )
    try:
        return _dump(await _get_client().list_co_dispositions(model_id, kind=wanted))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Scan Prompt ===


# === Project Setup ===


@mcp.tool()
async def complete_setup_step(server_version: str, step_id: str) -> dict:
    """Mark one onboarding setup step as done. Mutating: updates the workspace onboarding checklist. Call after actually performing the corresponding setup action on the user's behalf.

    Check current progress with ``get_setup_status`` first to avoid re-marking completed steps. An unrecognized ``step_id`` is rejected without any state change.

    Args:
        step_id: The step to mark complete, one of "mcp_configured", "mipiti_verify_installed", "ci_secret_added", "ci_pipeline_added".
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
    """Get the workspace onboarding checklist with completed and pending steps. Read-only.

    Call this before suggesting or performing setup actions so already-done steps aren't repeated; mark a step done with ``complete_setup_step``. Takes no arguments beyond the version header.
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
    passes: Optional[str] = None,
    sealed: Optional[bool] = None,
) -> dict:
    """Add a trust boundary. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        description: What this boundary represents (e.g., "Public network to API server").
        crosses: Optional comma-separated asset IDs that cross this boundary.
        passes: Optional comma-separated AttackVector values the boundary
            allows through (subset of "Network,Adjacent,Local,Physical").
            Omit for the methodology default (passes-everything). Narrowing
            this set is what makes a boundary block specific attacker
            vectors in the deterministic reachability composer.
        sealed: Optional. Set True to declare the boundary has NO lateral
            ingress — the only way into its zone is crossing the perimeter
            (an air-gap / network-segmented enclave). A sealed boundary that
            blocks the attacker's vector lets reachability decisively rule the
            asset unreachable instead of indeterminate. Default False (assume a
            lateral pivot is possible). Set it only when the isolation is real
            and attestable.
    """
    parsed_crosses = [c.strip() for c in crosses.split(",") if c.strip()] if crosses else []
    parsed_passes = (
        [v.strip() for v in passes.split(",") if v.strip()] if passes is not None else None
    )
    try:
        return await _get_client().add_trust_boundary(
            model_id, description, parsed_crosses or None, parsed_passes,
            sealed=sealed,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_trust_boundary(
    server_version: str, model_id: str, tb_id: str,
    description: Optional[str] = None,
    crosses: Optional[str] = None,
    passes: Optional[str] = None,
    sealed: Optional[bool] = None,
    seal_source: Optional[str] = None,
    change_reason: Optional[str] = None,
) -> dict:
    """Edit a trust boundary. Creates a new model version.

    Args:
        model_id: ID of the threat model.
        tb_id: ID of the trust boundary (e.g., "TB1").
        description: New description.
        crosses: New comma-separated asset IDs.
        passes: New comma-separated AttackVector values the boundary allows
            through (subset of "Network,Adjacent,Local,Physical"). Use the
            empty string to set "blocks all"; omit to leave unchanged.
            Reach-relevant — narrowing or widening this set can flip CO
            verdicts.
        sealed: New isolation flag. True declares NO lateral ingress (the only
            way in is crossing the perimeter — an air-gap / segmented enclave),
            which lets reachability decisively rule the boundary unreachable;
            False assumes a lateral pivot is possible. Reach-relevant — changing
            it can flip CO verdicts. Setting it records an operator attestation
            of the seal. Omit to leave unchanged.
        seal_source: "attested" | "unattested". Only an operator-attested seal
            lets reachability decisively rule an objective unreachable past the
            boundary; an unattested (default/model-suggested) seal is treated as
            pivotable. Use "attested" to attest a boundary already marked sealed
            without re-toggling it; "unattested" retracts. An attested seal
            implies ``sealed``. Requires ``change_reason``.
        change_reason: Required when ``passes``, ``sealed``, or the seal
            attestation actually changes. Captured in the audit trail; documents
            why the boundary's vector filter, isolation claim, or attestation
            changed.
    """
    kwargs: dict = {}
    if description is not None:
        kwargs["description"] = description
    if crosses is not None:
        kwargs["crosses"] = [c.strip() for c in crosses.split(",") if c.strip()]
    if passes is not None:
        kwargs["passes"] = [v.strip() for v in passes.split(",") if v.strip()]
    if sealed is not None:
        kwargs["sealed"] = sealed
    if seal_source is not None:
        kwargs["seal_source"] = seal_source
    if change_reason is not None:
        kwargs["change_reason"] = change_reason
    try:
        return await _get_client().edit_trust_boundary(model_id, tb_id, **kwargs)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption CRUD ===


@mcp.tool()
async def add_assumption(
    server_version: str, model_id: str, description: str,
    linked_co_ids: Optional[str] = None,
    assumption_type: str = "external",
    exclusion_attacker_id: Optional[str] = None,
    exclusion_attacker_vector: Optional[str] = None,
    exclusion_asset_id: Optional[str] = None,
    exclusion_asset_component_id: Optional[str] = None,
    exclusion_property_match: Optional[str] = None,
    exclusion_co_ids: Optional[str] = None,
) -> dict:
    """Add an assumption. Creates a new model version.

    Assumptions represent security properties outside the system owner's
    trust boundary. When linked to COs and attested, they mitigate those
    COs in the assessment.

    Optionally attach a structured exclusion predicate (the
    ``exclusion_*`` params). The reachability composer matches active
    + attested assumptions with predicates against COs deterministically
    — class-3 (deterministic computation) evidence in addition to the
    operator-attested class-1 evidence. Pass any subset of the fields;
    unspecified fields default to wildcard ("*"). When
    ``exclusion_co_ids`` is non-empty, it takes precedence over the
    match fields.

    Use this to resolve a CO whose composer verdict is
    ``indeterminate`` because no structural primitive backs an
    operator non-applicability claim: set ``exclusion_co_ids=<co_id>``
    (and optionally the attacker/asset/property fields), and the
    composer will derive ``unreachable / reason: assumption_excludes``
    on subsequent loads, with the assumption's structured predicate as
    the audit-trail cause.

    Args:
        model_id: ID of the threat model.
        description: What is assumed (e.g., "Customer restricts CI runner egress").
        linked_co_ids: Optional comma-separated CO IDs this assumption covers.
        assumption_type: "external" (default, allows manual attestation)
            or "non_applicability" (requires CI verification, no manual attestation).
        exclusion_attacker_id: Predicate match — "*" wildcard (default
            when any other exclusion_* param is set) or concrete attacker ID.
        exclusion_attacker_vector: One of "Network" | "Adjacent" | "Local"
            | "Physical" | "*".
        exclusion_asset_id: "*" or concrete asset ID.
        exclusion_asset_component_id: "*" or concrete component ID.
        exclusion_property_match: "C" | "I" | "A" | "U" | "*".
        exclusion_co_ids: Comma-separated CO IDs the predicate matches
            explicitly. When non-empty, overrides the match fields.
    """
    parsed = [c.strip() for c in linked_co_ids.split(",") if c.strip()] if linked_co_ids else None

    # Build exclusion only when at least one exclusion_* param is supplied.
    has_excl = any(
        v is not None for v in (
            exclusion_attacker_id, exclusion_attacker_vector,
            exclusion_asset_id, exclusion_asset_component_id,
            exclusion_property_match, exclusion_co_ids,
        )
    )
    exclusion: Optional[dict] = None
    if has_excl:
        exclusion = {
            "attacker_id": exclusion_attacker_id or "*",
            "attacker_vector": exclusion_attacker_vector or "*",
            "asset_id": exclusion_asset_id or "*",
            "asset_component_id": exclusion_asset_component_id or "*",
            "property_match": exclusion_property_match or "*",
            "co_ids": (
                [c.strip() for c in exclusion_co_ids.split(",") if c.strip()]
                if exclusion_co_ids else []
            ),
        }
    try:
        return await _get_client().add_assumption(
            model_id, description, parsed,
            assumption_type=assumption_type,
            exclusion=exclusion,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_assumption(
    server_version: str, model_id: str, assumption_id: str,
    description: Optional[str] = None,
    linked_co_ids: Optional[str] = None,
    exclusion_attacker_id: Optional[str] = None,
    exclusion_attacker_vector: Optional[str] = None,
    exclusion_asset_id: Optional[str] = None,
    exclusion_asset_component_id: Optional[str] = None,
    exclusion_property_match: Optional[str] = None,
    exclusion_co_ids: Optional[str] = None,
    clear_exclusion: bool = False,
) -> dict:
    """Edit an assumption. Creates a new model version.

    Exclusion predicate semantics on edit:
      - If any ``exclusion_*`` param is set: replace the existing
        predicate with one built from the supplied fields (unspecified
        fields default to "*").
      - If ``clear_exclusion=True``: remove the existing predicate
        entirely (the assumption becomes prose-only).
      - If neither: leave the existing predicate untouched.

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption to edit (e.g., "AS1").
        description: New description (omit to leave unchanged).
        linked_co_ids: New comma-separated CO IDs; replaces the existing
            linkage (omit to leave unchanged).
        exclusion_attacker_id: Predicate match — "*" wildcard or a concrete
            attacker ID.
        exclusion_attacker_vector: One of "Network" | "Adjacent" | "Local" |
            "Physical" | "*".
        exclusion_asset_id: "*" or a concrete asset ID.
        exclusion_asset_component_id: "*" or a concrete component ID.
        exclusion_property_match: "C" | "I" | "A" | "U" | "*".
        exclusion_co_ids: Comma-separated CO IDs the predicate matches
            explicitly; when non-empty, overrides the match fields. Supplying
            any exclusion_* param rewrites the whole predicate (unspecified
            fields default to "*").
        clear_exclusion: When True, removes the predicate entirely (the
            assumption becomes prose-only). Mutually exclusive with the
            exclusion_* params — if both are sent, the exclusion_* params win.
    """
    kwargs: dict = {}
    if description is not None:
        kwargs["description"] = description
    if linked_co_ids is not None:
        kwargs["linked_co_ids"] = [c.strip() for c in linked_co_ids.split(",") if c.strip()]

    has_excl = any(
        v is not None for v in (
            exclusion_attacker_id, exclusion_attacker_vector,
            exclusion_asset_id, exclusion_asset_component_id,
            exclusion_property_match, exclusion_co_ids,
        )
    )
    if has_excl:
        kwargs["exclusion"] = {
            "attacker_id": exclusion_attacker_id or "*",
            "attacker_vector": exclusion_attacker_vector or "*",
            "asset_id": exclusion_asset_id or "*",
            "asset_component_id": exclusion_asset_component_id or "*",
            "property_match": exclusion_property_match or "*",
            "co_ids": (
                [c.strip() for c in exclusion_co_ids.split(",") if c.strip()]
                if exclusion_co_ids else []
            ),
        }
    elif clear_exclusion:
        kwargs["exclusion"] = None
    try:
        return await _get_client().edit_assumption(model_id, assumption_id, **kwargs)
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
    """List an assumption's attestation history. Read-only; no side effects.

    Returns the chronological record of attestation events recorded against the assumption (each with its actor, timestamp, and status/expiry as recorded), so you can trace why the assumption is currently attested, expired, or never attested. An assumption only mitigates its control objectives while it is active AND currently attested, so use this to diagnose coverage that depends on an attestation.

    To record a new attestation use submit_attestation; for the assumption's current fields (status, description) use get_entity (entity_type="assumption").

    Args:
        model_id: ID of the threat model.
        assumption_id: ID of the assumption whose attestation history to list.
    """
    try:
        return await _get_client().list_attestations(model_id, assumption_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Control Assumption ===


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

    The legacy set_control_assumption_groups / set_control_assumption_groups tools remain as shorthand
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
    ctx: Context,
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
        client = _get_client()
        # Runs as a background job (strong-LLM per-group relevance gate); poll it
        # so the work stays off the backend event loop and the transport stays
        # warm.
        started = await client.start_set_control_assumption_groups(
            model_id, control_id, parsed_groups, justification.strip(),
        )
        return await _await_backend_job(client, started["job_id"], ctx)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assumption Restore ===


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
# Functional conformance (Capability × Condition)
# ------------------------------------------------------------------
# Proves a feature does what it was specified to do, verified by the same
# assertion + CI engine as security controls. Two flows:
# (1) generate — generate_functional_objectives → get_functional_scan_prompt →
#     write tests → add_functional_test → submit_functional_tests → CI verifies →
#     get_functional_coverage.
# (2) import existing tests — import_functional_tests → suggest_functional_test_mappings
#     → associate_functional_test → (optionally) set_functional_satisfaction_groups →
#     get_functional_test_sufficiency.


@mcp.tool()
async def generate_functional_objectives(
    server_version: str, model_id: str, refresh: bool = False,
) -> dict:
    """Derive capabilities, functional objectives, and the concrete tests to
    implement from the feature spec.

    Capabilities are the behaviours the feature must deliver; each is walked
    against a taxonomy of operating conditions (nominal, boundary, invalid
    input, dependency failure, concurrency, …) to produce testable
    Given-When-Then objectives — and then a concrete, implementable test is
    specified for each objective (so the agent implements the tests rather than
    deciding what to test). Requires a Pro plan. Billable — may take some time.
    `refresh=true` re-derives from scratch, replacing prior generated (not
    manually authored) capabilities, objectives, and tests.

    Args:
        model_id: ID of the threat model.
        refresh: Re-generate from scratch instead of serving cached output.
    """
    try:
        return _dump(await _get_client().generate_functional(model_id, refresh))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_capabilities(server_version: str, model_id: str) -> dict:
    """List every capability (a behaviour the feature must deliver) for a model.

    Read-only; no side effects. Use this to enumerate a model's capabilities
    (e.g. before reviewing functional objectives). To fetch one capability's
    full detail use ``get_capability`` instead.

    Args:
        model_id: ID of the threat model whose capabilities to list.

    Returns a list of capabilities, each with its id, name/description, and a
    summary of its component/asset bindings.
    """
    try:
        return _dump(await _get_client().list_capabilities(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_capability(server_version: str, model_id: str, capability_id: str) -> dict:
    """Get one capability with its component and asset bindings.

    Read-only; no side effects. Use when you already have a ``capability_id``
    (e.g. from ``list_capabilities``) and need its full detail; to enumerate
    all capabilities of a model, use ``list_capabilities`` instead.

    Args:
        model_id: ID of the threat model the capability belongs to.
        capability_id: ID of the capability to fetch.

    Returns the capability with its bound components and assets.
    """
    try:
        return _dump(await _get_client().get_capability(model_id, capability_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_coverage(server_version: str, model_id: str) -> dict:
    """Get the full functional coverage report for a model.

    Read-only; no side effects. Returns per-objective state (verified /
    covered / failing / untested), the Capabilities × Conditions matrix, and
    the applicable / missing-objective / not-applicable cell accounting. This
    is the complete picture; when you only need the actionable subset (what to
    implement or fix next), use ``check_functional_gaps`` instead.

    Args:
        model_id: ID of the threat model whose functional coverage to report.

    Returns the coverage report (matrix + per-objective states + cell counts).
    """
    try:
        return _dump(await _get_client().get_functional_coverage(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def check_functional_gaps(server_version: str, model_id: str) -> dict:
    """Get the actionable functional gaps for a model.

    Read-only; no side effects. Returns the subset of the coverage report that
    needs action: applicable conditions with no objective yet, and objectives
    that are failing or have no passing test. Use this to decide what to
    implement or fix next; for the complete coverage matrix and all states use
    ``get_functional_coverage`` instead.

    Args:
        model_id: ID of the threat model to analyse for functional gaps.

    Returns the actionable gaps (missing objectives + failing/untested ones).
    """
    try:
        return _dump(await _get_client().get_functional_gaps(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_functional_test(
    server_version: str, model_id: str, description: str,
    functional_objective_ids: str, status: str = "not_implemented",
    component_ids: str = "",
) -> dict:
    """Hand-author a single functional test and map it to one or more objectives. Mutating.

    Generation (generate_functional_objectives) already specifies the tests to implement, so use this only to register an extra test that generation did not produce; a manually-added test survives regeneration/refresh. For bulk-registering tests that already exist in your codebase, use import_functional_tests instead. This records the test at the status you claim — it does not run or verify anything; CI verification happens only when you attach TEST_EXISTS/TEST_PASSES evidence via submit_functional_test_assertions.

    Args:
        model_id: ID of the threat model.
        description: What the test proves.
        functional_objective_ids: Comma-separated objective ids the test satisfies (at least one required; get them from get_functional_objectives).
        status: not_implemented | implemented | verified — an operator claim only; an independent CI run is what actually verifies the test. Defaults to not_implemented.
        component_ids: Comma-separated component ids the test exercises (optional).
    """
    fo_ids = [x.strip() for x in functional_objective_ids.split(",") if x.strip()]
    comp_ids = [x.strip() for x in component_ids.split(",") if x.strip()]
    if not fo_ids:
        raise ToolError("functional_objective_ids must list at least one objective id.")
    try:
        return _dump(await _get_client().add_functional_test(
            model_id, description, fo_ids, status, comp_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def import_functional_tests(
    server_version: str, model_id: str, tests_json: str,
) -> dict:
    """Register tests that already exist in your codebase against a model's functional objectives, so tests you already have count toward functional conformance — not only Mipiti-specified tests. Mutating (bulk).

    Scan the repo's test suite and pass the tests here. Optionally associate each with the objective ids it covers (from get_functional_objectives); the platform verifies each association is applicable before accepting it and returns any it rejected under ``rejected_mappings``. A test with no (or a rejected) association is still imported, unmapped, so it can be associated later (see suggest_functional_test_mappings / associate_functional_test). For a single hand-authored test, use add_functional_test instead.

    Args:
        model_id: ID of the threat model.
        tests_json: A JSON array of test objects. Each object supports ``test_name``, ``file_path``, ``framework``, ``description``, ``status`` (not_implemented | implemented | verified — an operator claim; an independent CI run is what verifies it), and ``functional_objective_ids`` (list of objective ids the test covers). At least ``test_name`` or ``description`` is required per test; the rest are optional.
    """
    try:
        tests = json.loads(tests_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ToolError(f"tests_json must be a JSON array: {exc}") from exc
    if not isinstance(tests, list) or not tests:
        raise ToolError("tests_json must be a non-empty JSON array of test objects.")
    try:
        return _dump(await _get_client().import_functional_tests(model_id, tests))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def suggest_functional_test_mappings(
    server_version: str, model_id: str, test_ids: str = "",
) -> dict:
    """Suggest which functional objectives each imported test likely covers.

    For unmapped tests (imported without an association, or added without
    objective ids), this proposes objective mappings so you can review and
    apply them with associate_functional_test. It only suggests — nothing is
    associated until you confirm.

    Args:
        model_id: ID of the threat model.
        test_ids: Comma-separated functional-test ids to map. Empty means every
            currently-unmapped test.
    """
    ids = [x.strip() for x in test_ids.split(",") if x.strip()]
    try:
        return _dump(
            await _get_client().suggest_functional_test_mappings(model_id, ids)
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def associate_functional_test(
    server_version: str, model_id: str, functional_test_id: str,
    functional_objective_ids: str,
) -> dict:
    """Associate a functional test with one or more functional objectives.

    Use this after suggest_functional_test_mappings, or to hand-map a test to
    the objectives it covers. The platform verifies each association is
    applicable before accepting it and returns any it declined under
    ``rejected_mappings``.

    Args:
        model_id: ID of the threat model.
        functional_test_id: The functional test to associate.
        functional_objective_ids: Comma-separated objective ids the test covers.
    """
    fo_ids = [x.strip() for x in functional_objective_ids.split(",") if x.strip()]
    if not fo_ids:
        raise ToolError("functional_objective_ids must list at least one objective id.")
    try:
        return _dump(await _get_client().associate_functional_test(
            model_id, functional_test_id, fo_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_satisfaction_groups(
    server_version: str, model_id: str, functional_objective_id: str,
) -> dict:
    """Read the satisfaction-group structure for a functional objective. Read-only; no side effects.

    A satisfaction group is a set of functional tests that together satisfy the objective: AND within a group (every test in the group must be verified), OR across groups (any one complete group satisfies the objective). Returns the current numbered groups plus any tests associated with the objective but not placed in a group.

    Use before set_functional_satisfaction_groups to see the current structure, or to trace why an objective is / isn't satisfied. This is the functional analog of get_control_assumption_groups / get_mitigation_groups.

    Args:
        model_id: ID of the threat model.
        functional_objective_id: The objective whose groups to read.
    """
    try:
        return _dump(await _get_client().get_functional_satisfaction_groups(
            model_id, functional_objective_id,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def set_functional_satisfaction_groups(
    server_version: str, model_id: str, functional_objective_id: str,
    groups_json: str, ungrouped: str = "",
) -> dict:
    """Declaratively set (replace) a functional objective's satisfaction groups. Mutating.

    Replaces the objective's group structure wholesale. Each group is a set of functional tests that together satisfy the objective (AND within a group); the objective counts as satisfied when any one complete group has all its tests verified (OR across groups). Tests you want to keep associated with the objective but outside any group go in ``ungrouped``. Unlike set_control_assumption_groups, there is no AI relevance gate — the structure you submit is applied as-is. Read the current state first with get_functional_satisfaction_groups.

    Args:
        model_id: ID of the threat model.
        functional_objective_id: The objective whose groups to set.
        groups_json: JSON object mapping group label to a list of functional test ids, e.g. ``{"1": ["FT-1", "FT-2"], "2": ["FT-3"]}``. Pass ``{}`` to clear all groups.
        ungrouped: Comma-separated functional-test ids to keep associated with the objective but unassigned to any group (optional).
    """
    try:
        groups = json.loads(groups_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ToolError(f"groups_json must be a JSON object: {exc}") from exc
    if not isinstance(groups, dict):
        raise ToolError("groups_json must be a JSON object of {label: [test ids]}.")
    ungrouped_ids = [x.strip() for x in ungrouped.split(",") if x.strip()]
    try:
        return _dump(await _get_client().set_functional_satisfaction_groups(
            model_id, functional_objective_id, groups, ungrouped_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_test_sufficiency(
    server_version: str, model_id: str, functional_test_id: str,
) -> dict:
    """Read the sufficiency verdict for a functional test. Read-only; no side effects.

    Reports whether the test's attached evidence adequately proves the objective(s) it is associated with, together with the reasoning behind the verdict. This is the functional-conformance analog of get_sufficiency (which covers security controls). The verdict is computed asynchronously after evidence is submitted, so it may read as pending or absent until evaluation completes.

    Args:
        model_id: ID of the threat model.
        functional_test_id: The functional test to assess.
    """
    try:
        return _dump(await _get_client().get_functional_test_sufficiency(
            model_id, functional_test_id,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_cwe_catalog(server_version: str) -> dict:
    """Get the platform's CWE reference catalog status.

    Returns ``{enabled, current_version, entry_count, versions}``. When CWE
    classification is not turned on for this instance, ``enabled`` is false
    and the rest is empty — this is a normal informational response, not an
    error.
    """
    try:
        return await _get_client().get_cwe_catalog()
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_model_cwe_tags(server_version: str, model_id: str) -> dict:
    """List CWE weakness classifications tagged onto a model's control objectives.

    Each tag's name/description are resolved from the platform's CWE catalog,
    never model-authored. A tag whose CWE id has since been deprecated,
    redefined, or removed by MITRE carries a ``stale`` reason (``missing`` /
    ``deprecated`` / ``changed``) — re-run ``classify_model_cwe`` to refresh
    it. 404s if CWE classification is not enabled on this instance.

    Args:
        model_id: ID of the threat model to inspect.
    """
    try:
        return await _get_client().get_model_cwe_tags(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def classify_model_cwe(
    server_version: str, model_id: str, force: bool = False,
) -> dict:
    """Classify a model's control objectives against the platform CWE catalog.

    Grounded: the model may only select from the catalog's current-version
    candidate ids, and every returned id is re-validated against the catalog
    before storage — a hallucinated or deprecated id is never persisted.
    Skips control objectives already tagged at the catalog's current version
    unless ``force`` is set. Returns a summary:
    ``{status, catalog_version, cos, classified, tags_written, skipped}``.
    404s if CWE classification is not enabled on this instance.

    Args:
        model_id: ID of the threat model to classify.
        force: re-classify control objectives even if already tagged at the
            catalog's current version (default false).
    """
    try:
        return await _get_client().classify_model_cwe(model_id, force=force)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_entity(
    server_version: str,
    model_id: str,
    entity_type: str,
    entity_id: str,
) -> dict:
    """Get a single entity of any core type by ID. Read-only.

    Dispatches on ``entity_type`` to the per-type read and returns that
    type's native record as-is (not wrapped in an array):

    - ``asset`` — the asset's typed fields. Soft-deleted assets carry
      ``deleted: true``; the caller decides whether to surface them.
      ``entity_id`` e.g. ``A-01``.
    - ``attacker`` — the attacker with its factor decomposition.
      Soft-deleted attackers carry ``deleted: true``. ``entity_id`` e.g.
      ``T-03``.
    - ``component`` — the component. Speculative components
      (``repo_url=""``) are returned as-is: the empty repo IS the
      lifecycle state, not an error. ``entity_id`` e.g. ``CMP-01``.
    - ``trust_boundary`` — the boundary incl. its ``passes`` set
      (closed-vocabulary subset of
      ``{Network, Adjacent, Local, Physical}``). ``entity_id`` e.g.
      ``TB-Net``.
    - ``assumption`` — the assumption with its override applied (mirrors
      ``list_assumptions``' merge for one entity: typed fields, the
      structured ``exclusion`` predicate when present, and the override
      layer — status / justification / linked CO IDs / target model).
      Soft-deleted assumptions carry ``deleted: true``. ``entity_id``
      e.g. ``AS-01``.

    Args:
        model_id: ID of the threat model.
        entity_type: Which entity to read — one of ``asset``,
            ``attacker``, ``component``, ``trust_boundary``,
            ``assumption``.
        entity_id: ID of the entity to fetch.
    """
    if entity_type not in {"asset", "attacker", "component", "trust_boundary", "assumption"}:
        raise ToolError(
            f"Unsupported entity_type {entity_type!r}; expected one of: "
            "asset, attacker, component, trust_boundary, assumption."
        )
    try:
        client = _get_client()
        getter = {
            "asset": client.get_asset,
            "attacker": client.get_attacker,
            "component": client.get_component,
            "trust_boundary": client.get_trust_boundary,
            "assumption": client.get_assumption,
        }[entity_type]
        return _dump(await getter(model_id, entity_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def remove_entity(
    server_version: str,
    model_id: str,
    entity_type: str,
    entity_id: str,
) -> dict:
    """Soft-delete a single entity of any core type. Mutating: creates a
    new model version. Reversible with ``restore_entity`` using the same
    ``entity_type`` — the entity's ID is preserved (never reused) so a
    restore reinstates the same ID and all its links. To change an
    entity's fields instead of removing it, use the typed ``edit_*`` tool.

    Dispatches on ``entity_type``. Per-type consequence (all derived at
    read time; nothing is hard-destroyed):

    - ``asset`` — the asset's (asset × attacker) CO pairs are tombstoned,
      orphaning any controls mapped to them.
    - ``attacker`` — control objectives anchored to this attacker are
      tombstoned; controls left with no live anchor become orphaned.
    - ``component`` — controls scoped to this component have their
      ``component_id`` cleared (the controls themselves are kept) and the
      component's trust-boundary contribution to asset reachability is
      withdrawn.
    - ``trust_boundary`` — reachability widens: attacker vectors the
      boundary was filtering now pass freely and its ``sealed``/isolation
      claim is dropped, so CO reachability verdicts past it can flip
      toward reachable/indeterminate.
    - ``assumption`` — marked deleted (kept for the audit trail); linked
      COs are no longer mitigated by it; controls with ``assumed_by``
      pointing to it are preserved as inert pointers that reconnect on
      restore.

    Args:
        model_id: ID of the threat model.
        entity_type: Which entity to soft-delete — one of ``asset``,
            ``attacker``, ``component``, ``trust_boundary``,
            ``assumption``.
        entity_id: ID of the entity to soft-delete.
    """
    if entity_type not in {"asset", "attacker", "component", "trust_boundary", "assumption"}:
        raise ToolError(
            f"Unsupported entity_type {entity_type!r}; expected one of: "
            "asset, attacker, component, trust_boundary, assumption."
        )
    try:
        client = _get_client()
        remover = {
            "asset": client.remove_asset,
            "attacker": client.remove_attacker,
            "component": client.remove_component,
            "trust_boundary": client.remove_trust_boundary,
            "assumption": client.remove_assumption,
        }[entity_type]
        return _dump(await remover(model_id, entity_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def restore_entity(
    server_version: str,
    model_id: str,
    entity_type: str,
    entity_id: str,
) -> dict:
    """Un-soft-delete a single entity of any core type, reversing a prior
    ``remove_entity``. Mutating: creates a new model version. Only affects
    an entity that is currently soft-deleted.

    Dispatches on ``entity_type``. Per-type effect:

    - ``asset`` — revives the asset's tombstoned (asset × attacker) COs
      with their original IDs, un-orphaning any linked controls.
    - ``attacker`` — reinstates the attacker under its original ID,
      revives the COs tombstoned when it was removed, and un-orphans any
      controls that were anchored to it.
    - ``component`` — reinstates the component under its original ID,
      restoring its trust-boundary contribution to asset reachability.
    - ``trust_boundary`` — reinstates the boundary: the reachability it
      filtered re-narrows and its ``sealed``/isolation claim is restored,
      so CO reachability verdicts past it can flip back toward
      unreachable.
    - ``assumption`` — returns the assumption to active status; controls
      whose ``assumption_groups`` referenced it keep their group
      structure intact. Re-attestation is required before it mitigates
      COs again.

    Args:
        model_id: ID of the threat model.
        entity_type: Which entity to restore — one of ``asset``,
            ``attacker``, ``component``, ``trust_boundary``,
            ``assumption``.
        entity_id: ID of the entity to restore.
    """
    if entity_type not in {"asset", "attacker", "component", "trust_boundary", "assumption"}:
        raise ToolError(
            f"Unsupported entity_type {entity_type!r}; expected one of: "
            "asset, attacker, component, trust_boundary, assumption."
        )
    try:
        client = _get_client()
        restorer = {
            "asset": client.restore_asset,
            "attacker": client.restore_attacker,
            "component": client.restore_component,
            "trust_boundary": client.restore_trust_boundary,
            "assumption": client.restore_assumption,
        }[entity_type]
        return _dump(await restorer(model_id, entity_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_risk_view(
    server_version: str,
    scope: Literal["model", "system", "tag"],
    scope_id: str,
) -> dict:
    """Prioritized Risk View — one row per live Control Objective — at a chosen scope. Read-only; no side effects.

    ``scope`` selects the aggregation boundary and how ``scope_id`` is interpreted:

    - ``"model"`` — a single threat model (``scope_id`` = model id). One row per live CO with derived risk tier, asset impact, attacker likelihood, control coverage counts (``coverage_ratio``), and open-finding count (``open_findings``). Tombstoned COs are excluded; pair with ``get_threat_model`` if historical context is needed. Use to triage which COs need attention on one model — a single call ranks the work, no per-CO fan-out.
    - ``"system"`` — every model in a System, a group of related threat models (``scope_id`` = system id). Same row shape as ``model`` with ``model_id`` and ``model_title`` added per row, so rows can be grouped/filtered by source model without an extra lookup. Use for posture queries spanning multiple models in the same product or service.
    - ``"tag"`` — every member model of a tag, a freely-composed cohort (``scope_id`` = tag id). One delegation-aware row per CO across members (``delegation_mitigated`` / ``delegating_controls``): a CO mitigated via a verified cross-model delegation reads as covered, consistent with each model's own assessment. Use for a portfolio/audit-scope posture rollup.

    Args:
        scope: aggregation boundary — "model", "system", or "tag".
        scope_id: id of the model, system, or tag selected by ``scope``.
    """
    if scope not in ("model", "system", "tag"):
        raise ToolError("scope must be 'model', 'system', or 'tag'.")
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.get_model_risk_view(scope_id))
        if scope == "system":
            return _dump(await client.get_system_risk_view(scope_id))
        return _dump(await client.get_tag_risk_view(scope_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_compliance_report(
    server_version: str,
    scope: Literal["model", "system", "tag"],
    scope_id: str,
    framework_id: str,
    level: Optional[int] = None,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Compliance gap-analysis report for one framework at a chosen scope. Read-only; no side effects. System/tag scopes require PRO tier.

    Evaluates every framework requirement against the mapped controls in scope and classifies each as covered, partial, uncovered, unmapped, or excluded, then returns coverage counts plus per-requirement rows. The framework must first be activated at the same scope via ``select_compliance_frameworks`` (with the matching ``scope``), otherwise there is nothing to report on.

    ``scope`` selects the boundary and how ``scope_id`` is read:

    - ``"model"`` — a single threat model (``scope_id`` = model id).
    - ``"system"`` — rolled up across every model in a System, a group of related threat models (``scope_id`` = system id).
    - ``"tag"`` — rolled up across every member model of a tag cohort, a freely-composed set of models (``scope_id`` = tag id).

    Filtering / pagination:

    - ``level`` — level filter for level-aware frameworks; returns only requirements at or below this level (e.g. 1 for L1 only). Omit (or 0) for all levels. Honored for all scopes.
    - ``status`` — one of "covered", "partial", "uncovered", "unmapped", "excluded"; empty = all statuses. **Model and system scopes only.**
    - ``offset`` / ``limit`` — per-requirement row pagination; offset skips the first N rows, limit caps rows returned (0 = no explicit limit). **Model and system scopes only.**

    A tag report is neither paginated nor status-filtered; passing ``status``, ``offset``, or ``limit`` with ``scope="tag"`` raises an error rather than silently returning unfiltered rows.

    Args:
        scope: report boundary — "model", "system", or "tag".
        scope_id: id of the model, system, or tag selected by ``scope``.
        framework_id: framework to report on (already selected at this scope; see ``list_compliance_frameworks``).
        level: optional level filter; omit for all levels.
        status: optional per-requirement status filter (model/system scopes only).
        offset: skip the first N requirement rows, pagination (model/system scopes only). Default 0.
        limit: max requirement rows to return, 0 = no explicit limit (model/system scopes only).
    """
    if scope not in ("model", "system", "tag"):
        raise ToolError("scope must be 'model', 'system', or 'tag'.")
    if scope == "tag" and (status or offset or limit):
        raise ToolError(
            "status/offset/limit are supported only for scope='model' or 'system'; "
            "tag compliance reports are not paginated or status-filtered."
        )
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.get_compliance_report(
                scope_id, framework_id, level, status or "", offset, limit,
            ))
        if scope == "system":
            return _dump(await client.get_system_compliance_report(
                scope_id, framework_id, level, status or "", offset, limit,
            ))
        return _dump(await client.get_tag_compliance_report(
            scope_id, framework_id, level if level is not None else 0,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def select_compliance_frameworks(
    server_version: str,
    scope: Literal["model", "system", "tag"],
    scope_id: str,
    framework_ids: str,
) -> dict:
    """Select (activate) compliance frameworks at a chosen scope. Requires PRO tier. Mutating.

    Discover valid ids with ``list_compliance_frameworks`` (or add a custom one via ``import_compliance_framework``); view the resulting gap analysis with ``get_compliance_report`` at the same ``scope``. Re-calling replaces the scope's framework selection.

    ``scope`` selects the target and how ``scope_id`` is read:

    - ``"model"`` — a single threat model (``scope_id`` = model id). Activating a framework also kicks off background auto-remediation: it auto-maps existing controls to requirements, excludes non-applicable requirements by taxonomy, and suggests/applies new entities for the remaining gaps. The response includes ``auto_remediate_jobs``, which run and complete on their own; re-trigger later with ``auto_remediate_compliance`` if the model changes.
    - ``"system"`` — a System, i.e. a group of related threat models (``scope_id`` = system id). Sets the system's active frameworks for portfolio-level compliance reporting.
    - ``"tag"`` — a tag cohort (``scope_id`` = tag id). Records the frameworks against the tag AND propagates them to every member model, making the tag a compliance scope (e.g. an audit boundary) spanning several models.

    Args:
        scope: target boundary — "model", "system", or "tag".
        scope_id: id of the model, system, or tag selected by ``scope``.
        framework_ids: comma-separated framework ids (e.g. "asvs-4.0,nist-csf").
    """
    if scope not in ("model", "system", "tag"):
        raise ToolError("scope must be 'model', 'system', or 'tag'.")
    parsed_ids = [f.strip() for f in framework_ids.split(",") if f.strip()]
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.select_compliance_frameworks(scope_id, parsed_ids))
        if scope == "system":
            return _dump(await client.select_system_compliance_frameworks(scope_id, parsed_ids))
        return _dump(await client.select_tag_compliance_frameworks(scope_id, parsed_ids))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def export_report(
    server_version: str,
    scope: Literal["model", "tag"],
    scope_id: str,
    ctx: Context,
    format: Literal["csv", "pdf", "html", "archive"] = "csv",
) -> dict:
    """Export a threat model or a tag cohort as a downloadable document. Read-only; no side effects on the source.

    ``scope`` selects what is exported and how ``scope_id`` is read; ``format`` selects the representation:

    - ``scope="model"`` (``scope_id`` = model id) supports ``format`` ∈ {``csv``, ``pdf``, ``html``, ``archive``}:
        - ``csv`` — the model's current state rendered as CSV; returned inline as UTF-8 text in ``content``.
        - ``pdf`` / ``html`` — rendered document returned base64-encoded in ``content_b64`` (with ``content_type``). Runs as a server-side job; progress is reported automatically while it completes, which may take time for large models.
        - ``archive`` — the self-contained, independently-verifiable JSON audit bundle: every version, controls, assertions (with Tier 1 / Tier 2 verdicts and attested flags), findings, risk acceptances, assumption overrides, attestations, and instance sufficiency signatures. Returned as ``{..., "envelope": <dict>}``; feed the envelope to ``import_threat_model_archive`` to restore it into any workspace. **Model scope only.**
    - ``scope="tag"`` (``scope_id`` = tag id) supports only ``format="html"``: the signed auditor report, aggregating every member model's report plus the cross-model dependency graph and attestation status into one HTML document, returned inline in ``content``. ``csv``, ``pdf``, and ``archive`` are rejected for tag scope.

    Args:
        scope: export boundary — "model" or "tag".
        scope_id: id of the model or tag selected by ``scope``.
        format: "csv" (default), "pdf", "html", or "archive". Tag scope requires "html"; "archive" is model-only.

    Returns:
        model csv → ``{scope, scope_id, format, filename, content}`` (inline UTF-8 text).
        model pdf/html → ``{scope, scope_id, format, filename, content_type, content_b64}`` (base64-encoded bytes).
        model archive → ``{scope, scope_id, format, envelope}``.
        tag html → ``{scope, scope_id, format, content}`` (inline HTML).
    """
    if scope not in ("model", "tag"):
        raise ToolError("scope must be 'model' or 'tag'.")
    if format not in ("csv", "pdf", "html", "archive"):
        raise ToolError("format must be 'csv', 'pdf', 'html', or 'archive'.")
    if scope == "tag":
        if format == "archive":
            raise ToolError("format='archive' is model-only; tag scope supports only 'html'.")
        if format != "html":
            raise ToolError("tag scope supports only format='html' (the signed auditor report).")
    try:
        client = _get_client()
        if scope == "tag":
            content = await client.export_tag(scope_id, "html")
            return {"scope": "tag", "scope_id": scope_id, "format": "html", "content": content}
        # scope == "model"
        if format == "archive":
            job_id = await client.start_export_model_full(scope_id)
            await _await_backend_job(client, job_id, ctx)
            content_bytes = await client.fetch_operation_result(job_id)
            envelope = json.loads(content_bytes.decode("utf-8"))
            return {"scope": "model", "scope_id": scope_id, "format": "archive", "envelope": envelope}
        job_id = await client.start_export_model(scope_id, format)
        result = await _await_backend_job(client, job_id, ctx)
        # The backend job result is the file envelope.
        filename = (result or {}).get("filename") or f"threat_model.{format}"
        content_type = (result or {}).get("content_type") or ""
        content_bytes = await client.fetch_operation_result(job_id)
        if format == "csv":
            return {
                "scope": "model",
                "scope_id": scope_id,
                "format": "csv",
                "filename": filename,
                "content": content_bytes.decode("utf-8"),
            }
        import base64 as _b64
        return {
            "scope": "model",
            "scope_id": scope_id,
            "format": format,
            "filename": filename,
            "content_type": content_type or (
                "application/pdf" if format == "pdf" else "text/html"
            ),
            "content_b64": _b64.b64encode(content_bytes).decode("ascii"),
        }
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def list_groups(server_version: str, kind: str) -> dict:
    """List the workspace's groups of a given kind. Read-only; no side effects.

    A \"group\" is a named collection of threat models. Two kinds, with distinct
    semantics and DIFFERENT response shapes:

    ``kind`` values:
      - ``\"tag\"``: overlapping, semantics-free groupings — for audit scopes,
        ad-hoc selections, or portfolios. A model may carry many tags, and a
        tag never affects posture or credit. Returns ``{\"tags\": [...]}``.
      - ``\"system\"``: named groupings of threat models for portfolio-level
        risk and compliance reporting; unlike tags these drive system-scoped
        risk/compliance rollups. Returns ``{\"items\": [<system>, ...]}`` where
        each system carries ``id``, ``name``, ``description``, ``model_count``.

    Discover group IDs here before the group risk/compliance/export tools or
    before adding/removing members. For a single model's tag memberships use
    ``list_model_groups``.

    Args:
        kind: ``\"tag\"`` or ``\"system\"``.
    """
    if kind not in ("tag", "system"):
        raise ToolError("kind must be 'tag' or 'system'.")
    try:
        client = _get_client()
        if kind == "tag":
            return await client.list_tags()
        return _dump(await client.list_systems())
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def create_group(
    server_version: str,
    kind: str,
    name: str,
    description: str = "",
    model_ids: list[str] | None = None,
) -> dict:
    """Create a group (tag or system), optionally seeding tag members. Mutating.

    A \"group\" is a named collection of threat models. Group names are unique
    per workspace within their kind.

    ``kind`` values:
      - ``\"tag\"``: an overlapping, semantics-free grouping — for viewing/
        reporting without asserting any relationship between members and
        without moving credit. Honors ``model_ids`` as an initial member seed.
        Returns the created tag.
      - ``\"system\"``: a named grouping for portfolio-level risk and compliance
        reporting. Systems are NOT seeded at creation — ``model_ids`` must be
        omitted/empty for ``kind=\"system\"`` (passing members raises); add them
        afterward with ``add_model_to_group(kind=\"system\", ...)``. Returns the
        created system with its new ID.

    Args:
        kind: ``\"tag\"`` or ``\"system\"``.
        name: the group name (unique within the workspace for its kind).
        description: optional description.
        model_ids: optional initial member model ids — ``\"tag\"`` only.
    """
    if kind not in ("tag", "system"):
        raise ToolError("kind must be 'tag' or 'system'.")
    if kind == "system" and model_ids:
        raise ToolError(
            "model_ids seeding is only supported for kind='tag'. Create the "
            "system first, then add members with "
            "add_model_to_group(kind='system', ...).",
        )
    try:
        client = _get_client()
        if kind == "tag":
            return await client.create_tag(name, description, model_ids or [])
        return _dump(await client.create_system(name, description))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def add_model_to_group(
    server_version: str, kind: str, group_id: str, model_id: str,
) -> dict:
    """Add a threat model to a group as a member. Mutating.

    Links the model into the group without moving or copying it — the model
    stays independently editable. Both the group and the model must already
    exist.

    ``kind`` values:
      - ``\"tag\"``: add the model to a tag. Membership is overlapping — a model
        may belong to many tags. Returns the updated tag payload.
      - ``\"system\"``: add the model to a system container for portfolio-level
        risk and compliance reporting. Returns an ok result.

    Note: member REMOVAL is tag-only (see ``remove_model_from_group``); the
    API has no remove-member endpoint for systems.

    Args:
        kind: ``\"tag\"`` or ``\"system\"``.
        group_id: ID of the tag or system.
        model_id: ID of the threat model to add.
    """
    if kind not in ("tag", "system"):
        raise ToolError("kind must be 'tag' or 'system'.")
    try:
        client = _get_client()
        if kind == "tag":
            return await client.add_model_to_tag(group_id, model_id)
        return _dump(await client.add_model_to_system(group_id, model_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_group(server_version: str, system_id: str) -> dict:
    """Get a system group by ID, including summaries of its member threat models. Read-only; no side effects.

    Single-group fetch is supported for SYSTEMS ONLY — tags have no
    fetch-by-id endpoint; enumerate tags with ``list_groups(kind=\"tag\")`` and
    a single model's tag memberships with ``list_model_groups``. A system is a
    named grouping of threat models for portfolio-level risk and compliance
    reporting. Discover system IDs with ``list_groups(kind=\"system\")``; add
    members with ``add_model_to_group(kind=\"system\", ...)``.

    Args:
        system_id: ID of the system to retrieve.
    """
    try:
        return _dump(await _get_client().get_system(system_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def delete_group(server_version: str, tag_id: str) -> dict:
    """Delete a tag group (the grouping only; member models are not affected).

    Deletion is supported for TAGS ONLY — systems have no delete endpoint on
    this API. A tag is an overlapping, semantics-free grouping; removing it
    leaves its member models untouched.

    Args:
        tag_id: ID of the tag to delete.
    """
    try:
        await _get_client().delete_tag(tag_id)
        return {"deleted": True, "tag_id": tag_id}
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def remove_model_from_group(
    server_version: str, tag_id: str, model_id: str,
) -> dict:
    """Remove a model from a tag group (the model itself is not deleted).

    Member removal is supported for TAGS ONLY — systems have no remove-member
    endpoint on this API (a model added to a system via
    ``add_model_to_group(kind=\"system\", ...)`` cannot be detached through
    this client). Removing a model from a tag leaves the model untouched.

    Args:
        tag_id: the tag.
        model_id: the model to remove.
    """
    try:
        await _get_client().remove_model_from_tag(tag_id, model_id)
        return {"removed": True, "tag_id": tag_id, "model_id": model_id}
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def list_model_groups(server_version: str, model_id: str) -> dict:
    """List the groups a given model belongs to. Read-only; no side effects.

    Returns the model's TAG memberships (``/api/models/{id}/tags``) — tags are
    the overlapping grouping kind, so a model may appear under many. There is
    no per-model listing for systems; enumerate systems with
    ``list_groups(kind=\"system\")`` and inspect membership via each system's
    ``get_group``. Use ``list_groups(kind=\"tag\")`` for all tags in the
    workspace.

    Args:
        model_id: the model whose groups (tags) to list.
    """
    try:
        return await _get_client().list_model_tags(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def link_system_dependency(
    server_version: str,
    model_id: str,
    assumption_id: str,
    target_model_id: str = "",
) -> dict:
    """Link an external assumption to a target model in the same system.

    Makes the assumption a cross-model (system-scoped) dependency: it becomes a
    compliance requirement on the target model. Two independent satisfaction
    paths: auto-attestation when the target model's controls satisfy the
    requirement (no manual action needed), or manual attestation via
    submit_attestation. Either path alone suffices.

    The assumption must already be linked to control objectives (via
    add_assumption or edit_assumption with linked_co_ids). Pass empty
    target_model_id to unlink. Inspect the resulting dependency graph with
    get_system_dependencies.

    Args:
        model_id: ID of the threat model containing the assumption.
        assumption_id: ID of the assumption (e.g., \"AS1\").
        target_model_id: ID of the target model in the same system.
            Pass \"\" to unlink.
    """
    try:
        return _dump(await _get_client().link_assumption(
            model_id, assumption_id, target_model_id,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_reachability_verdicts(
    server_version: str,
    model_id: str,
    composed: bool = False,
    co_id: str = "",
    page: int = 1,
    page_size: int = 100,
    kind_filter: str | None = None,
) -> dict:
    """Per-CO reachability verdicts for a model — flat or composed topology.

    ``composed`` selects which topology the verdicts are derived over:

      - ``composed=False`` (default) — FLAT: verdicts over THIS model's own
        structural primitives only (components, asset.component_ids,
        trust_boundary.passes, attacker.trust_boundary_ids + attack_vector,
        Assumption.exclusion predicates). Pure derivation, NOT persisted on
        the CO — re-running against the model JSON is deterministic, the
        verification an auditor performs. Pass ``co_id`` to retrieve a
        single verdict (skips the cross-CO loop); ``page`` / ``page_size`` /
        ``kind_filter`` are ignored in this mode. Returns ``{model_id,
        model_version, verdicts: [...]}`` where each verdict carries
        ``co_id``, ``kind`` ("reachable" | "unreachable" |
        "indeterminate"), ``reason`` (structural label:
        ``boundary_blocks_vector`` / ``assumption_excludes`` /
        ``attacker_unpositioned`` / ``asset_unbounded`` /
        ``no_shared_boundary`` / ``missing_entity``), ``narration``, and
        (when applicable) ``boundary_id`` / ``assumption_id``.

      - ``composed=True`` — COMPOSED: the same verdict semantics evaluated
        over the merged effective tree (own components and trust boundaries
        combined with everything inherited from ancestors, qualified ids for
        cross-model references). Use this when the model is a child on the
        composition tree and you need reach state that reflects the ancestor
        topology, not just the local model document. Paginated via ``page``
        / ``page_size`` and filterable via ``kind_filter``; ``co_id`` is
        ignored (the composed surface has no single-CO lookup). Returns
        ``{model_id, flag_enabled, verdicts: [{co_qid, asset_qid,
        attacker_qid, kind, reason}, ...], total, page, page_size}``. When
        composition is disabled on the backend, ``verdicts`` is empty and
        ``flag_enabled: false`` — fall back to ``composed=False`` for the
        per-model derivation.

    When a flat verdict is indeterminate, address the gap via the standard
    model-edit affordances:
      - ``attacker_unpositioned`` → ``edit_attacker`` setting
        ``trust_boundary_ids``
      - ``asset_unbounded`` → ``assign_to_components (target_type="asset")`` or
        ``edit_asset`` with ``component_ids``
      - ``no_shared_boundary`` → re-position attacker, re-scope asset, OR
        ``add_assumption`` with structured exclusion
      - ``missing_entity`` → restore the missing asset/attacker, or remove
        the orphaned CO

    Use this before relying on per-CO reach state for triage,
    auto-remediation, or audit responses. The ``model_coherence_report``
    tool surfaces the same gaps as actionable findings; this tool exposes
    the raw verdicts when you need the structured data (boundary_id
    citations, narration strings) that the findings summarize.

    Args:
        model_id: ID of the threat model.
        composed: When False (default), derive over this model's own
            topology (flat). When True, derive over the composed effective
            tree (own ⊕ inherited).
        co_id: FLAT mode only. Optional CO id — when set, returns a single
            verdict; 404 if the CO doesn't exist or is tombstoned. Ignored
            when ``composed=True``.
        page: COMPOSED mode only. 1-indexed page number (default ``1``).
            Ignored when ``composed=False``.
        page_size: COMPOSED mode only. Verdicts per page (default ``100``).
            Ignored when ``composed=False``.
        kind_filter: COMPOSED mode only. Restrict verdicts to one kind —
            one of ``"reachable" | "unreachable" | "indeterminate"``. Named
            ``kind_filter`` (not ``kind``) to disambiguate from the verdict
            object's own ``kind`` field. When omitted, all verdict kinds are
            returned. Ignored when ``composed=False``.
    """
    try:
        if composed:
            return _dump(
                await _get_client().composition_reachability(
                    model_id,
                    page=page,
                    page_size=page_size,
                    kind_filter=kind_filter,
                ),
            )
        return _dump(
            await _get_client().model_reachability_verdicts(model_id, co_id=co_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def recompute_verdicts(
    server_version: str,
    model_id: str,
    dry_run: bool = False,
) -> dict:
    """Re-run coverage and group-sufficiency verdict evaluation for a model,
    or return the pre-flight cost estimate without enqueueing anything.

    ``dry_run`` selects between enqueueing the recompute and a cost-only
    quote:

      - ``dry_run=False`` (default) — ENQUEUE: force a fresh evaluation of
        every control's coverage verdict and every live control objective's
        group-sufficiency verdict, bypassing the normal quiet-period
        batching. Evaluation runs in the background; re-read the model's
        divergence report (or coverage surfaces) shortly after to see
        updated verdicts. The response carries ``estimated_credits`` — an
        informational estimate; nothing is charged from it, actual usage is
        metered as the evaluation runs, per the account's plan. Returns
        ``{model_id, model_version, enqueued_coverage,
        enqueued_group_sufficiency, total_enqueued, estimated_credits,
        quote, governor}``. When ``governor.exhausted`` is true the work is
        queued and resumes automatically at ``governor.resets_at`` — it is
        never dropped.

      - ``dry_run=True`` — QUOTE ONLY: return the informational pre-flight
        cost estimate and enqueue NOTHING. Nothing is charged from the
        estimate. It carries ``computed_at`` and the pricing ``rate_version``
        in force so a stale quote is detectable. Returns
        ``{estimated_credits, computed_at, rate_version, informational,
        total_enqueueable, already_evaluated, governor}``, where
        ``total_enqueueable`` is the number of jobs a recompute would enqueue
        and ``already_evaluated`` counts subjects that already carry a
        verdict (a portion short-circuit without cost, so the estimate is an
        upper bound). When ``governor.exhausted`` is true, new evaluation
        would be queued until ``governor.resets_at``.

    **Scope — what this does NOT do.** It evaluates control-objective
    COVERAGE and GROUP SUFFICIENCY only. It does not evaluate per-control
    sufficiency (whether a control's assertions cover its description) and
    it does not evaluate assertion coherence — both of those are computed
    on assertion write and read back with ``get_sufficiency`` /
    ``get_verification_report``. So a control sitting at
    ``partially_verified``, or an assertion showing
    ``coherence_status: "pending"``, is NOT a reason to call this tool: the
    verdict you want already exists, and recomputing spends credits without
    changing it. Reach for this only when control-to-CO MAPPINGS look wrong
    (see ``get_verdict_divergence``).

    Cost: this fans out across every control and live control objective, so
    on a large model the estimate can run to thousands of credits. Call it
    with ``dry_run=True`` first and surface the number to the operator
    before enqueueing.

    Both modes return a 503-mapped error when verdict observability is
    unavailable on the deployment. To un-park verdicts stuck by a transient
    outage instead of force-enqueueing the whole model, use
    ``retry_verdicts``.

    Args:
        model_id: ID of the threat model to re-evaluate (or estimate for).
        dry_run: When True, return only the pre-flight estimate and enqueue
            nothing. When False (default), enqueue the recompute.
    """
    try:
        if dry_run:
            return _dump(await _get_client().get_recompute_quote(model_id))
        return _dump(await _get_client().recompute_verdicts(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def list_reconciliation_candidates(
    server_version: str,
    model_id: str,
    disposition: str = "active",
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """Reconciliation triage surface between this model and its ancestors.

    When a model inherits entities (assets, attackers, components, trust
    boundaries) from an ancestor *and* the operator has authored a
    locally-named entity that looks like the same real-world thing, the
    reconciliation engine pairs them so the operator can decide whether to
    alias the local entity onto the inherited qualified id. ``disposition``
    selects which side of the triage queue to read:

      - ``disposition="active"`` (default) — the OPEN candidate queue:
        detected pairs the operator has not yet acted on. Tier ``certain``
        is a deterministic match (same qid or structurally identical) and is
        safe to auto-apply via ``apply_certain_reconciliation_match``; tier
        ``heuristic`` is a fuzzy name/description match that needs review.
        Previously-rejected pairs are filtered out of this queue. Paginated
        via ``page`` / ``page_size``. Returns ``{model_id, flag_enabled,
        total, tiers: {certain: int, heuristic: int}, page, page_size,
        candidates: [{kind, own_qid, inherited_qid, tier:
        "certain"|"heuristic", reasons: [str, ...]}, ...]}``. When
        composition is disabled on the backend, ``total`` is 0,
        ``candidates`` is empty, and ``flag_enabled: false``.

      - ``disposition="rejected"`` — the operator's persisted "these are NOT
        duplicates" decisions, in ``rejected_at`` ascending order (the same
        set the candidate detector consults to filter the active queue). Use
        this to render the rejected section of a triage view, or to find the
        surrogate ``id`` needed by ``unreject_reconciliation_candidate``.
        NOT paginated — ``page`` / ``page_size`` are ignored. Returns
        ``{model_id, flag_enabled, rejections: [{id, model_id, kind,
        own_qid, inherited_qid, rejected_by, rejected_at}, ...]}``. When
        composition is disabled on the backend, ``rejections`` is empty and
        ``flag_enabled: false``; the same empty list is returned with
        ``flag_enabled: true`` when the rejection store is not configured on
        the instance.

    Use on child models in a recursive tree to find duplicates that should
    be collapsed before they distort coverage.

    Args:
        model_id: ID of the descendant threat model.
        disposition: Which side of the queue to read — ``"active"``
            (default, open candidates) or ``"rejected"`` (persisted
            not-a-duplicate decisions).
        page: ACTIVE disposition only. 1-indexed page number. Default 1.
            Ignored when ``disposition="rejected"``.
        page_size: ACTIVE disposition only. Items per page. Default 50.
            Ignored when ``disposition="rejected"``.
    """
    if disposition not in ("active", "rejected"):
        raise ToolError("disposition must be one of 'active', 'rejected'.")
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if disposition == "active":
        if page < 1:
            raise ToolError("page must be >= 1")
        if page_size < 1:
            raise ToolError("page_size must be >= 1")
    try:
        if disposition == "rejected":
            return _dump(
                await _get_client().list_reconciliation_rejections(model_id),
            )
        return _dump(
            await _get_client().composition_reconciliation(
                model_id, page=page, page_size=page_size,
            ),
        )
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def preview_undo_composition(
    server_version: str,
    model_id: str,
    event_type: str,
    event_id: str,
) -> dict:
    """Preview the inverse plan (or divergence refusal) for a prior
    composition event WITHOUT mutating any state. Read-only.

    Read-only counterpart to ``undo_composition_event``. Used by the
    confirmation flow so the operator sees what an undo would do before
    committing — either the inverse state operations the apply step will
    commit, or the enumerated reasons the divergence detector refuses the
    undo. Same ``{plan, refusal}`` return shape for both event types.

    Args:
        model_id: The model whose composition view originated the event.
            Must match the ``threat_model_id`` carried by the cited
            activity event; the server rejects with 404 when a caller
            tries to undo a sibling model's event through a different
            model's URL.
        event_type: Which forward composition event to preview undoing.
            One of:
              - ``"lift"``: preview undo of a ``lift_applied`` event. The
                plan block carries the lift inverse operations — tombstone
                the lifted LCA entity, restore the source descendants'
                copies, rewrite CO references.
              - ``"split"``: preview undo of a ``split_applied`` event.
                The plan block carries the split inverse operations —
                restore at the ancestor, tombstone the duplicated copies
                on every target descendant.
        event_id: Either the surrogate id of the forward
            ``lift_applied`` / ``split_applied`` activity event, or the
            structured ``lift_id`` / ``split_id`` carried in the event's
            payload — both lookups are supported.

    Returns::

        {"plan": <UndoPlan> | null,
         "refusal": <UndoRefusal> | null}

    Exactly one of ``plan`` / ``refusal`` is non-null. The plan block
    carries the inverse state operations; the refusal block carries the
    enumerated divergence reasons when state has materially evolved since
    the forward event.

    Errors: 404 if the cited event doesn't exist or belongs to a different
    model; 503 if composition is not available on the backend.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not event_id or not event_id.strip():
        raise ToolError("event_id is required and must be non-empty.")
    kind = (event_type or "").strip().lower()
    if kind not in ("lift", "split"):
        raise ToolError("event_type must be one of: 'lift', 'split'.")
    try:
        client = _get_client()
        if kind == "lift":
            result = await client.preview_lift_undo(model_id, event_id)
        else:
            result = await client.preview_split_undo(model_id, event_id)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def undo_composition_event(
    server_version: str,
    model_id: str,
    event_type: str,
    event_id: str,
) -> dict:
    """Apply the inverse of a previous composition event. Mutating —
    persists inverse state across multiple models.

    Re-runs the divergence detector immediately before applying and
    refuses with 409 + the structured refusal block when state has
    materially evolved since the forward event (assertions submitted on
    the affected entity, downstream COs added that reference it, the
    entity edited, etc.). On success, persists the inverse state
    operations across every affected model and emits a structured
    ``lift_undone`` / ``split_undone`` activity event citing
    ``original_event_id`` so the audit pack can chain undo to its forward.

    Args:
        model_id: The model whose composition view originated the event.
            Must match the cited event's ``threat_model_id`` — the server
            rejects cross-model citations with 404.
        event_type: Which forward composition event to undo. One of:
              - ``"lift"``: undo a ``lift_applied`` event. On success,
                persists the inverse across the LCA + every affected
                source descendant and emits a ``lift_undone`` event. The
                returned ``models`` block carries ``lca_model`` and
                ``source_descendant_models``.
              - ``"split"``: undo a ``split_applied`` event. On success,
                restores the ancestor's entity, tombstones the duplicated
                copies on every target descendant, persists across all
                affected models, and emits a ``split_undone`` event. The
                returned ``models`` block carries ``ancestor_model`` and
                ``descendant_models``.
        event_id: Either the surrogate id of the forward
            ``lift_applied`` / ``split_applied`` activity event, or the
            structured ``lift_id`` / ``split_id`` carried in the event
            payload.

    Returns::

        {"undone_event_id": str,
         "original_event_id": str,
         "applied_state_ops": [...],
         "models": {...}}

    The ``models`` block keys depend on ``event_type`` (see above):
    ``{lca_model, source_descendant_models}`` for ``"lift"``,
    ``{ancestor_model, descendant_models}`` for ``"split"``.

    Errors: 409 with ``detail = {message, refusal: {reasons: [...]}}``
    when the divergence detector refuses; 404 if the cited event doesn't
    exist or belongs to a different model; 400 on payload / event-type
    mismatch; 503 if composition is not available for this deployment.

    Operator pattern: call ``preview_undo_composition`` first with the
    same ``event_type`` / ``event_id``, surface the plan or refusal to the
    operator, and only call this tool after explicit confirmation.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not event_id or not event_id.strip():
        raise ToolError("event_id is required and must be non-empty.")
    kind = (event_type or "").strip().lower()
    if kind not in ("lift", "split"):
        raise ToolError("event_type must be one of: 'lift', 'split'.")
    try:
        client = _get_client()
        if kind == "lift":
            result = await client.undo_lift(model_id, event_id)
        else:
            result = await client.undo_split(model_id, event_id)
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_functional_objectives(
    server_version: str, model_id: str, functional_objective_id: str = "",
) -> dict:
    """List a model's functional objectives, or fetch one by id. Read-only; no side effects.

    A functional objective is a Capability × Condition test plan expressed as a
    Given-When-Then statement. ``functional_objective_id`` selects the behaviour:

    - omitted / empty string -> list every functional objective for the model
      (the full functional test plan).
    - a functional-objective id -> return just that one objective's detail,
      including its capability, condition, Given-When-Then statement, and
      current test state.

    For pass/fail coverage state across all objectives use
    ``get_functional_coverage``; for the actionable gaps use
    ``check_functional_gaps``.

    Args:
        model_id: ID of the threat model whose functional objective(s) to read.
        functional_objective_id: Optional. Omit (or pass "") to list every
            objective; pass an id (from a prior list call) to fetch that one.

    Returns the list of functional objectives, or the single objective when an
    id is given.
    """
    try:
        client = _get_client()
        fo_id = functional_objective_id.strip()
        if fo_id:
            return _dump(await client.get_functional_objective(model_id, fo_id))
        return _dump(await client.list_functional_objectives(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def submit_functional_test_assertions(
    server_version: str, model_id: str, functional_test_id: str,
    assertions_json: str,
) -> dict:
    """Attach machine-verifiable evidence assertions to one already-existing functional test so CI can verify it. Mutating.

    This submits EVIDENCE for a test that already exists (identified by
    functional_test_id) — it does not create or register the test. It is the
    functional-conformance analog of submit_assertions (which covers security
    controls): it binds assertions such as "the test exists" and "the test
    passes" to the functional test, and an independent CI run against the named
    repo is what turns an operator's "verified" claim into verified state.

    To bulk-register test DEFINITIONS from your codebase instead, use
    import_functional_tests; to hand-author a single test use
    add_functional_test. Call this after the test is implemented (e.g. following
    get_scan_prompt (kind="functional")), then read the resulting state via
    get_functional_coverage or get_functional_test_sufficiency.

    Args:
        model_id: ID of the threat model.
        functional_test_id: The already-existing functional test the assertions prove.
        assertions_json: JSON array of assertion objects, each {"type": "test_passes" | "test_exists" | ..., "params": {...}, "description": "...", "repo": "<owner>/<repo>"}. Every assertion must carry an explicit repo, or the "no_repo" sentinel when the check is not tied to a repository.
    """
    try:
        assertions = json.loads(assertions_json)
    except json.JSONDecodeError:
        raise ToolError("assertions_json must be a valid JSON array.")
    if not isinstance(assertions, list):
        raise ToolError("assertions_json must be a JSON array.")
    try:
        return _dump(await _get_client().submit_functional_tests(
            model_id, functional_test_id, assertions,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    control_id: Optional[str] = None,
    version: int = 0,
    status: Optional[str] = None,
    co_id: Optional[str] = None,
    component_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
    include_deleted: bool = False,
    include_orphaned: bool = False,
    summary_only: bool = False,
) -> dict:
    """Get implementation controls for a threat model — list or single-control detail. Read-only (with one list-mode side effect, below).

    Two modes, selected by whether ``control_id`` is set:

    - **List mode** (``control_id`` omitted) — returns the controls that
      should be implemented to satisfy the model's control objectives, as
      ``{"controls": [...], "total": N, "returned": M}``. One side effect:
      if controls have never been generated for this model, the first
      call triggers generation. Generation may finish inline or continue
      in the background — if results look incomplete, poll
      ``get_control_generation_status`` and re-read once it reports
      ``complete``. The filters (``status``, ``co_id``, ``component_id``),
      pagination (``offset``/``limit``), and the ``include_deleted`` /
      ``include_orphaned`` / ``summary_only`` toggles apply only in this
      mode. By default list mode excludes ORPHANED controls (controls
      whose every mapped CO is tombstoned because its asset/attacker pair
      was removed in a later version); pass ``include_orphaned=True`` to
      include them — each returned control carries a boolean ``orphaned``
      field so callers can render the distinction.

    - **Detail mode** (``control_id`` set) — returns a single control
      directly (NOT wrapped in an array) with verified-status enrichment
      and an ``orphaned`` flag derived from the live CO set. 404 if the
      control doesn't exist on the requested version. Pass ``version`` to
      read the control as of a specific model version. The list-mode
      filters, pagination, and toggles are ignored in this mode.

    **Objective mapping is not coverage credit.** The control-objective ids a
    control carries record which objectives it is ATTACHED to, not which ones
    it is required to satisfy. Within an objective, a control is either a
    member of a required mitigation group or it is defense-in-depth, which is
    tracked but earns no mitigation credit. A control that is defense-in-depth
    on every objective it touches can be fully implemented and fully verified
    without moving a single objective out of at-risk. Read
    ``get_mitigation_groups`` for the per-objective role before deciding a
    control is worth evidence work — the id list alone will not tell you
    whether proving it changes anything.

    **Two different status fields — do not conflate them.** ``status`` is the
    operator-set implementation state (``not_implemented`` / ``implemented``
    / ``verified``). ``verification_status`` and ``is_verified`` are the
    EVIDENCE state, derived from the control's assertions:

    - ``"verified"`` — every assertion passes both tiers AND they
      collectively cover the whole control description.
    - ``"partially_verified"`` — deliberately covers three distinct
      situations, so it does not by itself tell you what to fix: some
      assertion FAILED a tier, or all passed but leave clauses of the
      description UNPROVEN, or the control leaned on an operator
      attestation that has since EXPIRED. Call ``get_sufficiency`` on the
      control to find out which.
    - ``"pending"`` — assertions exist, some still awaiting evaluation.
    - ``"unverified"`` — no assertions submitted at all.

    A control with ``assertion_count`` well above zero and every tier
    passing can still read ``partially_verified``; that is the normal state
    for evidence narrower than the description promises, and the fix is
    more assertions (or a narrower description), never a verdict recompute.

    Filtering ``status="implemented"`` returns controls the operator marked
    implemented that have NOT been promoted to verified — the right filter
    for "what still needs evidence work". It reads this model's OWN stored
    controls; controls inherited through composition are counted by
    ``assess_model`` but are managed on their source model.

    Args:
        model_id: ID of the threat model.
        control_id: If set, detail mode — return this one control's full
            record directly (e.g. ``CTL-12``). If omitted, list mode.
        version: Detail mode only — model version to read the control
            from. 0 (default) uses the latest. Ignored in list mode.
        status: List-mode filter — "implemented", "not_implemented", or
            "verified".
        co_id: List-mode filter — control objective ID.
        component_id: List-mode filter — component ID (e.g., "CMP1").
        offset: List mode — skip the first N controls (pagination).
        limit: List mode — max controls to return (0 = all).
        include_deleted: List mode — include soft-deleted controls
            (default False).
        include_orphaned: List mode — include controls mapped only to
            tombstoned COs (default False).
        summary_only: List mode — if True, returns only id, description,
            status, assertion_count, and assumed_by per control (much
            smaller response).

    Returns a single control dict in detail mode, or a dict with
    ``controls`` plus ``total`` and ``returned`` counts in list mode.
    """
    try:
        if control_id:
            return _dump(
                await _get_client().get_control(
                    model_id, control_id, version=version,
                ),
            )
        data = await _get_client().get_controls(
            model_id,
            include_deleted=include_deleted,
            include_orphaned=include_orphaned,
            control_id="",
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
async def get_control_objectives(
    server_version: str,
    model_id: str,
    co_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Get the control objective matrix, or one control objective. Read-only.

    Two modes, selected by whether ``co_id`` is set:

    - **Matrix mode** (``co_id`` omitted) — returns the model's COs, each
      with references to the controls that cover it. By default returns a
      compact summary (total count only); pass ``offset``/``limit`` to
      page through full CO records.

    - **Single mode** (``co_id`` set) — returns that one CO's typed
      fields, the IDs of any controls that map to it, and the
      deterministic reachability verdict (the structural derivation that
      backs any reach claim on the CO). Tombstoned COs (``removed:
      true``) are returned with the flag set; the verdict is omitted
      because reach state is frozen at the removal version.
      ``offset``/``limit`` are ignored in this mode.

    For pass/fail assurance scoring use ``assess_model``.

    Args:
        model_id: ID of the threat model.
        co_id: If set, single mode — return this one control objective
            (e.g. ``CO3``) with its verdict. If omitted, matrix mode.
        offset: Matrix mode — skip the first N control objectives.
        limit: Matrix mode — max to return (0 = summary only, no per-CO
            records).
    """
    try:
        if co_id:
            return _dump(await _get_client().get_control_objective(model_id, co_id))
        return _dump(await _get_client().get_control_objectives(model_id, offset, limit))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def assign_to_components(
    server_version: str,
    model_id: str,
    target_type: str,
    target_id: str,
    component_ids: str,
    change_reason: str,
) -> dict:
    """Replace an asset's or a control's component scope. Mutating.

    Components are the canonical bridge between security architecture
    (trust boundaries) and code organization (repos). ``target_type``
    selects what is being scoped:

    - ``"control"`` — replace a control's component scope. A control
      scoped to one or more components is visible to coding agents
      working in those repos (matched via Component.repo_url +
      Component.path); an unscoped control is visible everywhere. Use
      when wiring a previously unscoped control to the component(s) that
      implement it, adding a second component to a cross-cutting control
      (e.g. "all microservices enforce JWT validation"), or correcting a
      wrong assignment. ``target_id`` is the control ID (e.g. "CTRL-03").

    - ``"asset"`` — replace an asset's component scope. Linking assets to
      components flows boundary context into reachability derivation
      without giving Asset its own ``trust_boundary_ids``. Multi-component
      is the right shape for a multi-instance asset (e.g., a session
      token on client + cache + DB — each component handles a distinct
      instance). ``target_id`` is the asset ID (e.g. "A1").

    Both variants are mechanical / non-AI-gated and validate only that
    every referenced component exists on the model.

    Args:
        model_id: ID of the threat model.
        target_type: Either "asset" or "control" — which entity to scope.
        target_id: ID of the asset or control to scope (must match
            ``target_type``).
        component_ids: Comma-separated component IDs (e.g., "CMP1,CMP2").
            Empty string = unscoped (a control becomes visible to every
            coding agent; an asset loses its explicit code-ownership
            binding). Every supplied ID must exist on the model.
        change_reason: Why this scope is appropriate (min 10 chars).
            Captured in the version history.
    """
    if target_type not in ("asset", "control"):
        raise ToolError('target_type must be "asset" or "control".')
    parsed = [c.strip() for c in component_ids.split(",") if c.strip()] if component_ids else []
    if len(change_reason.strip()) < 10:
        raise ToolError("change_reason must be at least 10 characters.")
    try:
        client = _get_client()
        if target_type == "asset":
            result = await client.assign_asset_to_components(
                model_id, target_id, parsed, change_reason.strip(),
            )
        else:
            result = await client.assign_control_to_components(
                model_id, target_id, parsed, change_reason.strip(),
            )
        return _dump(result)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_scan_prompt(
    server_version: str,
    model_id: str,
    kind: str = "security",
    control_id: str = "",
) -> dict:
    """Get guidance prompts for scanning a codebase. Read-only; no side effects.

    ``kind`` selects which scan brief to return:

    - ``"security"`` (default) — prompts telling the agent what evidence
      to look for per security control; only NOT_IMPLEMENTED controls are
      included (implemented ones need no scan). Use this to drive a
      gap-discovery pass, then record what is missing with
      ``submit_findings`` and what is present with ``submit_assertions``.
      Pass ``control_id`` to scope the prompt to one control; empty
      (default) returns prompts for all not-yet-implemented controls.

    - ``"functional"`` — the agent brief for implementing
      functional-conformance tests. Generation specifies the functional
      tests, so for each test not yet verified this returns its
      implementation brief and the objectives it proves; it also reports
      ``objectives_without_tests`` (regenerate or add a test) and
      ``missing_objectives`` (applicable conditions with no objective
      yet). Drive test implementation from it, then call
      ``submit_functional_test_assertions`` with TEST_EXISTS + TEST_PASSES
      assertions so CI verifies each test; read the resulting pass/fail
      state via ``get_functional_coverage``. ``control_id`` does not
      apply to this kind and is ignored.

    Args:
        model_id: ID of the threat model.
        kind: "security" (default) or "functional" — which scan brief.
        control_id: Security kind only — optional single control to scope
            the prompt to. Empty (default) returns prompts for all
            not-yet-implemented controls. Ignored when kind="functional".
    """
    if kind not in ("security", "functional"):
        raise ToolError('kind must be "security" or "functional".')
    try:
        client = _get_client()
        if kind == "functional":
            return _dump(await client.get_functional_scan_prompt(model_id))
        return _dump(await client.get_scan_prompt(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def set_control_objective_cal(
    server_version: str,
    model_id: str,
    co_id: str,
    cal: Optional[int] = None,
) -> dict:
    """Set the per-CO ISO/SAE 21434 Cybersecurity Assurance Level (CAL).

    CAL is a 1-4 grade on each individual control objective that
    expresses how much assurance the control program owes for that
    specific objective. It lives on the ``control_objectives`` identity
    side-table — writes do NOT create a new threat-model version, and
    the value survives soft-delete + revival of the CO.

    Pass ``cal=None`` (or omit it) to clear the value.

    Args:
        model_id: ID of the threat model.
        co_id: Control-objective ID (e.g. ``CO3``).
        cal: ISO/SAE 21434 CAL grade (1-4), or ``None`` to clear.

    Returns:
        ``{"model_id": ..., "co_id": ..., "cal": ...}``
    """
    if cal is not None and (cal < 1 or cal > 4):
        raise ToolError("cal must be between 1 and 4 (inclusive), or None to clear")
    try:
        return _dump(await _get_client().set_co_cal(model_id, co_id, cal))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def revalidate_entity_quality(
    server_version: str,
    model_id: str,
) -> dict:
    """Re-run quality validation on a threat model's existing assets and
    attackers, as if they were freshly generated. A fast first-pass check
    judges every entity; only the ones it flags get a deeper review that
    confirms them, sharpens their wording, or flags them for you.

    Use this to apply validation improvements to an already-generated model, or
    to clear stale quality warnings — without regenerating the whole model
    (which would destroy controls, assertions, and components). It is
    non-destructive: an entity that should be removed is left in place with a
    quality warning rather than deleted, so no control objective loses its asset
    or attacker anchor. The result is saved as a new model version; controls and
    control objectives carry forward.

    May consume credits for the entities that need the deeper review; a model
    already in good shape costs nothing. Returns the updated model envelope:
    ``{"accepted": true, "model": {...}}``.

    Args:
        model_id: ID of the threat model whose assets and attackers to
            re-validate.
    """
    try:
        return _dump(await _get_client().revalidate_entities(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def auto_remediate_compliance(
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


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

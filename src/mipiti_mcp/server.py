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
    "/mcp toggle does NOT refresh them. The MCP server config must be torn "
    "down and re-added. In Claude Code: exit the session, run "
    "`claude mcp remove Mipiti` (substitute the name you used when adding "
    "if different), resume the session, exit again, run your original "
    "`claude mcp add ...` command, reauthenticate, then resume."
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

## Constructing `feature_description`

Output quality scales with input quality. A one-line "this is a backend \
that handles payments" produces a generic, shallow model; a multi-paragraph \
spec with concrete components, integrations, and trust boundaries produces a \
useful one. Two scenarios require different gathering strategies:

**Scenario A — planned change (you're about to implement something).** The \
in-progress design discussion or PR description is usually enough. Pass it \
verbatim or lightly edited. Don't pad with unrelated repo context.

**Scenario B — existing repo (operator said "threat-model this repo" or \
similar).** The conversation context alone is almost never enough. Before \
calling `generate_threat_model`, gather:

1. **Purpose** — open `README.md` (and any `docs/` overview). One or two \
sentences on what the system does and who uses it.
2. **Components / processes** — entry points, services, daemons, workers. \
Look at `Procfile`, `docker-compose.yml`, `fly.toml`, k8s manifests, the \
`scripts` block in `package.json`, `__main__.py` / top-level `main.py` / \
`cmd/` directories, the `[project.scripts]` table in `pyproject.toml`. \
List each component with a short purpose.
3. **External integrations** — third-party APIs, databases, queues, auth \
providers, payment processors. Grep env-var references (`os.environ`, \
`process.env`), SDK imports (`stripe`, `boto3`, `@octokit`, etc.), and \
infrastructure definitions. Name each one and what it's used for.
4. **Data flows / assets** — what data enters the system and where it \
goes. Skim HTTP route files, webhook handlers, message-queue consumers, \
schema/model files. Note PII, secrets, credentials, regulated data.
5. **Trust boundaries** — where requests cross from less-trusted to \
more-trusted (network ingress, auth middleware, service-to-service calls, \
worker IPC). At minimum: "anonymous internet → authenticated API → \
internal services → datastore."
6. **Deployment shape** — SaaS / on-prem / hybrid / library. Single-tenant \
vs. multi-tenant. Look at `Dockerfile`, `fly.toml`, `helm/`, `terraform/`, \
or absence thereof.

Pass all of this as a multi-paragraph `feature_description`. The backend \
will detect similar existing models — if one matches, prefer \
`refine_threat_model` on it instead of `force=True`.

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
- `reevaluate_threat_model_factors` — bulk LLM re-run of the factor \
decomposition (subscores + blast/recoverability/regulatory on assets; \
CVSS-Base + capability_prevalence on attackers) for every live entity in \
a model. Use this to re-baseline an existing model after the feature \
description changes meaningfully, or to refresh stale ratings — without \
regenerating the whole model (which would destroy controls, assertions, \
components). The platform's factor judgment is a calibrated *starting \
point*; layer deployment-specific reality on top via `edit_asset` / \
`edit_attacker` with a `change_reason` documenting the override (e.g., \
"regulatory_scope=Legal — tenant is HIPAA-covered", \
"capability_prevalence=Commodity — endpoint is public-internet \
exposed"). The rating-revision audit trail distinguishes platform \
suggestions from operator overrides.
- `revalidate_threat_model_entities` — re-run quality validation over an \
existing model's assets and attackers (a fast first-pass check on every \
entity, a deeper review only on the ones it flags). Use it to apply \
validation improvements to an already-generated model or clear stale quality \
warnings, without regenerating. Non-destructive (it flags rather than \
deletes) and saves a new version.
- `get_threat_model` — retrieve a model's full structure (excludes COs by \
default; use `include_cos=True` to include them).
- `query_threat_model` — ask questions about an existing model.
- `list_threat_models` — browse existing models.
- `rename_threat_model` — rename a model (metadata only, no new version). \
Model titles must be unique within a workspace (case-insensitive); pick a \
distinct name on the first try to avoid a 409 retry.
- `set_threat_model_parent` — wire a model under (or detach it from) a \
parent on the recursive composition tree. Pass `parent_id=None` to clear. \
Server rejects cycles and over-deep chains; bumps version on success.
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
Pair with `get_reachability_verdicts` to surface composer reachability \
state per CO before linking assumptions or regenerating.
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

## When you hit an implementation constraint mid-coding

When a reviewer, hardware limit, library bound, or operator decision \
forces you off the prescribed mechanism (e.g., "this device only \
supports AES-128, not AES-256"), do NOT silently weaken the existing \
control or its assertions. Record the constraint structurally so the \
threat model reflects reality and the audit trail captures the \
reasoning. Use this 3-step pattern:

1. **Add the alternative control** — call `import_controls` with a \
single-entry `controls_json` describing the weaker-but-feasible \
mechanism. Set `co_ids` to the affected CO. Set `framework_refs` \
**honestly**: include only bindings the alternative actually \
satisfies — drop any that the weaker mechanism cannot meet. Then \
call `assign_control_to_components` to scope it to the constrained \
component(s) only, so the original control still applies elsewhere.

2. **Declare them as OR-alternatives** — call `set_mitigation_groups` \
on the affected CO with the original (strict) control in one group \
and the new (weaker) control in another (across groups = OR). Pass \
the operator's plain-language constraint reason in `justification` \
— it flows into the AI gate's verdict and the activity log.

3. **Record the constraint context** — call `add_assumption` with \
`linked_co_ids=[<co>]` capturing what reviewer or system imposed \
the constraint, the rationale, and any expiry conditions (e.g., \
"hardware refresh in 2027 lifts the AES-128 limit"). Then \
`submit_attestation` so the assumption is active.

If the alternative drops a framework binding the original carried, \
the platform automatically emits a `framework_binding_asymmetry` \
finding for the security team to triage — surfaced via \
`list_findings` and `get_findings_risks`.

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

**Reachability and risk reason**: Reachability per CO is exposed by \
`get_reachability_verdicts` (deterministic-computation provenance — \
re-derived from structural primitives, never persisted). Each CO \
assessment also includes:
- `risk_reason` — why a non-mitigated CO is at risk: `missing_controls` \
(implement controls), `pending_attestation` (submit an attestation for \
the linked boundary assumption), `expired_attestation` (renew an expired \
attestation), `unassessed` (generate controls or create an assumption), \
`asset_absent` (asset is not applicable — skip this CO), \
`attacker_irrelevant` (attack surface is not applicable — skip this CO), \
`coverage_gap` (controls are implemented but do not span the CO's full \
threat — add controls to close the gap, or dismiss/accept if intentional), \
`insufficient_by_design` (the controls *defined* for the CO's mitigation \
group would not mitigate the objective even if fully implemented — a design \
gap, not an implementation gap; redesign or add controls so the group can \
span the threat). `insufficient_by_design` is more binding than \
`missing_controls` and takes precedence over it.
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
`unassessed` → generate controls with `regenerate_controls`. If the \
composer says the CO is unreachable or indeterminate (per \
`get_reachability_verdicts`), author a structured `Assumption.exclusion` \
predicate via `add_assumption` instead of generating controls. \
`asset_absent` → the asset is not applicable. No action \
needed — skip controls for this CO. \
`attacker_irrelevant` → the attack surface is not applicable. No action \
needed — skip controls for this CO. \
`coverage_gap` → the controls are implemented but leave part of the CO's \
threat unaddressed. Inspect the linked `coverage_gap` finding via \
`list_findings` for the uncovered aspects + suggested control, add controls \
(`regenerate_controls` / `import_controls`) and submit assertions; if it's a \
false positive `dismiss` the finding, or if intentional record a risk \
acceptance / assumption. \
`insufficient_by_design` → the controls *defined* for the CO's mitigation \
group would not mitigate the objective even if fully implemented. Do NOT \
just implement the defined controls — that will not help. Inspect the linked \
`insufficient_by_design` finding via `list_findings` for the rationale, then \
redesign or ADD controls to the mitigation group (`regenerate_controls` / \
`import_controls`, then `set_mitigation_groups`) so the group can actually \
span the objective's threat, and submit assertions; if it's a false positive \
`dismiss` the finding, or if intentional record a risk acceptance / \
assumption. (Contrast with `missing_controls`, where the defined controls \
*would* mitigate the CO and you simply implement them and submit assertions.)

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
- `get_findings_risks` — workspace-wide dashboard: open findings, active \
risk acceptances, and at-risk Control Objectives in one call. Use as the \
triage entry point when the operator asks "what's open?" / "what should \
I work on next?".
- `get_model_risk_view` / `get_system_risk_view` — Prioritized Risk View \
rows for a specific model or system with risk dimensions, control \
coverage counts, and open-finding counts per CO. Use when narrowing \
from workspace-wide to a specific target.
- `list_risk_acceptances` — see which risks have been explicitly accepted \
on a model (with owner, justification, review deadline) so you can \
separate intentional acceptances from genuinely unaddressed gaps.

## Remediating findings (structural drift)

The platform emits structural-drift findings (e.g. duplicate controls \
that accumulated from prior platform behavior, framework-binding \
asymmetries when mitigation groups have inconsistent compliance \
coverage) via list_findings. For findings whose kind supports \
automatic remediation, you can offer the operator a one-click cleanup \
flow:

1. Call preview_finding_remediation(finding_id) to see the proposed \
   change. The response is a structured diff scoped to that one \
   finding — typically very small.

2. SHOW THE OPERATOR THE DIFF. Do not commit silently. The operator \
   should see exactly which controls would be merged, what framework \
   refs would consolidate, etc.

3. Get the operator's confirmation AND a one-line rationale (e.g. \
   "cleaning up duplicates from pre-fix trigger bug").

4. Call apply_finding_remediation(finding_id, justification=<rationale>) \
   to commit. The platform records who, what, and why for the audit \
   trail.

Never apply remediation without preview. The platform does not \
enforce this — it's the agent's responsibility to surface the change \
before committing.

**Diagnose-and-hand-off findings.** Some finding kinds have NO automatic \
remediation handler (`preview_finding_remediation` / \
`apply_finding_remediation` return 422) — they describe a gap for you to \
resolve directly with the control tools, then submit assertions / \
`update_finding`: \
`coverage_gap` (the CO's controls do not span its full threat → add the \
missing controls via `regenerate_controls` / `import_controls`, or `dismiss` \
if a false positive, or record a risk acceptance / assumption if \
intentional), \
`insufficient_by_design` (the controls *defined* for the CO's mitigation \
group would not mitigate it even if fully implemented → do NOT just \
implement the defined controls; redesign or add controls to the mitigation \
group via `regenerate_controls` / `import_controls` + `set_mitigation_groups` \
so the group can span the threat, or `dismiss` if a false positive, or \
record a risk acceptance / assumption if intentional), \
`control_mechanism` (an existing control's mechanism is wrong and could not \
be corrected automatically → edit, split, or remove it; the finding's \
details list the control's full CO-set so you see the blast radius before \
changing a shared control), \
`misclassified_defense_in_depth` (a defense-in-depth control is load-bearing \
for a CO's coverage → promote it into that CO's mitigation group via \
`set_mitigation_groups`). Do not call `apply_finding_remediation` for these \
kinds.

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
rejected. Originates from the taxonomy-classification step (which judges the \
feature against the closed 17-primitive taxonomy) or from operator-authored \
declarations. Generation-time validation failures on individual assets / \
attackers do NOT auto-create non-applicability assumptions; entities that \
exhaust the validation loop's retries receive a `quality_warning` field for \
the operator to review.
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

## Composition (recursive-tree multi-model)

Threat models can compose hierarchically — a child model inherits assets, \
attackers, components, trust boundaries, and baseline controls from its \
parent (and transitively from ancestors). With composition enabled, the \
effective model = own ⊕ inherited; the platform computes effective control \
objectives, coverage, compliance, reachability, attack paths, and finding \
inheritance over that composed view.

**When to use**: a child model that shares a security baseline with its \
parent (e.g., a feature built on top of a multi-tenant platform that already \
has auth / MFA / RBAC / KMS controls). Composition lets the child operator \
focus on the feature's delta while the parent's controls credit the child \
automatically.

### Reading the composed view

Start with the overview, then drill in:
- `get_composition_overview` — flag state, tree position, own-vs-inherited \
counts, reconciliation badge. Cheapest call (~1-2KB). Use first.
- `composition_entities` — full own + inherited entity set per kind.
- `composition_control_objectives` — effective CO list (classified own / \
cross / inherited).
- `composition_coverage` — effective coverage / compliance numbers.
- `composition_reachability` — composed reachability verdicts.
- `composition_attack_paths` — AttackPath references resolved against the \
effective entity set (paths spanning inherited entities resolve cleanly).

### Reconciliation — surfaced cross-tree duplicates

When the same entity is authored on both the child and an ancestor (e.g., \
both name an "API Gateway" component), the detector surfaces it as a \
reconciliation candidate. Two tiers:
- `certain` — identical name AND identical structural refs (same trust \
boundary / asset attachments). Auto-merge eligible.
- `heuristic` — identical name only; structural refs differ. Triage needed.

Tools:
- `composition_reconciliation` — paginated candidate list with names, \
source-model titles, and reasons.
- `reject_reconciliation_candidate` — record "these are NOT duplicates"; \
the detector filters the pair out of future queues, durable at org scope.
- `unreject_reconciliation_candidate` — undo a rejection.
- `list_reconciliation_rejections` — rejected pairs for a model.

### Mutations — lift and split

When the operator confirms a duplicate should be reconciled, lift it to \
the lowest common ancestor (LCA). Inverse: split an ancestor entity down \
to specific descendants when the entity isn't shared after all.
- `lift_composition_entity` — promote shared-anchor entity from two \
descendants to their LCA. Carries operator confirmations (LCA, third-party \
subtree acknowledgements, field-resolutions, attached-state resolutions, \
optional over-application-gate override). Emits `lift_applied`; audit pack \
surfaces under `lift_history`.
- `split_composition_entity` — push an ancestor entity down to operator- \
chosen descendants. Emits `split_applied`; audit pack `split_history`.

### Undo with divergence detection

Both lift and split mutations are reversible. The divergence detector \
refuses the undo with enumerated reasons if state has continued to evolve \
since the mutation (e.g., entity edited after lift, re-lifted further up, \
descendant collision, attached-state mutation, model deletion).
- `preview_undo_lift_composition` / `preview_undo_split_composition` — \
read-only; returns `{plan, refusal}`. Always preview FIRST.
- `undo_lift_composition_event` / `undo_split_composition_event` — apply \
the inverse mutation. Emits `lift_undone` / `split_undone` citing \
`original_event_id`.

**Operator pattern**: preview → inspect plan or refusal-reasons → if clean \
proceed with apply; if refused, surface the enumerated reasons (operator \
decides whether to edit the divergence manually or accept it).

## Cross-model dependencies (delegation)

Distinct from the parent/composition tree (containment): a *reliance* edge \
declares that one model depends on a control implemented in ANOTHER model — \
the right tool when a product is built on shared services (auth, logging, a \
shared datastore) rather than being a sub-part of them. The target is always a \
provider *control*, so credit terminates at a proven mechanism. Reliance is \
scoped to the current workspace: a consumer can only delegate to provider \
models in the SAME workspace (these tools don't see models across workspace \
boundaries), so pick the foundation from this workspace's models. These tools \
are available when the recursive-tree feature is enabled.

- `declare_foundation` — mark a shared-service model as a foundation that \
advertises specific controls other models can delegate to.
- `propose_attach_foundation` → `attach_foundation` — bulk flow: propose which \
of a consumer's objectives each foundation capability covers (read-only, \
scored), then create draft delegation edges for the chosen subset.
- `create_reliance` — declare a single dependency. `delegated` (consumer has \
no local control for an objective; the provider handles it — pass \
`source_objective_id`) or `relied_upon` (consumer keeps its own control but \
its validity depends on the provider's — pass `source_control_id`).
- `confirm_reliance` — promote a draft edge to active. Edges run LLM semantic \
validation on creation and carry NO credit until confirmed, and only when \
validation returned `valid` (a `partial` or mode-mismatch is refused — never \
silently credited).
- `list_reliance` — a model's dependency edges (as consumer) plus who relies on \
it (as provider — the blast radius before changing its controls).
- `delete_reliance` — remove an edge.

A delegated objective is credited only while the provider control stays \
verified; if the provider control regresses or a refined mechanism no longer \
satisfies the consumer, the edge breaks and a finding is raised on the consumer.

## Tags (grouping)

A *tag* is an overlapping, semantics-free grouping of models — for audit \
scopes, ad-hoc selections, or portfolios. It is a label, not a relationship: a \
model may carry MANY tags, and a tag never affects posture or credit (that's \
what delegation and composition are for). Use tags to organize and to get an \
aggregate risk view across a chosen set of models.

- `create_tag` / `delete_tag` — create or remove a tag (deleting affects the \
grouping only, never the member models).
- `add_model_to_tag` / `remove_model_from_tag` — manage membership; a model can \
be in many tags at once.
- `list_tags` / `list_model_tags` — browse tags, or a model's tags.
- `get_tag_risk_view` — aggregate per-CO risk across a tag's members. \
Delegation-aware, so a CO mitigated via a verified cross-model delegation reads \
as covered, consistent with the per-model assessment.

A tag can also be a **compliance / audit scope** spanning several models: \
`select_tag_compliance_frameworks` selects frameworks for the tag and \
propagates them to its members; `get_tag_compliance_report` gives cross-model \
requirement coverage; `export_tag_report` produces the signed auditor HTML \
(member reports + cross-model dependency graph + attestation status) — the tag \
equivalents of the system-level compliance report and auditor export.

## Functional conformance

Functional conformance proves a feature does what it was *specified* to do — the \
parallel of security controls, verified by the same assertion + CI engine. \
Capabilities are the behaviours the feature must deliver; each is tested against a \
taxonomy of operating conditions (nominal, boundary, dependency-failure, …), and a \
Functional Objective is a Given-When-Then acceptance criterion. Two ways to \
establish coverage:

**Generate (top-down).** `generate_functional_objectives` derives capabilities, \
objectives, and the concrete tests to write; `get_functional_scan_prompt` returns \
the per-test brief; implement each test, register it with `add_functional_test`, \
then submit `TEST_EXISTS` + `TEST_PASSES` evidence with `submit_functional_tests` \
so CI verifies it.

**Import (bottom-up) — bring the tests you already have.** \
`import_functional_tests` registers your existing codebase tests (optionally with \
the objectives they cover; the platform verifies each association is applicable \
before accepting it). For tests you don't map yourself, \
`suggest_functional_test_mappings` proposes which objective each one actually \
proves (judged on behaviour, with a confidence) and `associate_functional_test` \
confirms a mapping — so an existing suite counts toward conformance, not only \
Mipiti-specified tests.

- `get_functional_coverage` / `check_functional_gaps` — the Capability × Condition \
coverage report and the actionable gaps (uncovered cells, failing/untested \
objectives).
- `set_functional_satisfaction_groups` / `get_functional_satisfaction_groups` — \
when several tests must *together* prove an objective, group them (within a group \
all must pass; any complete group proves the objective).
- `get_functional_test_sufficiency` — whether a test's submitted evidence is \
sufficient to prove the objective it targets.

"""

_INSTRUCTIONS_COMPLIANCE = """\

## Compliance

1. `list_compliance_frameworks` — available frameworks (SOC 2, ISO 27001, etc.).
2. `import_compliance_framework` — import a customer-specific framework \
(regulatory, contractual, or internal program not covered by the 11 \
built-ins). Accepts a JSON body with `name`, `requirements`, and the \
optional `level_definitions` per-level legend.
3. `select_compliance_frameworks` — activate frameworks for a model. \
**Automatically triggers auto-remediation**: maps existing controls, \
excludes non-applicable requirements by taxonomy, and suggests/applies \
new entities for remaining gaps. Returns `auto_remediate_jobs` with \
job IDs for polling.
4. `get_compliance_report` — coverage report (run after auto-remediation completes).
5. `auto_remediate` — re-trigger auto-remediation manually (e.g. after model changes).
6. `auto_map_controls` — map controls to framework requirements (runs automatically \
during auto-remediation, but can be triggered independently).
7. `map_control_to_requirement` — manually map a specific control to a \
specific requirement (use when auto-mapping misses or misassigns).

### Per-entity grades

Some frameworks (IEC 62443, ISO/SAE 21434, NIST CSF, FIPS 140-3, \
Common Criteria) carry per-entity level grades alongside the \
control-to-requirement mapping:

- `edit_component` with `target_sl` / `eal` / `fips_level` — set per-\
component IEC 62443 SL (1-4), CC EAL (1-7), FIPS 140-3 (1-4). \
Orthogonal axes; set whichever the customer program requires.
- `set_co_cal` — set per-CO ISO/SAE 21434 Cybersecurity Assurance \
Level (1-4). Lives on the CO identity table; survives soft-delete.
- `update_organization` — set per-org IEC 62443-4-1 Maturity Level \
(1-5) and NIST CSF Tier (1-4). Admin-only.

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
to specific codebases AND to ground the deterministic reachability \
composer's asset-boundary derivation.

- `add_component` — create a component with name, repo_url, and \
optional path (for monorepos) and trust_boundary_ids.
- `edit_component` / `remove_component` — modify or delete a component.
- `get_controls` with `component_id` — filter controls by component.
- `assign_asset_to_components` — link an asset to one or more \
components. Drives the reachability composer's per-CO verdicts.

### When to populate components

`generate_threat_model` proposes speculative components (with \
`repo_url=""`) when no topology has been supplied. These are a \
starting point — refine them as code grounding emerges:

- **Existing codebase**: when you've scanned the repo and know \
the real services, call `add_component` (with grounded `repo_url` \
and `path`) BEFORE `generate_threat_model`. The generation prompts \
will scope assets and boundaries to the components you supplied. \
Alternatively, call `generate_threat_model` first and then \
`edit_component` on each speculative component the LLM proposed, \
swapping `repo_url` to the real URL.
- **Planning conversation, no code yet**: call `generate_threat_model` \
directly; the LLM-proposed speculative components serve as a \
topology starting point the user/developer refines as the design \
firms up. `repo_url` stays empty until code exists; the coherence \
report flags `component_unbound` findings on speculative components \
so they're visible to auditors.

A component with empty `repo_url` is the natural signal "speculative \
— not yet bound to code." A component with a populated `repo_url` is \
grounded. There is no separate status field — the binding is the \
state.
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
    your parent) and over-deep chains (depth bounded by
    ``MAX_TREE_DEPTH``) with HTTP 400. Bumps the model version on
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

    A foundation is a shared service (auth, logging, a shared datastore) whose
    controls other models can delegate to. Each entry in ``provides`` advertises
    one of THIS model's controls as providable:
    ``{"control_id": "CTRL-07", "capability_label": "Validates session tokens",
    "description": "..."}``. A capability always advertises a control (a proven
    mechanism), never an objective. ``visibility`` is "workspace" (default) or
    "explicit".

    Args:
        model_id: ID of the model to declare as a foundation.
        provides: List of advertised-control dicts (control_id required).
        visibility: "workspace" or "explicit".
    """
    try:
        return await _get_client().declare_foundation(model_id, provides, visibility)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_reliance(server_version: str, model_id: str) -> dict:
    """List a model's cross-model dependency edges (as consumer and as provider).

    Returns ``{model_id, as_consumer: [...], as_provider: [...]}``. Consumer
    edges are this model's declared delegations / reliances; provider edges are
    other models relying on this one (the blast radius if its controls change).

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
    """Delete a cross-model reliance edge.

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
async def list_tags(server_version: str) -> dict:
    """List the workspace's tags (the Affiliation primitive).

    A tag is an overlapping, semantics-free grouping of models — for audit
    scopes, ad-hoc selections, or portfolios. Unlike a system, a model may carry
    many tags, and a tag never affects posture or credit. Returns ``{tags: [...]}``.
    """
    try:
        return await _get_client().list_tags()
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def create_tag(
    server_version: str,
    name: str,
    description: str = "",
    model_ids: list[str] | None = None,
) -> dict:
    """Create a tag, optionally seeding it with member models.

    Tags group models for viewing/reporting without asserting any relationship
    between them and without moving credit. Tag names are unique per workspace.

    Args:
        name: the tag name (unique within the workspace).
        description: optional description.
        model_ids: optional initial member model ids.
    """
    try:
        return await _get_client().create_tag(name, description, model_ids or [])
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def delete_tag(server_version: str, tag_id: str) -> dict:
    """Delete a tag (the grouping only; member models are not affected).

    Args:
        tag_id: ID of the tag to delete.
    """
    try:
        await _get_client().delete_tag(tag_id)
        return {"deleted": True, "tag_id": tag_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_model_to_tag(server_version: str, tag_id: str, model_id: str) -> dict:
    """Add a model to a tag. A model may belong to many tags (overlapping).

    Args:
        tag_id: the tag.
        model_id: the model to add.
    """
    try:
        return await _get_client().add_model_to_tag(tag_id, model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def remove_model_from_tag(
    server_version: str, tag_id: str, model_id: str,
) -> dict:
    """Remove a model from a tag (the model itself is not deleted).

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
async def list_model_tags(server_version: str, model_id: str) -> dict:
    """List every tag a model belongs to (overlapping membership).

    Args:
        model_id: the model whose tags to list.
    """
    try:
        return await _get_client().list_model_tags(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_tag_risk_view(server_version: str, tag_id: str) -> dict:
    """Aggregate per-CO risk rows across a tag's member models.

    The tag-based aggregate posture view. Each row is delegation-aware
    (``delegation_mitigated`` / ``delegating_controls``), so a CO mitigated via a
    verified cross-model delegation reads as covered — consistent with the
    per-model assessment.

    Args:
        tag_id: the tag to aggregate over.
    """
    try:
        return await _get_client().get_tag_risk_view(tag_id)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def select_tag_compliance_frameworks(
    server_version: str,
    tag_id: str,
    framework_ids: list[str],
) -> dict:
    """Select compliance frameworks for a tag (scope-level).

    Records the frameworks against the tag and propagates them to each member
    model — the tag becomes a compliance scope (e.g. an audit boundary) spanning
    several models, the same capability a system has.

    Args:
        tag_id: the tag to scope compliance to.
        framework_ids: framework ids to select (from `list_compliance_frameworks`).
    """
    try:
        return await _get_client().select_tag_compliance_frameworks(tag_id, framework_ids)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_tag_compliance_report(
    server_version: str,
    tag_id: str,
    framework_id: str,
    level: int = 0,
) -> dict:
    """Cross-model compliance coverage report scoped to a tag's members.

    Aggregates requirement coverage across every model the tag contains, the
    same as a system-level compliance report but over a freely-composed set.

    Args:
        tag_id: the tag (compliance scope).
        framework_id: the framework to report on.
        level: optional framework level filter (0 = all).
    """
    try:
        return await _get_client().get_tag_compliance_report(tag_id, framework_id, level)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def export_tag_report(server_version: str, tag_id: str) -> dict:
    """Export the signed auditor report for a tag (HTML).

    Aggregates every member model's report plus the cross-model dependency graph
    and attestation status into one signed HTML document — the tag equivalent of
    the system auditor export. Returns ``{tag_id, format, content}`` where
    ``content`` is the HTML body.

    Args:
        tag_id: the tag to export.
    """
    try:
        content = await _get_client().export_tag(tag_id, "html")
        return {"tag_id": tag_id, "format": "html", "content": content}
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
async def export_threat_model(
    server_version: str,
    model_id: str,
    ctx: Context,
    format: Literal["csv", "pdf", "html"] = "csv",
) -> dict:
    """Export a threat model as CSV, PDF, or HTML.

    The backend export endpoint runs as an async job (the synchronous
    render path was retired because cross-model assurance compute could
    pin the worker for minutes on large models). This tool kicks off the
    job, polls for completion via ``_await_backend_job`` (reporting
    progress), then fetches the rendered bytes.

    Args:
        model_id: ID of the threat model to export.
        format: Export format — "csv" (default), "pdf", or "html".

    Returns:
        ``{"format", "filename", "content"}`` for CSV (inline text).
        ``{"format", "filename", "content_b64", "content_type"}`` for
        PDF/HTML (binary, base64-encoded).
    """
    if format not in ("csv", "pdf", "html"):
        raise ToolError("format must be 'csv', 'pdf', or 'html'.")
    try:
        client = _get_client()
        job_id = await client.start_export_model(model_id, format)
        result = await _await_backend_job(client, job_id, ctx)
        # The backend job result is the file envelope.
        filename = (result or {}).get("filename") or f"threat_model.{format}"
        content_type = (result or {}).get("content_type") or ""
        content_bytes = await client.fetch_operation_result(job_id)
        if format == "csv":
            return {
                "format": "csv",
                "filename": filename,
                "content": content_bytes.decode("utf-8"),
            }
        import base64 as _b64
        return {
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
async def export_threat_model_archive(
    server_version: str, model_id: str, ctx: Context,
) -> dict:
    """Export the self-contained JSON audit archive for a threat model.

    The archive carries every version, controls, assertions (with CI Tier
    1/Tier 2 verdicts and attested flags), findings, risk acceptances,
    assumption overrides, attestations, and instance sufficiency
    signatures. Independently verifiable — CI OIDC JWTs verify against
    the issuer's public JWKS, workspace signatures against the
    workspace's published key, and sufficiency signatures against the
    origin instance's key (via the target's trusted_signers table).

    The backend renders the archive as an async job (the same
    cross-model assurance compute that motivated PDF/HTML to migrate
    away from synchronous rendering). This tool kicks off the job,
    polls for completion via ``_await_backend_job`` (reporting progress),
    then fetches and decodes the JSON envelope.

    Args:
        model_id: ID of the threat model to export.

    Returns:
        ``{"envelope": <full archive dict>}`` — pass this envelope to
        ``import_threat_model_archive`` on any instance to restore.
    """
    try:
        client = _get_client()
        job_id = await client.start_export_model_full(model_id)
        await _await_backend_job(client, job_id, ctx)
        content_bytes = await client.fetch_operation_result(job_id)
        envelope = json.loads(content_bytes.decode("utf-8"))
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
      ID that no longer exists. Resolve: ``assign_control_to_components``.
    - ``asset_component_unknown`` — asset references a missing
      component. Resolve: ``edit_asset`` (with corrected
      ``component_ids``).
    - ``assertion_repo_mismatch`` — an assertion's ``repo`` does not
      match the ``repo_url`` of any component scoping its control.
      Resolve: rebind the assertion or rescope the control.
    - ``assertion_repo_orphan`` — an assertion has a ``repo`` but its
      control is unscoped. Resolve: ``assign_control_to_components``
      to scope the control, or correct the assertion's repo.
    - ``control_unscoped_with_scoped_assertions`` — control is
      unscoped, but its assertions all carry a single component's
      ``repo``. Resolve: ``assign_control_to_components`` to that
      component.
    - ``component_unbound`` — a component has no ``repo_url``
      (speculative; LLM-proposed during generation, or operator-
      added without a binding yet). Resolve: ``edit_component`` with
      the real repo URL once the codebase exists. Speculative is a
      valid lifecycle state, not an error — surfaced so the gap is
      visible to auditors.

    Reachability findings (deterministic composer; indeterminate
    verdicts surface as findings, never auto-decided by an LLM):
    - ``co_attacker_unpositioned`` — the CO's attacker has no
      positioned trust boundaries. Resolve: ``edit_attacker`` (set
      ``trust_boundary_ids``), or ``add_assumption`` with a
      structured exclusion predicate.
    - ``co_asset_unbounded`` — the CO's asset has no component-derived
      trust boundaries. Resolve: ``assign_asset_to_components``,
      ``edit_asset`` (with ``component_ids``), or ``add_assumption``
      with a structured exclusion.
    - ``co_no_shared_boundary`` — attacker and asset boundaries do
      not intersect. Resolve: re-position the attacker via
      ``edit_attacker``, scope the asset to a shared component via
      ``assign_asset_to_components``, or ``add_assumption`` with a
      structured exclusion.
    - ``co_missing_entity`` — the CO references a missing
      asset/attacker; model state inconsistent. Resolve: restore
      the entity (``restore_asset`` / ``restore_attacker``) or
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


@mcp.tool()
async def get_reachability_verdicts(
    server_version: str,
    model_id: str,
    co_id: str = "",
) -> dict:
    """Composer verdicts for every live CO on the model. Pass ``co_id``
    to retrieve a single verdict (skips the cross-CO loop).

    Pure derivation over the model's structural primitives —
    components, asset.component_ids, trust_boundary.passes,
    attacker.trust_boundary_ids + attack_vector, and
    Assumption.exclusion predicates. NOT persisted on the CO. Re-
    running this call against the model JSON produces the same
    result every time — that's the verification an auditor performs.

    Each verdict carries:
      - ``co_id``
      - ``kind``: "reachable" | "unreachable" | "indeterminate"
      - ``reason``: structural label
        (``boundary_blocks_vector`` / ``assumption_excludes`` /
        ``attacker_unpositioned`` / ``asset_unbounded`` /
        ``no_shared_boundary`` / ``missing_entity``)
      - ``narration``: auditor-readable explanation
      - ``boundary_id``: which boundary blocked, if applicable
      - ``assumption_id``: which assumption excluded, if applicable

    When the verdict is indeterminate, address the gap via the
    standard model-edit affordances:
      - ``attacker_unpositioned`` → ``edit_attacker`` setting
        ``trust_boundary_ids``
      - ``asset_unbounded`` → ``assign_asset_to_components`` or
        ``edit_asset`` with ``component_ids``
      - ``no_shared_boundary`` → re-position attacker, re-scope
        asset, OR ``add_assumption`` with structured exclusion
      - ``missing_entity`` → restore the missing asset/attacker,
        or remove the orphaned CO

    Use this before relying on per-CO reach state for triage,
    auto-remediation, or audit responses. The
    ``model_coherence_report`` tool surfaces the same gaps as
    actionable findings; this tool exposes the raw verdicts when
    you need the structured data (boundary_id citations, narration
    strings) that the findings summarize.

    Args:
        model_id: ID of the threat model.
        co_id: Optional CO id. When set, returns a single verdict;
            404 if the CO doesn't exist or is tombstoned.
    """
    try:
        return _dump(
            await _get_client().model_reachability_verdicts(model_id, co_id=co_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


# === Composition (recursive-tree effective model) ===
#
# Read-only views over the *effective* model — own entities composed with
# everything inherited from ancestor threat models on the recursive tree.
# Backend-gated by ``TREE_COMPOSITION_ENABLED``. When the flag is off every
# tool below returns its stable empty shape with ``flag_enabled: false`` so
# agents can detect the disabled state without separate code paths or 404
# handling.


@mcp.tool()
async def get_composition_overview(
    server_version: str,
    model_id: str,
) -> dict:
    """Composition index for a model — counts, tree metadata, warnings.

    Cheapest call in the composition surface (~1-2KB). Use this first to
    learn whether composition is enabled, where the model sits on the
    recursive tree (parent + ancestor chain + child ids), how many own vs
    inherited entities and COs there are per kind, and whether any
    structural warnings (cycle, parent missing, max depth exceeded) need
    surfacing before drilling into sub-resources.

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

    When ``TREE_COMPOSITION_ENABLED`` is off on the backend, returns the
    same shape with all counts zeroed and ``flag_enabled: false``.

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

    Per effective CO: whether it is covered, how much credit comes from
    controls owned by this model vs inherited from ancestors, and the
    list of contributing controls (with the owning model id, origin tag,
    verification status, and mitigation group). This is the surface that
    drives the composition view's coverage / compliance numbers — it
    reflects ``TREE_COMPOSITION_ENABLED`` math, not the per-model
    coverage shown by ``get_verification_report``.

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

    When composition is disabled on the backend, ``coverage`` is empty
    and ``flag_enabled: false``.

    Omitting ``page`` / ``page_size`` defaults to ``page=1,
    page_size=100`` — the response is paginated and no longer returns
    every coverage row in a single call.

    Args:
        model_id: ID of the threat model.
        page: 1-indexed page number (default ``1``).
        page_size: coverage rows per page (default ``100``).
        origin: filter coverage rows by contributing-control origin —
            one of ``"own" | "cross" | "inherited"``. When omitted,
            rows with any origin mix are returned.
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
async def get_reach_verdicts(
    server_version: str,
    model_id: str,
    page: int = 1,
    page_size: int = 100,
    kind_filter: str | None = None,
) -> dict:
    """Per-CO reachability verdicts over the *composed* effective topology.

    Same shape as ``get_reachability_verdicts``, but evaluated against
    the merged tree: own components and trust boundaries combined with
    everything inherited, and qualified ids used for cross-model
    references. Use this when the model is a child on the composition
    tree and you need reach state that reflects the ancestor topology,
    not just the local model document.

    Return shape::

        {
          model_id, flag_enabled,
          verdicts: [
            {co_qid, asset_qid, attacker_qid,
             kind: "reachable"|"unreachable"|"indeterminate",
             reason: <structural label>},
            ...
          ],
          total, page, page_size,
        }

    When composition is disabled on the backend, ``verdicts`` is empty
    and ``flag_enabled: false`` — fall back to ``get_reachability_verdicts``
    for the per-model derivation.

    Omitting ``page`` / ``page_size`` defaults to ``page=1,
    page_size=100`` — the response is paginated and no longer returns
    every verdict in a single call.

    Args:
        model_id: ID of the threat model.
        page: 1-indexed page number (default ``1``).
        page_size: verdicts per page (default ``100``).
        kind_filter: restrict verdicts to one kind — one of
            ``"reachable" | "unreachable" | "indeterminate"``. Named
            ``kind_filter`` (not ``kind``) to disambiguate from the
            verdict object's own ``kind`` field. When omitted, all
            verdict kinds are returned.
    """
    try:
        return _dump(
            await _get_client().composition_reachability(
                model_id,
                page=page,
                page_size=page_size,
                kind_filter=kind_filter,
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


@mcp.tool()
async def list_reconciliation_candidates(
    server_version: str,
    model_id: str,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """Reconciliation candidates between this model and its ancestors.

    When a model inherits entities (assets, attackers, components, trust
    boundaries) from an ancestor *and* the operator has authored a
    locally-named entity that looks like the same real-world thing, the
    reconciliation engine surfaces the pair as a candidate so the operator
    can decide whether to alias it onto the inherited qualified id. Tier
    ``certain`` is a deterministic match (same qid or structurally
    identical) and is safe to auto-apply; tier ``heuristic`` is a fuzzy
    name/description match that needs review.

    Paginated. Use this on child models in a recursive tree to find
    duplicates that should be collapsed before they distort coverage.

    Return shape::

        {
          model_id, flag_enabled, total,
          tiers: {certain: int, heuristic: int},
          page, page_size,
          candidates: [
            {kind, own_qid, inherited_qid,
             tier: "certain"|"heuristic", reasons: [str, ...]},
            ...
          ],
        }

    When composition is disabled on the backend, ``total`` is 0,
    ``candidates`` is empty, and ``flag_enabled: false``.

    Args:
        model_id: ID of the threat model.
        page: 1-indexed page number. Default 1.
        page_size: Items per page. Default 50.
    """
    if page < 1:
        raise ToolError("page must be >= 1")
    if page_size < 1:
        raise ToolError("page_size must be >= 1")
    try:
        return _dump(
            await _get_client().composition_reconciliation(
                model_id, page=page, page_size=page_size,
            ),
        )
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
    detected, returns 400 and the operator should refresh the
    candidate list and retry. Bumps model version and emits an
    activity event on success.

    Args:
        model_id: ID of the descendant threat model the duplicate is
            on.
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

    Errors: 400 on stale candidates, or heuristic-tier candidates
    without ``confirm_heuristic``; 404 if the model isn't found; 503
    if ``TREE_COMPOSITION_ENABLED`` is off on the backend.
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
    scope so the candidate detector filters this pair out of the
    active queue on subsequent reads. Idempotent on the natural key
    ``(model_id, kind, own_qid, inherited_qid)`` — re-rejecting an
    existing pair returns the same row. Use when
    ``list_reconciliation_candidates`` surfaces a pair that looks like
    a duplicate but the operator has confirmed it is not.

    Persistence is at org scope, not model state — the rejection is
    durable across sessions and teammates but does NOT bump model
    version.

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

    Use the ``id`` field with ``unreject_reconciliation_candidate`` if
    the operator changes their mind.

    Errors: 404 if the model isn't found; 503 if
    ``TREE_COMPOSITION_ENABLED`` is off or the rejection store is not
    configured.
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
    again on the next read of ``list_reconciliation_candidates``. Use
    when the operator changes their mind about a prior rejection — the
    surrogate ``rejection_id`` comes from ``rejections[*].id`` on
    ``list_reconciliation_rejections`` (or the return value of
    ``reject_reconciliation_candidate``).

    Does NOT bump model version (rejection is org state, not model
    state).

    Args:
        model_id: ID of the descendant threat model the rejection is
            on.
        rejection_id: Surrogate id of the persisted rejection.

    Returns ``{"ok": True}`` on success.

    Errors: 404 if no rejection with that id exists on the model;
    503 if ``TREE_COMPOSITION_ENABLED`` is off or the rejection store
    is not configured.
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
async def list_reconciliation_rejections(
    server_version: str,
    model_id: str,
) -> dict:
    """List persisted reconciliation rejections for a model.

    Returns the operator's "these are NOT duplicates" decisions on this
    model in ``rejected_at`` ascending order — the same set the
    candidate detector consults to filter the active queue. Use this
    to render the rejected section of a triage view, or to find the
    surrogate id needed by ``unreject_reconciliation_candidate``.

    When ``TREE_COMPOSITION_ENABLED`` is off, returns
    ``{model_id, flag_enabled: false, rejections: []}`` so the caller
    can render the disabled state without a separate code path. The
    same empty shape is returned with ``flag_enabled: true`` when the
    rejection store is not configured on the instance.

    Args:
        model_id: ID of the threat model.

    Returns::

        {"model_id": str,
         "flag_enabled": bool,
         "rejections": [
             {"id": str, "model_id": str, "kind": str,
              "own_qid": str, "inherited_qid": str,
              "rejected_by": str, "rejected_at": <ISO-8601>},
             ...
         ]}

    Errors: 404 if the model isn't found.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().list_reconciliation_rejections(model_id),
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
    """Promote a shared-anchor entity from two sibling descendants to
    their lowest common ancestor. Mutates state across three models.

    The operator has confirmed (via the composition lift-candidate view)
    that the entity ``local_id_a`` on ``descendant_a_id`` and the entity
    ``local_id_b`` on ``descendant_b_id`` are the same logical thing
    and should be modeled once on the LCA. The route's ``model_id`` is
    the operator's current context model — typically the LCA, but the
    server accepts any ancestor of both descendants.

    Conflict resolution. The server re-detects field-level and
    attached-state conflicts against current live state before
    applying. If new conflicts have surfaced since the operator's last
    candidate fetch, the call returns 400 with the missing conflict
    keys; refresh ``composition_lift_candidates`` and resubmit with
    resolutions covering every key. Each entry in ``field_resolutions``
    / ``attached_state_resolutions`` is ``"keep_a"`` | ``"keep_b"`` |
    ``"keep_both"`` (union for list/set fields; falls back to B for
    scalars).

    Over-application gate. The lift extends visibility to every
    descendant of the LCA, not just the two source descendants. The
    server runs an over-application gate that refuses lifts touching
    descendants outside an acknowledged set; pass
    ``acknowledged_third_party_subtrees`` to acknowledge specific
    subtrees, or ``skip_overapplication_gate=True`` to override
    entirely after explicit operator confirmation.

    Each affected model (LCA + both descendants) bumps version and
    emits a ``model_refined`` activity event; a structured
    ``lift_applied`` event with the full ``lift_event`` payload lands
    on the LCA. The audit pack surfaces this under ``lift_history``.

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
        lca_model_id: Target ancestor model id (the LCA, or any
            ancestor higher up the chain).
        lca_descendant_ids: Optional snapshot of the LCA's descendant
            set used by the over-application gate. Omit to let the
            server compute it via BFS.
        acknowledged_third_party_subtrees: Optional list of subtree
            roots the operator has acknowledged as in-scope for the
            lift.
        field_resolutions: Optional per-field resolution map (e.g.
            ``{"description": "keep_both", "tags": "keep_a"}``).
        attached_state_resolutions: Optional per-state-key resolution
            map (e.g. ``{"state:assertions/AS3": "keep_b"}``).
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
    either source descendant is missing; 503 if
    ``TREE_COMPOSITION_ENABLED`` is off.
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
    """Push an ancestor-owned entity down to one or more descendants
    and soft-delete the ancestor's copy. Mutates state across the
    ancestor + every target descendant.

    Inverse of ``lift_composition_entity``. Use when an entity that
    currently lives on an ancestor is in fact descendant-specific and
    should be modeled separately per descendant — the operator chooses
    which descendants take a copy. A new local id is minted on each
    target; attached state on the ancestor's entity (assertions, jira
    mappings, risk acceptances, etc.) is duplicated to every target.

    The route's ``model_id`` IS the ancestor (the entity being split
    lives on it). Each affected model (ancestor + every target
    descendant) bumps version and emits a ``model_refined`` activity
    event; a structured ``split_applied`` event with the full
    ``split_event`` payload lands on the ancestor. The audit pack
    surfaces this under ``split_history``.

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
    structurally refused; 404 if the ancestor or any target descendant
    is missing; 503 if ``TREE_COMPOSITION_ENABLED`` is off.
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
async def preview_undo_lift_composition(
    server_version: str,
    model_id: str,
    lift_id: str,
) -> dict:
    """Preview the inverse plan (or divergence refusal) for a prior
    ``lift_applied`` event WITHOUT mutating any state.

    Read-only counterpart to ``undo_lift_composition_event``. Used by
    the confirmation flow so the operator sees what an undo would do
    before committing — either the inverse state operations the apply
    step will commit (tombstone the lifted LCA entity, restore the
    source descendants' copies, rewrite CO references), or the
    enumerated reasons the divergence detector refuses the undo.

    Args:
        model_id: The model whose composition view originated the
            lift. Must match the ``threat_model_id`` carried by the
            cited activity event; the server rejects with 404 when a
            caller tries to undo a sibling model's lift through a
            different model's URL.
        lift_id: Either the surrogate id of the ``lift_applied``
            activity event, or the structured ``lift_id`` carried in
            the event's payload — both lookups are supported.

    Returns::

        {"plan": <UndoPlan> | null,
         "refusal": <UndoRefusal> | null}

    Exactly one of ``plan`` / ``refusal`` is non-null. The plan block
    carries the inverse state operations; the refusal block carries
    the enumerated divergence reasons when state has materially
    evolved since the forward lift.

    Errors: 404 if the cited event doesn't exist or belongs to a
    different model; 503 if ``TREE_COMPOSITION_ENABLED`` is off.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not lift_id or not lift_id.strip():
        raise ToolError("lift_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().preview_lift_undo(model_id, lift_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def undo_lift_composition_event(
    server_version: str,
    model_id: str,
    lift_id: str,
) -> dict:
    """Apply the inverse of a previous ``lift_applied`` event.

    Re-runs the divergence detector immediately before applying and
    refuses with 409 + the structured refusal block when state has
    materially evolved since the forward lift (assertions submitted on
    the lifted entity, downstream COs added that reference it, the
    entity edited, etc.). On success, persists the inverse state
    operations across the LCA + every affected source descendant and
    emits a structured ``lift_undone`` activity event citing
    ``original_event_id`` so the audit pack can chain undo to its
    forward.

    Args:
        model_id: The model whose composition view originated the
            lift. Must match the cited event's ``threat_model_id`` —
            the server rejects cross-model citations with 404.
        lift_id: Either the surrogate id of the ``lift_applied``
            activity event, or the structured ``lift_id`` carried in
            the event payload.

    Returns::

        {"undone_event_id": str,
         "original_event_id": str,
         "applied_state_ops": [...],
         "models": {"lca_model": <ThreatModel>,
                    "source_descendant_models": [<ThreatModel>, ...]}}

    Errors: 409 with ``detail = {message, refusal: {reasons: [...]}}``
    when the divergence detector refuses; 404 if the cited event
    doesn't exist or belongs to a different model; 400 on payload /
    event-type mismatch; 503 if ``TREE_COMPOSITION_ENABLED`` is off.

    Operator pattern: call ``preview_undo_lift_composition`` first,
    surface the plan or refusal to the operator, and only call this
    tool after explicit confirmation.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not lift_id or not lift_id.strip():
        raise ToolError("lift_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().undo_lift(model_id, lift_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def preview_undo_split_composition(
    server_version: str,
    model_id: str,
    split_id: str,
) -> dict:
    """Preview the inverse plan (or divergence refusal) for a prior
    ``split_applied`` event WITHOUT mutating any state.

    Counterpart to ``preview_undo_lift_composition`` for splits. Same
    ``{plan, refusal}`` shape; the plan block carries the
    split-specific inverse operations (restore at the ancestor,
    tombstone the duplicated copies on every target descendant)
    instead of the lift mirrors.

    Args:
        model_id: The ancestor model whose split is being previewed.
            Must match the cited event's ``threat_model_id``.
        split_id: Either the surrogate id of the ``split_applied``
            activity event, or the structured ``split_id`` carried in
            the event payload.

    Returns::

        {"plan": <UndoPlan> | null,
         "refusal": <UndoRefusal> | null}

    Errors: 404 if the cited event doesn't exist or belongs to a
    different model; 503 if ``TREE_COMPOSITION_ENABLED`` is off.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not split_id or not split_id.strip():
        raise ToolError("split_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().preview_split_undo(model_id, split_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def undo_split_composition_event(
    server_version: str,
    model_id: str,
    split_id: str,
) -> dict:
    """Apply the inverse of a previous ``split_applied`` event.

    Mirror of ``undo_lift_composition_event`` for splits. Re-runs the
    divergence detector before applying and refuses with 409 + a
    structured refusal block when state has materially evolved since
    the forward split. On success, restores the ancestor's entity,
    tombstones the duplicated copies on every target descendant,
    persists across all affected models, and emits a structured
    ``split_undone`` activity event citing ``original_event_id``.

    Args:
        model_id: The ancestor model whose split is being undone.
            Must match the cited event's ``threat_model_id``.
        split_id: Either the surrogate id of the ``split_applied``
            activity event, or the structured ``split_id`` carried in
            the event payload.

    Returns::

        {"undone_event_id": str,
         "original_event_id": str,
         "applied_state_ops": [...],
         "models": {"ancestor_model": <ThreatModel>,
                    "descendant_models": [<ThreatModel>, ...]}}

    Errors: same shape as ``undo_lift_composition_event`` — 409 on
    divergence refusal, 404 on missing event, 400 on type mismatch,
    503 when ``TREE_COMPOSITION_ENABLED`` is off.

    Operator pattern: call ``preview_undo_split_composition`` first,
    surface the plan or refusal to the operator, and only call this
    tool after explicit confirmation.
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not split_id or not split_id.strip():
        raise ToolError("split_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().undo_split(model_id, split_id),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_control_objective(
    server_version: str,
    model_id: str,
    co_id: str,
) -> dict:
    """Get a single control objective with its composer verdict.

    Returns the CO's typed fields, the IDs of any controls that map to
    it, and the deterministic reachability verdict — the structural
    derivation that backs any reach claim on the CO.

    Tombstoned COs (``removed: true``) are returned with the flag set;
    the verdict is omitted because reach state is frozen at the
    removal version.

    Args:
        model_id: ID of the threat model.
        co_id: Control-objective ID (e.g. ``CO3``).
    """
    try:
        return _dump(await _get_client().get_control_objective(model_id, co_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def set_co_cal(
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
async def get_asset(
    server_version: str,
    model_id: str,
    asset_id: str,
) -> dict:
    """Get a single asset. Soft-deleted assets carry ``deleted: true``;
    the caller decides whether to surface them.

    Args:
        model_id: ID of the threat model.
        asset_id: Asset ID (e.g. ``A-01``).
    """
    try:
        return _dump(await _get_client().get_asset(model_id, asset_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_attacker(
    server_version: str,
    model_id: str,
    attacker_id: str,
) -> dict:
    """Get a single attacker. Soft-deleted attackers carry ``deleted: true``.

    Args:
        model_id: ID of the threat model.
        attacker_id: Attacker ID (e.g. ``T-03``).
    """
    try:
        return _dump(await _get_client().get_attacker(model_id, attacker_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_component(
    server_version: str,
    model_id: str,
    component_id: str,
) -> dict:
    """Get a single component. Speculative components (``repo_url=""``)
    are returned as-is — the empty repo IS the lifecycle state, not an
    error.

    Args:
        model_id: ID of the threat model.
        component_id: Component ID (e.g. ``CMP-01``).
    """
    try:
        return _dump(await _get_client().get_component(model_id, component_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_trust_boundary(
    server_version: str,
    model_id: str,
    tb_id: str,
) -> dict:
    """Get a single trust boundary, including its ``passes`` set
    (closed-vocabulary subset of ``{Network, Adjacent, Local, Physical}``).

    Args:
        model_id: ID of the threat model.
        tb_id: Trust-boundary ID (e.g. ``TB-Net``).
    """
    try:
        return _dump(await _get_client().get_trust_boundary(model_id, tb_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_assumption(
    server_version: str,
    model_id: str,
    assumption_id: str,
) -> dict:
    """Get a single assumption with its override applied.

    Mirrors ``list_assumptions``' merge logic for one entity. Returns
    the assumption's typed fields, structured ``exclusion`` predicate
    (when present), and the override layer (status / justification /
    linked CO IDs / target model). Soft-deleted assumptions carry
    ``deleted: true``.

    Args:
        model_id: ID of the threat model.
        assumption_id: Assumption ID (e.g. ``AS-01``).
    """
    try:
        return _dump(await _get_client().get_assumption(model_id, assumption_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_control(
    server_version: str,
    model_id: str,
    control_id: str,
    version: int = 0,
) -> dict:
    """Get a single control with verified-status enrichment and an
    ``orphaned`` flag derived from the live CO set.

    Returns the control directly (not wrapped in an array). 404 if the
    control doesn't exist on the requested version.

    Args:
        model_id: ID of the threat model.
        control_id: Control ID (e.g. ``CTL-12``).
        version: Optional model version. 0 (default) uses the latest.
    """
    try:
        return _dump(
            await _get_client().get_control(model_id, control_id, version=version),
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
    ctx: Context,
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
        client = _get_client()
        started = await client.start_edit_asset(model_id, asset_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
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
    ctx: Context,
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
        client = _get_client()
        started = await client.start_edit_attacker(model_id, attacker_id, **body)
        return await _await_backend_job(client, started["job_id"], ctx)
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
async def revalidate_threat_model_entities(
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
    """
    try:
        return _dump(await _get_client().revalidate_entities(model_id))
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

    Components bridge security architecture to code organization. They
    map trust boundaries to repos so controls can be scoped to the
    codebase that implements them. They also drive the deterministic
    reachability composer's asset-boundary derivation: an asset's
    trust-boundary footprint is the union of its components'
    ``trust_boundary_ids``.

    A component with empty ``repo_url`` is speculative — a topology
    waypoint that hasn't been bound to code yet. The coherence report
    surfaces these as ``component_unbound`` findings. Speculative
    components are valid in the lifecycle (LLM-proposed during
    generation, or operator-added during planning); ground them via
    ``edit_component`` once the code exists.

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
async def get_model_risk_view(server_version: str, model_id: str) -> dict:
    """Per-model Prioritized Risk View: one row per live Control
    Objective with derived risk tier, asset impact, attacker
    likelihood, control coverage counts, and open-finding count.

    Use to triage which COs need attention on a specific model. The
    rows already carry coverage_ratio and open_findings, so a single
    call is sufficient to rank work — no per-CO fan-out needed.
    Tombstoned COs are excluded; pair with ``get_threat_model`` if
    historical context is needed.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_model_risk_view(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_system_risk_view(server_version: str, system_id: str) -> dict:
    """System-level cross-model Prioritized Risk View: one row per
    live Control Objective across every model in a System (a System
    is a group of related threat models), with model context attached
    to each row.

    Use for posture queries spanning multiple models in the same
    product or service. Same row shape as ``get_model_risk_view``
    with ``model_id`` and ``model_title`` added per row so the agent
    can group / filter by source model without an extra lookup.

    Args:
        system_id: ID of the system.
    """
    try:
        return _dump(await _get_client().get_system_risk_view(system_id))
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

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().list_risk_acceptances(model_id))
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
            it can flip CO verdicts. Omit to leave unchanged.
        change_reason: Required when ``passes`` or ``sealed`` actually changes.
            Captured in the audit trail; documents why the boundary's vector
            filter was tightened/widened or its isolation claim changed.
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
    if change_reason is not None:
        kwargs["change_reason"] = change_reason
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
        assumption_id: ID of the assumption (e.g., "AS1").
        description: New description.
        linked_co_ids: New comma-separated CO IDs (replaces existing linkage).
        exclusion_attacker_id, exclusion_attacker_vector,
        exclusion_asset_id, exclusion_asset_component_id,
        exclusion_property_match, exclusion_co_ids: Same semantics as
            on ``add_assumption`` — supplying any of them rewrites the
            predicate.
        clear_exclusion: When True, clears the predicate. Mutually
            exclusive with the exclusion_* params (those win if both
            are sent).
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
    """List the capabilities (behaviours the feature must deliver) for a model."""
    try:
        return _dump(await _get_client().list_capabilities(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_capability(server_version: str, model_id: str, capability_id: str) -> dict:
    """Get a single capability with its component and asset bindings."""
    try:
        return _dump(await _get_client().get_capability(model_id, capability_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_functional_objectives(server_version: str, model_id: str) -> dict:
    """List the functional objectives (Capability × Condition test plan)."""
    try:
        return _dump(await _get_client().list_functional_objectives(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_objective(
    server_version: str, model_id: str, functional_objective_id: str,
) -> dict:
    """Get a single functional objective (its Given-When-Then statement)."""
    try:
        return _dump(
            await _get_client().get_functional_objective(model_id, functional_objective_id)
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_coverage(server_version: str, model_id: str) -> dict:
    """Get the functional coverage report — per-objective state (verified /
    covered / failing / untested), the Capabilities × Conditions matrix, and
    the applicable / missing-objective / not-applicable cell accounting."""
    try:
        return _dump(await _get_client().get_functional_coverage(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def check_functional_gaps(server_version: str, model_id: str) -> dict:
    """Get the actionable functional gaps: applicable conditions with no
    objective yet, and objectives that are failing or have no passing test."""
    try:
        return _dump(await _get_client().get_functional_gaps(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_scan_prompt(server_version: str, model_id: str) -> dict:
    """Get the agent brief for functional conformance. Generation specifies the
    functional tests, so this returns, for each test not yet verified, its
    implementation brief and the objectives it proves. Complete each
    instruction by implementing the described test and submitting TEST_EXISTS +
    TEST_PASSES assertions with submit_functional_tests so CI verifies it. Also
    reports objectives_without_tests (regenerate or add a test) and
    missing_objectives (applicable conditions with no objective yet)."""
    try:
        return _dump(await _get_client().get_functional_scan_prompt(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_functional_test(
    server_version: str, model_id: str, description: str,
    functional_objective_ids: str, status: str = "not_implemented",
    component_ids: str = "",
) -> dict:
    """Manually register a functional test that satisfies one or more objectives.

    Generation already specifies the tests to implement, so this is for hand-
    authoring an extra test; a manually-added test is preserved when the model
    is regenerated.

    Args:
        model_id: ID of the threat model.
        description: What the test proves.
        functional_objective_ids: Comma-separated objective ids the test satisfies.
        status: not_implemented | implemented | verified (an operator claim;
            an independent CI run is what actually verifies it).
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
    """Register existing tests from the codebase against a model's functional
    objectives, so tests you already have count toward functional conformance —
    not only Mipiti-specified tests.

    Scan the repo's test suite and pass the tests here. Optionally associate each
    with the objective ids it covers (from list_functional_objectives); the
    platform verifies each association is applicable before accepting it and
    returns any it rejected under ``rejected_mappings``. A test with no (or a
    rejected) association is still imported, unmapped, so it can be associated
    later.

    Args:
        model_id: ID of the threat model.
        tests_json: A JSON array of test objects. Each object supports
            ``test_name``, ``file_path``, ``framework``, ``description``,
            ``status`` (not_implemented | implemented | verified — an operator
            claim; an independent CI run is what verifies it), and
            ``functional_objective_ids`` (list of objective ids the test covers).
            At least ``test_name`` or ``description`` is required per test; the
            rest are optional.
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
async def submit_functional_tests(
    server_version: str, model_id: str, functional_test_id: str,
    assertions_json: str,
) -> dict:
    """Submit evidence assertions for a functional test (verified in CI).

    Args:
        model_id: ID of the threat model.
        functional_test_id: The functional test the assertions prove.
        assertions_json: JSON array of assertions, each
            {"type": "test_passes"|..., "params": {...}, "description": "...",
             "repo": "<owner>/<repo>"}. Each assertion must carry an explicit
            repo (or the "no_repo" sentinel).
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
    """Get the satisfaction groups for a functional objective.

    A satisfaction group is a set of functional tests that together satisfy the
    objective; the objective is satisfied when any one complete group is
    verified. Returns the current groups plus any ungrouped tests.

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
    """Set the satisfaction groups for a functional objective.

    Replaces the objective's groups wholesale. Each group is a set of functional
    tests that together satisfy the objective; the objective is satisfied when
    any one complete group is verified.

    Args:
        model_id: ID of the threat model.
        functional_objective_id: The objective whose groups to set.
        groups_json: A JSON object mapping group label to a list of functional
            test ids, e.g. ``{"1": ["FT-1", "FT-2"], "2": ["FT-3"]}``.
        ungrouped: Comma-separated functional-test ids to keep unassigned to any
            group (optional).
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
    """Get the sufficiency verdict for a functional test.

    Reports whether the test's evidence adequately proves the objectives it is
    associated with, along with the reasoning behind the verdict.

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


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

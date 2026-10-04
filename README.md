# Mipiti MCP Server

MCP (Model Context Protocol) server for [Mipiti](https://mipiti.io) — security posture platform.

Lets AI coding agents (Claude Code, Claude Desktop, Cursor, etc.) generate and manage threat models, controls, assumptions, compliance mapping, and evidence programmatically.

## Hosted Endpoint (Recommended)

The Mipiti backend hosts an MCP server at `https://api.mipiti.io/mcp`. No installation needed — just configure your MCP client to connect.

### Claude Code (quickstart)

```bash
claude mcp add --transport http Mipiti https://api.mipiti.io/mcp
```

You'll be prompted to log in via your browser (OAuth). That's it.

### OAuth (manual config)

MCP clients with OAuth support (Claude Code, Claude Desktop, Cursor) automatically prompt you to log in via your browser. Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "mipiti": {
      "type": "http",
      "url": "https://api.mipiti.io/mcp"
    }
  }
}
```

On first connection, your MCP client opens a browser window where you approve access with your Mipiti account. Tokens refresh automatically.

### API Key

For clients without OAuth support, or headless/CI environments, create an API key in Settings:

```json
{
  "mcpServers": {
    "mipiti": {
      "type": "http",
      "url": "https://api.mipiti.io/mcp",
      "headers": {
        "X-API-Key": "your-api-key"
      }
    }
  }
}
```

## Standalone Package (Alternative)

If you prefer running the MCP server locally (e.g., for development or self-hosted instances), install the `mipiti-mcp` package. This is a thin HTTP client that calls the Mipiti API.

```bash
pip install mipiti-mcp
# Or run directly with uvx
uvx mipiti-mcp
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MIPITI_API_KEY` | Yes | — | Your Mipiti API key |
| `MIPITI_API_URL` | No | `https://api.mipiti.io` | API base URL |
| `SERVER_VERSION` | Yes | — | Identifier for the running server's MCP surface (instructions, tool docstrings, schemas, behavior). Sent on every tool call. Clients invalidate cached MCP guidance when this changes. For local runs, any sentinel string is fine (`"local"`, `"dev"`). For deployed runs, use a value that changes when this package's source changes (commit SHA is typical). |

### Claude Code (standalone)

```json
{
  "mcpServers": {
    "mipiti": {
      "command": "uvx",
      "args": ["mipiti-mcp"],
      "env": {
        "MIPITI_API_KEY": "your-api-key",
        "SERVER_VERSION": "local"
      }
    }
  }
}
```

## Tools (<!--MCP_TOOL_COUNT-->128<!--/MCP_TOOL_COUNT-->)

### Threat Modeling

| Tool | Description |
|------|-------------|
| `generate_threat_model` | Generate a complete threat model from a feature description. Runs a multi-step AI pipeline producing trust boundaries, assets, attackers, control objectives, and assumptions. Progress reported automatically via MCP protocol — the tool blocks until complete. Optional `provenance_*` params record where the description came from at creation (for a repository: `provenance_kind="code"` + `provenance_repo_url` + `provenance_commit_sha`). |
| `update_threat_model` | Change a model's metadata: `name` (no new version; titles are unique within a workspace, case-insensitive), `parent_id` or `clear_parent` (its place on the recursive composition tree; no new version), and the `provenance_*` values (where its description came from: `code` with a commit SHA means the code is authoritative and the model follows it, anything else means the description is intent and the code is measured against it; bumps the version). Changes apply in that order; a failure names the ones already applied. |
| `refine_threat_model` | Refine an existing threat model based on an instruction. Creates a new version. Only affected entity types are modified — unaffected entities are preserved server-side. An instruction that cannot be applied (a targeted change naming an entity the model does not have) writes nothing and returns `{model_id, changed: false, message}`. |
| `query_threat_model` | Ask a question about an existing threat model. It only answers; it never changes the model. |
| `get_threat_model` | Get the full details of a specific threat model (trust boundaries, assets, attackers, assumptions). Use `include_cos=True` to include control objectives. |
| `list_threat_models` | List all saved threat models with IDs, titles, versions, and creation dates. Supports `source` filter and `include_assessment_summary=True` to inline per-model posture counts in one call (avoids N+1 looping `assess_model`). |
| `delete_threat_model` | Permanently delete a model and all its data. |
| `export_report (scope="model")` | Export as PDF, HTML, or CSV. |
| `export_report (scope="model", format="archive")` | Export the self-contained JSON audit archive of the model's current state (latest version, controls, live assertions with CI verdicts, findings, decisions in force, attestations, sufficiency signatures). Independently verifiable: the verdicts in it are the origin's record of what it claimed, which is what a third party checks against the signatures. |
| `import_threat_model_archive` | Restore an audit archive into a target workspace as version 1 of a new model. Fresh `model_id` per import; title collisions auto-suffix. It queues no judgement: the result carries the estimate, and `judge_objectives` queues it on request. The restored model arrives unverified — the origin's assertion verdicts and run-attested flags are not credited in the importing workspace, which earns them by running verification against code it can reach. |

### Entity CRUD

| Tool | Description |
|------|-------------|
| `add_asset` / `edit_asset` / `remove_entity (entity_type="asset")` | Targeted single-entity changes for assets. Creates a new version. |
| `add_attacker` / `edit_attacker` / `remove_entity (entity_type="attacker")` | Same for attackers. `surface_extent` (`whole`: the attacker's operations range over any entry of the interface it reaches; `point`: one named entry) is an operator declaration: supplying it attests it and requires `change_reason` on either tool, and an attested `whole` makes the objectives that attacker anchors for-all obligations. A create declares only `whole`; narrowing is an `edit_attacker` call, checked against the objectives the attacker anchors. |
| `revalidate_entity_quality` | Judge every live asset's and attacker's quality warning again, in the background. Creates no version; returns `{accepted, queued, model}`, and the refreshed warnings appear on the next read of the model. |
| `get_entity` | Read one entity of any kind. An attacker also carries `surface_extent` and `surface_extent_source`, which says whether a person attested it. |

### Trust Boundaries

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing trust boundaries (along with assets, attackers, assumptions). Review current boundaries before adding or modifying. |
| `add_trust_boundary` / `edit_trust_boundary` / `remove_entity (entity_type="trust_boundary")` | CRUD for trust boundaries. Defines where trust transitions occur in the system architecture. Attackers are positioned at boundaries; COs are annotated with boundary reachability. Changes auto-generate boundary assumptions for newly unreachable COs. |

### Controls

| Tool | Description |
|------|-------------|
| `get_controls` | List controls with current status. Use `summary_only=True` for a compact response (id, description, status, verification_status, assertion_count, co_ids, assumption_groups, attestation_dependency). |
| `get_control_objectives` | List COs with which controls cover each one. Pair with `get_reachability_verdicts` for per-CO composer reachability state. |
| `update_control_status` | Mark implemented or not_implemented. Requires at least one assertion first. |
| `refine_control` | Modify a control's description with justification. Platform evaluates whether the mitigation group still covers the COs. An accepted refinement keeps the control's assertions and judges them again against the new description; nothing is superseded. |
| `regenerate_controls` | Propose a regeneration of the controls; it starts nothing. Supports `mode="per_co"` and `co_ids` to target specific COs. |
| `get_control_generation_status` | The model's proposed control build (`proposal`, with its estimate and the `model_version` and `set_revision` a start must name) and the last build started: its status, progress, and the next action (`hint`). |
| `start_control_build` | Start the proposed build. Generating or refining a model, editing an entity and `regenerate_controls` each propose one and start nothing. Call once for the proposal and a fresh estimate, then with `confirm_estimate=True` and the `model_version` and `set_revision` reviewed. A started build holds the model until it publishes its result in one step; meanwhile other writers of its controls are refused and reads show the last published controls. |
| `discard_control_build` | Drop a held build (queued, deferred, paused or blocked): what it staged is discarded, the published controls are untouched, and the build is proposed again. A running build is paused first. |
| `list_control_revisions` / `undo_model_change` | Every change to a version's controls, with its author. `undo_model_change(target="controls")` undoes the latest one (latest first, no redo); `target="version"` replaces the latest model version with a copy of the latest earlier version not already discarded, keeping the replaced version in the history as discarded. |
| `pause_control_generation` | Pause a model's control build (for example one started by mistake). A running build stops at its next step; everything done so far is kept unpublished, nothing new is started or billed, and nothing resumes it except `resume_control_generation`; `discard_control_build` drops it instead. A paused model can then be deleted as usual. |
| `resume_control_generation` | Resume control generation that was paused (`get_control_generation_status` reports `paused`), or retry one that stopped before finishing (`blocked`): a service it depends on was unavailable, or some new controls could not be checked for duplicates and were held back. A paused run resumes at once; for a blocked one the services are checked first, so a retry during an outage costs nothing. Either way only the unfinished work runs, billed to the original generation. |
| `strengthen_controls` | Work on the objectives whose mitigation groups the background judge found do not cover them. Generation stops after drafting and judging unless the workspace strengthens automatically; `get_control_generation_status` reports the `diagnosis`. Call once for the estimate (nothing starts, nothing is charged), then with `confirm_estimate=True` and the `model_version` and `set_revision` the estimate returned to start a background run. A gap only the environment can close is answered with an assumption, never a control: an accepted one is bound into the group, and otherwise a proposal waits in the review queue for a person. |
| `judge_objectives` | Judge every objective that has no judgement for its current controls and none queued: the diagnosis's `not_judged` count (`judging` counts the ones already queued; wait for those). Call once for the estimate (nothing is queued, nothing is charged), then with `confirm_estimate=True` to queue; any credits it consumes are metered as each judgement runs. Objectives with no mitigation group come back in `ungrouped` and are not judged. Not a repair: a judgement can come back insufficient. Refusals (`409` generation in progress, `402` balance, `503` unavailable) come back as data. |
| `import_controls` | Import controls from JSON or free text, auto-mapped to COs and deduplicated. The imported controls await their judgement: the groups they join credit nothing until it is asked for. |
| `judge_imported_controls` | Estimate, and with `confirm_estimate=True` queue, the judgement of the imported controls awaiting one. |
| `delete_control` | Soft-delete with justification. Blocked if it's the only control covering a CO. |
| `check_control_gaps` | AI-powered gap analysis across all controls. |
| `get_mitigation_groups` / `set_mitigation_groups` | Inspect and modify how controls are grouped into mitigation paths for a CO (AND within groups, OR across groups). Platform AI-evaluates whether proposed changes preserve CO coverage. |
| `set_control_objective_cal` | Set per-CO ISO/SAE 21434 Cybersecurity Assurance Level (1-4). Persisted on the control_objectives identity side-table; survives soft-delete + revival; no new model version. |

### Assumptions and Attestation

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing assumptions (along with assets, attackers, trust boundaries). Review current assumptions before adding or modifying. |
| `add_assumption` | Add an assumption, optionally linking it to COs via `linked_co_ids`. |
| `edit_assumption` | Update description and/or linked COs. |
| `remove_entity (entity_type="assumption")` | Soft-delete (preserved for audit). Its CO links are cleared and its attestations retired. |
| `restore_entity (entity_type="assumption")` | Restore a soft-deleted assumption to active. Its CO links are not restored (set them with `edit_assumption`), and it must be attested again. |
| `submit_attestation` | Record that a responsible party affirmed an assumption holds. Provide `attested_by`, `statement`, `expires_at`. A claim, never a proof over every site: it can cover an existential clause and never a for-all one. Attesting accepts the assumption, a judgment: a program is refused with 403 and an `escalation_id` unless the workspace delegates `assumption_accepted` to it. Editing the assumption's description retires the attestation. |
| `list_attestations` | Attestation history for an assumption. |
| `set_control_assumption_groups` | Declaratively set a control's assumption group structure: mark it externally handled by a single assumption (shorthand), clear the groups (the control's status is not changed), or express compound cases with multiple groups (within a group = AND, across groups = OR; e.g. "AWS KMS + quarterly review"). Attested groups count as active for mitigation group completeness. |
| `get_control_assumption_groups` | Inspect the current assumption group structure on a control. Groups express alternative sets of external claims (within = AND, across = OR). |
| `convert_assumption_to_controls` | Retire the assumption linkage and propose the control build its COs owe; `start_control_build` starts it. |

### Assertions and Evidence

| Tool | Description |
|------|-------------|
| `get_assertion_types` | The catalogue as data: every type, what it proves, its soundness class, its params (an array-valued param carries its item schema), and the class vocabulary. Read-only. |
| `submit_assertions` | Submit typed, machine-verifiable claims about system properties (<!--ASSERTION_TYPE_COUNT-->30<!--/ASSERTION_TYPE_COUNT--> assertion types) for a control, an assumption or a functional test (name one of `control_id`, `assumption_id`, `functional_test_id`). Each object for a control may carry `covers`: the objective id (`CO-NN`) or clause ids (`cls_…`) it proves; a declared binding survives review, an undeclared one is inferred and capped below sound credit. |
| `list_assertions` / `delete_assertion` | List or delete assertions for a control. |
| `edit_evidence` | Attach (`action="add"`) or detach (`action="remove"`) auxiliary metadata (docs, links). Evidence is contextual — only assertions prove implementation. |
| `get_verification_report` | Shows verified, partially verified, and unverified controls with sufficiency details. |
| `get_sufficiency` | Quick check: do the assertions of one control (or one functional test, with `functional_test_id`) collectively cover all aspects? For the per-clause work list read `get_control_work_order`: where the order names a required class for a clause, `required_evidence` carries the class, the clause id to bind evidence to, and a submission skeleton to fill in. A claim that carries a `soundness_tier` reports its weakest clause's tier. |
| `get_scan_prompt` | Returns targeted prompts for scanning the codebase against not_implemented controls. |
| `get_review_queue` | The workspace review queue, ranked: `escalation`, `proposal` (including `assumption` proposals a strengthening run raised), `unaccepted_assumption` (an assumption something depends on that is not accepted), `open_assumption`, `stale_control` (implemented/verified controls not checked in 90+ days). Escalations and proposals are decided with `decide_proposal`; an unaccepted assumption is accepted with `submit_attestation`. Start here for periodic maintenance. |
| `submit_findings` / `list_findings` / `update_finding` | Report and track negative findings (gap discovery). |
| `remediate_finding` | Without `apply`, read-only: a structured diff of the changes the remediation would make, shaped by the finding's kind (e.g. for `structural_duplicate_controls`: which controls would be kept, which dropped, the union of CO mappings + framework refs that would land on the survivor). With `apply=True` and a non-empty `justification` (one-line operator rationale, recorded on the audit trail), it commits them. The agent is responsible for the preview-then-apply norm — surface the diff and get explicit confirmation before applying. |

### Evidence soundness classes

Every assertion type declares the class of the fact it reports, and the class bounds what a passing verdict can establish. `get_assertion_types` returns it per type; the platform and the CI verifier hold their own tables equal to the catalogue's.

| Class | A pass establishes | Types |
|-------|--------------------|-------|
| `presence` | A named construct, configuration value, dependency, file or pattern occurrence exists in the tree. Existence, not behaviour; a test file existing is presence. | `function_exists`, `class_exists`, `test_exists`, the configuration, dependency, semantic and RTL structure types |
| `under_approximating_scan` | A syntactic scan over a scope with no false-positive guarantee. A clean result proves the absence of the syntactic form only. | `pattern_matches`, `pattern_absent`, `no_plaintext_secret` |
| `existential_witness` | A signed statement that a named execution ran and passed at this commit. Proves the path it drove and nothing beyond it. | `test_attested` |
| `sound_over_approximation` | Every site in a declared scope that can violate the property was enumerated, and each is a declared safe form or a reviewed exception. Sound modulo the declared sink list. | `sink_default_deny` |
| `by_construction` | The sink accepts only a declared boundary type, and every construction site of that type is default-denied. | `typed_boundary` |

A clause that ranges over every entry of a surface (every endpoint, every query, every frame) is credited only by one of the two sound classes bound to it with `covers`; a test proves only the path it drove, and an attestation is a responsible party's claim. Which types carrying those classes a platform takes is a read, not an assumption: `get_control_work_order`'s `assertion_contract.sound_types` names them, and where it names none the acts that remain are to scope the asset to the component the attacker actually reaches, attest a `point` extent with its reason, or record a risk acceptance or a not-applicable disposition. The two sound types take a declared `scope`, the `sinks` through which the property could be violated (a call, a constructor, a macro, a store to a named target such as an HDL assignment, or a module instantiation), a reviewed `allowlist`, and the `property` in one sentence; `sink_default_deny` adds the accepted `safe_forms`, `typed_boundary` the `boundary_type` and its `constructors`. Hardware sources are covered by the same rule.

### Agent work orders & delegation

| Tool | Description |
|------|-------------|
| `get_control_work_order` | The ticket for implementing one control: scan brief, what counts as proof (assertion contract), acceptance criteria, steps, reconcile rules, what this agent may decide on its own, open proposals, and the model's provenance. Call before implementing a control. Read-only. |
| `reconcile_model` | Reconcile the model with the code: pass the paths changed since the recorded commit and your observations (`mechanism_named`, `component_present`, `component_absent`, `forbidden_behavior`). The platform decides the consequence of each; proposals are never applied on the agent's word, except a component change on a code-derived model, which is applied and queued for a person's review. |
| `create_proposal` | Raise a change of scope or design (`add_component`, `remove_component`, `design_change`), or an `assumption` a gap needs that only the environment can meet. Raising is not deciding: a person (or an agent under a delegation rule) decides it with `decide_proposal`; design changes are never applied automatically. |
| `list_proposals` | Proposals and escalations on a model with their status (`proposed` / `applied_pending_review` open; `accepted` / `rejected` / `reverted` / `superseded` closed). A refused judgment (403 with `escalation_id`) appears as a `decision_request`; poll here until a person resolves it. Read-only. |
| `decide_proposal` | Accept or reject a proposal. A judgment: refused with 403 and an `escalation_id` unless the workspace's delegation policy names the decision for this agent at the proposal's tier. Do not retry a refusal. Accepting an `assumption` proposal accepts the assumption (its own decision, `assumption_accepted`), attested until `expires_at`; rejecting one keeps the precondition from being proposed again. |
| `get_design_leverage` | What eliminating each attacker position or asset by design would remove from the matrix, ranked by critical then high at-risk objectives removed. `include_design_moves=True` authors a concrete `design_move` per row; turn one into a `design_change` proposal with `create_proposal`. Read-only. |
| `list_decisions` | The model's decision ledger: every judgment recorded on it (finding dismissed / remediated, risk accepted, not-applicable declared, proposal accepted / rejected / reverted, assumption accepted, escalation resolved), newest first, with who decided and whether it was within the delegation policy. Append-only; nothing edits it. Call before raising a proposal or asking for a judgment, so you do not propose what a person rejected or ask again for what was already decided. Read-only. |

### Assurance

| Tool | Description |
|------|-------------|
| `assess_model` | Deterministic assessment of all COs. Returns mitigated/at_risk/unassessed with `risk_reason` (missing_controls, pending_attestation, expired_attestation, coverage_gap, insufficient_by_design). For per-CO reachability state call `get_reachability_verdicts`. |
| `get_findings_risks` | Workspace-scoped triage dashboard: open findings, active risk acceptances, and at-risk COs across every model the workspace can access. Entry point when asked "what's open?". |
| `get_risk_view (scope="model")` | Per-model Prioritized Risk View: one row per live CO with derived risk tier, asset impact, attacker likelihood, control coverage, and open-finding count. |
| `get_risk_view (scope="tag")` | Cross-model variant of `get_risk_view (scope="model")`: same shape, aggregated across every member of a tag (model_id + model_title attached per row), and delegation-aware. |
| `get_remediation_leverage` | Per-model remediation plan: the not-yet-satisfied controls ranked by how many COs each one closes, plus a greedy minimal fix order (`summary` / `ranked` / `greedy_plan`). Use to prioritize which controls to implement first for the shortest path to coverage. |
| `list_risk_acceptances` | All risk acceptances on a model — risks explicitly accepted instead of mitigated. Includes CO id, owner, justification, status, review deadline. |
| `create_co_disposition` | Record that a control objective does not apply to this system (owner, justification, review deadline). The sibling of a risk acceptance: an acceptance says the exposure is real and is being carried, a disposition says the objective does not apply here at all. The objective stays in the matrix and in every coverage count, reported in its own class — what is suppressed is work (no controls generated, no coverage gap raised), never the accounting. |
| `list_co_dispositions` | Every signed judgment on a model's objectives, both kinds. Expired and revoked entries are included: a lapsed decision is part of the audit trail. Optional `kind` filter. |
| `recompute_verdicts` | `mode="quote"` (the default) returns the informational cost estimate and enqueues nothing (carries `computed_at` + the pricing `rate_version`). `mode="recompute"` force-enqueues a fresh evaluation of every control's coverage verdict and every live CO's group-sufficiency verdict, bypassing the quiet-period batching; actuals are metered as evaluation runs. `mode="retry_parked"` re-runs only the verdicts a transient failure parked, of every kind. Each carries a spend status object — exhausted means the work is queued and resumes automatically, never dropped. |
| `judge_objective` | Have ONE control objective's mitigation group judged — the remedy for an objective reading `awaiting_judgement`, where a group is built and nothing has decided whether it covers the objective. Prefer it over `recompute_verdicts`, which sweeps the whole model. Runs in the background and may consume credits. Not a repair: the judgement can come back insufficient, moving the objective to `coverage_gap` / `insufficient_by_design`. Refusals (`409` generation in progress, `503` unavailable, `402` balance) come back as data. |

### Functional Conformance

Proves a feature *does what it was specified to do* (Capability × Condition), verified by the same assertion + CI engine as security controls.

| Tool | Description |
|------|-------------|
| `generate_functional_objectives` | Derive capabilities (behaviours the feature must deliver), Given-When-Then functional objectives (walking each capability against a taxonomy of operating conditions), **and a concrete implementable test per objective** — so the agent implements the tests rather than deciding what to test. Requires a Pro plan; billable. `refresh=true` re-derives. |
| `get_capabilities` | Read the capability decomposition: every capability, or one by `capability_id`. |
| `get_functional_objectives` | Read the functional objectives (the test plan). |
| `get_functional_coverage` | Per-objective + per-test state (verified / covered / failing / untested), the Capabilities × Conditions matrix, and applicable / missing-objective / not-applicable cell accounting. `gaps_only=True` returns just the actionable gaps: applicable conditions with no objective yet, plus objectives that are failing or untested. |
| `get_scan_prompt (kind="functional")` | The agent brief: per not-yet-verified test, its implementation brief and the objectives it proves; plus objectives with no test and applicable conditions with no objective. |
| `add_functional_test` | Manually register an extra test satisfying one or more objectives (generation already specifies the tests; a manual test survives regeneration). |
| `submit_assertions (functional_test_id=…)` | Submit evidence assertions for a functional test (verified in CI, same as control evidence). |

### Composition (recursive-tree effective model)

Views over the *effective* model — own entities composed with everything inherited from ancestor threat models on the recursive tree. Available where the deployment enables composition; where it does not, read tools return a stable empty body with `flag_enabled: false` and the write tool returns 503.

| Tool | Description |
|------|-------------|
| `get_composition (view="overview")` | Index: counts + tree metadata (`parent_id`, `ancestor_chain`, `depth`, `child_ids`) + structural warnings. Cheapest call — use first to learn whether composition is enabled and orient on the tree. |
| `get_composition (view="entities")` | Effective entity set keyed by kind (trust boundaries, components, assets, attackers, attack paths). Each entry carries provenance (`own` vs `inherited`) and a fully-qualified id for cross-model references. |
| `get_composition (view="objectives")` | Effective COs tagged with origin (`own` / `cross` / `inherited`). Pair with `view="coverage"` and `get_reachability_verdicts (composed=True)`. |
| `get_composition (view="coverage")` | Per-CO coverage with credited inheritance: `own_credit`, `inherited_credit`, and the list of contributing controls (with the owning model id, origin, verification status, mitigation group). This is what drives the composition coverage view, not per-model `get_verification_report`. |
| `get_reachability_verdicts (composed=True)` | Per-CO reachability verdicts over the composed effective topology — same kinds (`reachable` / `unreachable` / `indeterminate`) as `get_reachability_verdicts`, but evaluated against the merged tree. Use on child models when ancestor topology matters. |
| `get_composition (view="attack_paths")` | Effective AttackPath set + lifted missing/dangling suggestions computed against the composed reach surface. |
| `list_reconciliation_candidates` | Paginated reconciliation candidates between this model and its ancestors. Tier `certain` is a deterministic match safe to auto-apply; tier `heuristic` is fuzzy and needs review. With `disposition="rejected"`, the persisted rejections instead, oldest first, each with the surrogate id an unreject names. |
| `decide_reconciliation_candidate` | Mutating. `decision="apply"` records that the descendant's own entity is the inherited one: the own entity stays in the model and the composed view leaves it out, so the inherited entity is canonical (the record is dropped when the pair stops matching); the server re-validates against current live state and refuses a heuristic-tier candidate unless `confirm_heuristic=True`; bumps the model version and returns `{model, controls_carried, controls_orphaned, orphaned_control_ids}`. `decision="reject"` persists "these are NOT duplicates" at org scope, so the detector leaves the pair out of the active queue; idempotent on `(model_id, kind, own_qid, inherited_qid)`, no new version, returns the record (keep its `id`). `decision="unreject"` removes a rejection by `rejection_id`, returning `{ok: true}`. |
| `lift_composition_entity` | Mutating. Promote a shared-anchor entity from two sibling descendants to their lowest common ancestor: each source's copy is soft-deleted and the inherited entity becomes canonical for every descendant of the LCA. Server re-detects field-level and attached-state conflicts against current live state; pass `field_resolutions` / `attached_state_resolutions` keyed by the conflict keys returned in the 400 detail. Server also runs an over-application gate against the LCA's descendant set; pass `acknowledged_third_party_subtrees` to acknowledge extra reach or `skip_overapplication_gate=true` to override after explicit operator confirmation. Bumps version on the LCA + both source descendants; returns `{lift_id, lca_model, descendant_a_model, descendant_b_model, applied_migrations, lift_event}` — the `lift_event` block matches the audit pack's `lift_history` entry. |
| `split_composition_entity` | Mutating. Inverse of `lift_composition_entity`: push an ancestor-owned entity down to one or more target descendants and soft-delete the ancestor's copy. A new local id is minted on each target; attached state (assertions, jira mappings, risk acceptances) on the ancestor's entity is duplicated to every target. Bumps version on the ancestor + every target descendant; returns `{split_id, ancestor_model, descendant_models, applied_duplications, split_event}` — the `split_event` block matches the audit pack's `split_history` entry. |
| `undo_composition_event` | Undo a prior lift or split (`event_type="lift"` or `"split"`). By default (`dry_run=True`) read-only: the inverse plan or the divergence refusal, as `{plan, refusal}` with exactly one non-null — surface it to the operator. With `dry_run=False`, mutating: re-runs the divergence detector and refuses with 409 + `detail.refusal.reasons` when state has materially evolved since the forward event; on success persists the inverse across every affected model and emits a `lift_undone` / `split_undone` activity event citing `original_event_id`, so the audit pack chains undo to its forward. Returns `{undone_event_id, original_event_id, applied_state_ops, models}`, `models` being `{lca_model, source_descendant_models}` for a lift and `{ancestor_model, descendant_models}` for a split. |

### Cross-model dependencies (delegation)

Declared reliance edges (distinct from the parent/composition tree, which is containment): a model depends on a control implemented in *another* model — for systems built on shared services (auth, logging, shared data) rather than sub-parts. The target is always a provider *control* (credit terminates at a proven mechanism). Reliance is workspace-scoped: a consumer can only delegate to provider models in the same workspace (these tools don't see models across workspace boundaries). Available where the deployment enables the model tree; whether reliance carries credit is also a deployment setting.

| Tool | Description |
|------|-------------|
| `declare_foundation` | Mark a shared-service model as a foundation that advertises specific controls (`provides`) other models can delegate to. A capability advertises a control, never an objective. |
| `manage_reliance` | One edge at a time. `action="create"` declares a dependency: `delegated` (consumer has no local control for an objective; provider handles it — pass `source_objective_id`) or `relied_upon` (consumer keeps its own control but its validity depends on the provider's — pass `source_control_id`); it enters `draft` and runs LLM semantic validation. `action="confirm"` promotes a draft edge to active — the credit-soundness gate, refused unless validation returned `valid` (a `partial`/mode-mismatch is never silently credited). `action="delete"` removes an edge. |
| `list_reliance` | A model's dependency edges (as consumer) plus who relies on it (as provider — the blast radius before changing its controls). |
| `attach_foundation` | Without `selections`, read-only: which of a consumer's objectives each foundation capability covers (scored). With the chosen subset as `selections`, bulk-creates draft delegation edges for those (objective, provider control) pairs; each runs LLM validation and none credits until confirmed. |

### Tags (grouping)

Overlapping, semantics-free grouping of models (the Affiliation primitive) — for audit scopes, products, ad-hoc selections, or portfolios. A model may carry many tags; a tag never affects posture or credit. The group tools act on tags.

| Tool | Description |
|------|-------------|
| `create_group` / `delete_group` | Create or remove a tag (deleting affects the grouping only, not the member models). |
| `add_model_to_group` / `remove_model_from_group` | Manage membership; a model can belong to many tags at once. A model added to a tag takes on the frameworks the tag selected. |
| `list_groups` / `get_group` / `list_model_groups` | Browse the workspace's tags, read one with its members, or list a model's tags. |
| `get_group_dependencies` | The reliance edges among a tag's members, each with its status and whether it credits its objective. |
| `get_risk_view (scope="tag")` | Aggregate per-CO risk across a tag's members. Delegation-aware (a CO mitigated via a verified cross-model delegation reads as covered). |
| `select_compliance_frameworks (scope="tag")` | Make a tag a compliance/audit scope: select frameworks for the tag, propagated to its members and to every model added later. |
| `get_compliance_report (scope="tag")` | Cross-model compliance coverage report scoped to a tag's members. |
| `export_report (scope="tag")` | Signed auditor HTML for a tag: every member's report, after the reliance edges among the members with their status. |

### Compliance

| Tool | Description |
|------|-------------|
| `list_compliance_frameworks` | Available frameworks: the built-ins (among them OWASP ASVS, ISO 27001, SOC 2, NIST CSF, IEC 62443, ISO/SAE 21434, PCI DSS, GDPR) and any imported. |
| `import_compliance_framework` | Import a customer-specific framework (JSON: `name`, `requirements`, optional `level_definitions`). |
| `select_compliance_frameworks` | Select frameworks for a model, or for a tag (`scope="tag"`). |
| `get_compliance_report` | Coverage report for a selected framework. |
| `auto_map_controls` | AI-powered semantic mapping of controls to framework requirements. |
| `map_control_to_requirement` | Manual control-to-requirement mapping. |
| `auto_remediate_compliance` | LLM-powered gap closure — proposes new assets, attackers, and controls for uncovered framework requirements. |

### Components

| Tool | Description |
|------|-------------|
| `add_component` / `edit_component` / `remove_entity (entity_type="component")` | Components bridge trust boundaries (security architecture) to repositories (code organization). `Component(id, name, repo_url, path, trust_boundary_ids)` scopes controls to the codebase that implements them. Used for multi-repo systems and per-repo threat models. `edit_component` also accepts optional per-component level grades: `target_sl` (IEC 62443 Security Level, 1-4), `eal` (Common Criteria Evaluation Assurance Level, 1-7), `fips_level` (FIPS 140-3 Security Level, 1-4). |

### Organizations

| Tool | Description |
|------|-------------|
| `update_organization` | Set per-organization level grades: `target_ml` (IEC 62443-4-1 Maturity Level, 1-5), `csf_tier` (NIST CSF Tier, 1-4). Admin-only. Use `clear_target_ml` / `clear_csf_tier` to explicitly reset to NULL. |

### Setup and Operations

| Tool | Description |
|------|-------------|
| `get_setup_status` | Check which onboarding steps are done. |
| `complete_setup_step` | Mark an onboarding step as done (mcp_configured, mipiti_verify_installed, ci_secret_added, ci_pipeline_added). |

### CWE Classification

| Tool | Description |
|------|-------------|
| `get_cwe_catalog` | Get the platform's CWE reference catalog status (current MITRE version, entry count). Reports `enabled: false` when not turned on for this instance. |
| `get_model_cwe_tags` | List CWE weakness classifications tagged onto a model's control objectives, with a staleness marker for tags whose catalog entry has since been deprecated, redefined, or removed. |
| `classify_model_cwe` | Classify a model's control objectives against the platform CWE catalog. Grounded — the model may only select from the catalog's current candidates, and every returned id is re-validated before storage. |

## Development

```bash
git clone https://github.com/Mipiti/mipiti-mcp.git
cd mipiti-mcp
pip install -e ".[dev]"
python -m pytest -v
```

## Local Testing with Claude Desktop

```json
{
  "mcpServers": {
    "mipiti": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/mipiti-mcp", "mipiti-mcp"],
      "env": {
        "MIPITI_API_KEY": "your-key",
        "SERVER_VERSION": "local"
      }
    }
  }
}
```

## License

Proprietary. Copyright (c) 2026 Mipiti, Inc. All rights reserved. See [LICENSE](LICENSE) for details.

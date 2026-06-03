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

## Tools (<!--MCP_TOOL_COUNT-->122<!--/MCP_TOOL_COUNT-->)

### Threat Modeling

| Tool | Description |
|------|-------------|
| `generate_threat_model` | Generate a complete threat model from a feature description. Runs a multi-step AI pipeline producing trust boundaries, assets, attackers, control objectives, and assumptions. Progress reported automatically via MCP protocol — the tool blocks until complete. |
| `refine_threat_model` | Refine an existing threat model based on an instruction. Creates a new version. Only affected entity types are modified — unaffected entities are preserved server-side. |
| `query_threat_model` | Ask a question about an existing threat model. |
| `get_threat_model` | Get the full details of a specific threat model (trust boundaries, assets, attackers, assumptions). Use `include_cos=True` to include control objectives. |
| `list_threat_models` | List all saved threat models with IDs, titles, versions, and creation dates. Supports `source` filter and `include_assessment_summary=True` to inline per-model posture counts in one call (avoids N+1 looping `assess_model`). |
| `rename_threat_model` | Rename a model (metadata only, no new version). Titles must be unique within a workspace (case-insensitive). |
| `delete_threat_model` | Permanently delete a model and all its data. |
| `export_threat_model` | Export as PDF, HTML, or CSV. |
| `export_threat_model_archive` | Export the self-contained JSON audit archive (every version, controls, assertions with CI verdicts, findings, attestations, sufficiency signatures). Independently verifiable. |
| `import_threat_model_archive` | Restore an audit archive into a target workspace. Fresh `model_id` per import; title collisions auto-suffix. |

### Entity CRUD

| Tool | Description |
|------|-------------|
| `add_asset` / `edit_asset` / `remove_asset` | Targeted single-entity changes for assets. Creates a new version. |
| `add_attacker` / `edit_attacker` / `remove_attacker` | Same for attackers. |

### Trust Boundaries

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing trust boundaries (along with assets, attackers, assumptions). Review current boundaries before adding or modifying. |
| `add_trust_boundary` / `edit_trust_boundary` / `remove_trust_boundary` | CRUD for trust boundaries. Defines where trust transitions occur in the system architecture. Attackers are positioned at boundaries; COs are annotated with boundary reachability. Changes auto-generate boundary assumptions for newly unreachable COs. |

### Controls

| Tool | Description |
|------|-------------|
| `get_controls` | List controls with current status. Use `summary_only=True` for compact response. |
| `get_control_objectives` | List COs with which controls cover each one. Pair with `get_reachability_verdicts` for per-CO composer reachability state. |
| `update_control_status` | Mark implemented or not_implemented. Requires at least one assertion first. |
| `refine_control` | Modify a control's description with justification. Platform evaluates whether the mitigation group still covers the COs. |
| `regenerate_controls` | Regenerate controls. Supports `mode="per_co"` and `co_ids` to target specific COs. |
| `import_controls` | Import controls from JSON or free text, auto-mapped to COs and deduplicated. |
| `delete_control` | Soft-delete with justification. Blocked if it's the only control covering a CO. |
| `check_control_gaps` | AI-powered gap analysis across all controls. |
| `get_mitigation_groups` / `set_mitigation_groups` | Inspect and modify how controls are grouped into mitigation paths for a CO (AND within groups, OR across groups). Platform AI-evaluates whether proposed changes preserve CO coverage. |
| `set_co_cal` | Set per-CO ISO/SAE 21434 Cybersecurity Assurance Level (1-4). Persisted on the control_objectives identity side-table; survives soft-delete + revival; no new model version. |

### Assumptions and Attestation

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing assumptions (along with assets, attackers, trust boundaries). Review current assumptions before adding or modifying. |
| `add_assumption` | Add an assumption, optionally linking it to COs via `linked_co_ids`. |
| `edit_assumption` | Update description and/or linked COs. |
| `remove_assumption` | Soft-delete (preserved for audit). Linked COs are no longer mitigated by it. |
| `restore_assumption` | Restore a soft-deleted assumption. Re-attestation required. |
| `submit_attestation` | Record that a responsible party affirmed an assumption holds. Provide `attested_by`, `statement`, `expires_at`. |
| `list_attestations` | Attestation history for an assumption. |
| `assume_control` | Shorthand: mark a control as externally handled by a single assumption (writes to group 1). Counts as active for mitigation group completeness when attested. |
| `unassume_control` | Shorthand: clear externally-handled status; control reverts to not_implemented. Removes all assumption groups. |
| `get_control_assumption_groups` | Inspect the current assumption group structure on a control. Groups express alternative sets of external claims (within = AND, across = OR). |
| `set_control_assumption_groups` | Declaratively set the assumption group structure. Use for compound cases (e.g. "AWS KMS + quarterly review") or multiple independent paths. |
| `convert_assumption_to_controls` | Generate controls for assumption-covered COs and retire the assumption linkage. |

### Assertions and Evidence

| Tool | Description |
|------|-------------|
| `submit_assertions` | Submit typed, machine-verifiable claims about system properties (21 assertion types). |
| `list_assertions` / `delete_assertion` | List or delete assertions for a control. |
| `add_evidence` / `remove_evidence` | Attach auxiliary metadata (docs, links). Evidence is contextual — only assertions prove implementation. |
| `get_verification_report` | Shows verified, partially verified, and unverified controls with sufficiency details. |
| `get_sufficiency` | Quick check: do assertions for a single control collectively cover all aspects? |
| `get_scan_prompt` | Returns targeted prompts for scanning the codebase against not_implemented controls. |
| `get_review_queue` | Controls not reviewed in 90+ days. Start here for periodic maintenance. |
| `submit_findings` / `list_findings` / `update_finding` | Report and track negative findings (gap discovery). |
| `preview_finding_remediation` | Read-only. Returns a structured diff describing the changes a subsequent `apply_finding_remediation` call would make. Diff shape depends on the finding's kind (e.g. for `structural_duplicate_controls`: which controls would be kept, which dropped, the union of CO mappings + framework refs that would land on the survivor). Call before `apply_finding_remediation` so the operator can confirm. |
| `apply_finding_remediation` | Mutates state: commits the changes `preview_finding_remediation` showed. Requires a non-empty `justification` (one-line operator rationale) recorded on the audit trail. The agent is responsible for the preview-then-apply norm — surface the diff and get explicit confirmation before calling. |

### Assurance

| Tool | Description |
|------|-------------|
| `assess_model` | Deterministic assessment of all COs. Returns mitigated/at_risk/unassessed with `risk_reason` (missing_controls, pending_attestation, expired_attestation). For per-CO reachability state call `get_reachability_verdicts`. |
| `get_findings_risks` | Workspace-scoped triage dashboard: open findings, active risk acceptances, and at-risk COs across every model the workspace can access. Entry point when asked "what's open?". |
| `get_model_risk_view` | Per-model Prioritized Risk View: one row per live CO with derived risk tier, asset impact, attacker likelihood, control coverage, and open-finding count. |
| `get_system_risk_view` | Cross-model variant of `get_model_risk_view`: same shape, aggregated across every model in a System (model_id + model_title attached per row). |
| `list_risk_acceptances` | All risk acceptances on a model — risks explicitly accepted instead of mitigated. Includes CO id, owner, justification, status, review deadline. |

### Composition (recursive-tree effective model)

Views over the *effective* model — own entities composed with everything inherited from ancestor threat models on the recursive tree. Backend-gated by `TREE_COMPOSITION_ENABLED`; when off, read tools return a stable empty body with `flag_enabled: false` and the write tool returns 503.

| Tool | Description |
|------|-------------|
| `get_composition_overview` | Index: counts + tree metadata (`parent_id`, `ancestor_chain`, `depth`, `child_ids`) + structural warnings. Cheapest call — use first to learn whether composition is enabled and orient on the tree. |
| `list_effective_entities` | Effective entity set keyed by kind (trust boundaries, components, assets, attackers, attack paths). Each entry carries provenance (`own` vs `inherited`) and a fully-qualified id for cross-model references. |
| `list_effective_control_objectives` | Effective COs tagged with origin (`own` / `cross` / `inherited`). Pair with `get_effective_coverage` and `get_reach_verdicts`. |
| `get_effective_coverage` | Per-CO coverage with credited inheritance: `own_credit`, `inherited_credit`, and the list of contributing controls (with the owning model id, origin, verification status, mitigation group). This is what drives the composition coverage view, not per-model `get_verification_report`. |
| `get_reach_verdicts` | Per-CO reachability verdicts over the composed effective topology — same kinds (`reachable` / `unreachable` / `indeterminate`) as `get_reachability_verdicts`, but evaluated against the merged tree. Use on child models when ancestor topology matters. |
| `list_effective_attack_paths` | Effective AttackPath set + lifted missing/dangling suggestions computed against the composed reach surface. |
| `list_reconciliation_candidates` | Paginated reconciliation candidates between this model and its ancestors. Tier `certain` is a deterministic match safe to auto-apply; tier `heuristic` is fuzzy and needs review. |
| `apply_certain_reconciliation_match` | Mutating. Apply a `certain`-tier candidate from `list_reconciliation_candidates`: soft-deletes the descendant's own duplicate so the inherited entity becomes canonical. Server re-validates against current live state and refuses heuristic-tier candidates (those need operator-driven structural-divergence review). Bumps model version; returns the standard `_do_entity_crud` envelope (`{model, controls_carried, controls_orphaned, orphaned_control_ids}`). |
| `reject_reconciliation_candidate` | Mutating. Persist the operator's "these are NOT duplicates" decision at org scope so the candidate detector filters this pair out of the active queue on subsequent reads. Idempotent on the natural key `(model_id, kind, own_qid, inherited_qid)`. Does NOT bump model version (rejection is org state). Returns the persisted record — keep the `id` if the operator may unreject later. |
| `unreject_reconciliation_candidate` | Mutating. Remove a persisted rejection by surrogate id (from `list_reconciliation_rejections` or the return value of `reject_reconciliation_candidate`). The pair becomes eligible to surface in the active queue again on the next read. Returns `{ok: true}`. |
| `list_reconciliation_rejections` | List the persisted rejections on a model in `rejected_at` ascending order — the same set the candidate detector consults to filter the active queue. Use to render a rejected section in a triage view or to find the surrogate id needed by `unreject_reconciliation_candidate`. |
| `lift_composition_entity` | Mutating. Promote a shared-anchor entity from two sibling descendants to their lowest common ancestor: each source's copy is soft-deleted and the inherited entity becomes canonical for every descendant of the LCA. Server re-detects field-level and attached-state conflicts against current live state; pass `field_resolutions` / `attached_state_resolutions` keyed by the conflict keys returned in the 400 detail. Server also runs an over-application gate against the LCA's descendant set; pass `acknowledged_third_party_subtrees` to acknowledge extra reach or `skip_overapplication_gate=true` to override after explicit operator confirmation. Bumps version on the LCA + both source descendants; returns `{lift_id, lca_model, descendant_a_model, descendant_b_model, applied_migrations, lift_event}` — the `lift_event` block matches the audit pack's `lift_history` entry. |
| `split_composition_entity` | Mutating. Inverse of `lift_composition_entity`: push an ancestor-owned entity down to one or more target descendants and soft-delete the ancestor's copy. A new local id is minted on each target; attached state (assertions, jira mappings, risk acceptances) on the ancestor's entity is duplicated to every target. Bumps version on the ancestor + every target descendant; returns `{split_id, ancestor_model, descendant_models, applied_duplications, split_event}` — the `split_event` block matches the audit pack's `split_history` entry. |
| `preview_undo_lift_composition` | Read-only. Compute the inverse plan (or divergence refusal) for a prior `lift_applied` event WITHOUT mutating state. Returns `{plan, refusal}` — exactly one is non-null. Surface this to the operator before calling `undo_lift_composition_event` so the confirmation step shows the state operations the apply would commit, or the enumerated reasons the divergence detector would refuse. |
| `undo_lift_composition_event` | Mutating. Apply the inverse of a previous `lift_applied` event. Re-runs the divergence detector immediately before applying and refuses with 409 + a structured refusal block (`detail.refusal.reasons`) when state has materially evolved since the forward lift. On success, persists the inverse state operations across the LCA + every affected source descendant and emits a structured `lift_undone` activity event citing `original_event_id` so the audit pack chains undo to its forward. Returns `{undone_event_id, original_event_id, applied_state_ops, models: {lca_model, source_descendant_models}}`. |
| `preview_undo_split_composition` | Read-only. Counterpart to `preview_undo_lift_composition` for splits. Same `{plan, refusal}` shape; the plan block carries the split-specific inverse operations (restore at the ancestor, tombstone the duplicated copies on every target descendant). |
| `undo_split_composition_event` | Mutating. Mirror of `undo_lift_composition_event` for splits. Same divergence-detector contract — refuses with 409 + structured refusal block when state has evolved. On success, restores the ancestor's entity, tombstones the duplicated copies on every target descendant, and emits a structured `split_undone` activity event citing `original_event_id`. Returns `{undone_event_id, original_event_id, applied_state_ops, models: {ancestor_model, descendant_models}}`. |

### Cross-model dependencies (delegation)

Declared reliance edges (distinct from the parent/composition tree, which is containment): a model depends on a control implemented in *another* model — for systems built on shared services (auth, logging, shared data) rather than sub-parts. The target is always a provider *control* (credit terminates at a proven mechanism); the provider must be in the same workspace (cross-tenant delegation is prohibited). Backend-gated by `RECURSIVE_TREE_ENABLED`; credit effects further gated by `FOUNDATION_DELEGATION_ENABLED`.

| Tool | Description |
|------|-------------|
| `declare_foundation` | Mark a shared-service model as a foundation that advertises specific controls (`provides`) other models can delegate to. A capability advertises a control, never an objective. |
| `create_reliance` | Declare a single dependency. `delegated` (consumer has no local control for an objective; provider handles it — pass `source_objective_id`) or `relied_upon` (consumer keeps its own control but its validity depends on the provider's — pass `source_control_id`). Enters `draft`; runs LLM semantic validation. |
| `confirm_reliance` | Promote a draft edge to active — the credit-soundness gate. Refused unless validation returned `valid`; a `partial`/mode-mismatch is never silently credited. |
| `delete_reliance` | Remove a reliance edge. |
| `list_reliance` | A model's dependency edges (as consumer) plus who relies on it (as provider — the blast radius before changing its controls). |
| `propose_attach_foundation` | Read-only. Propose which of a consumer's objectives each foundation capability covers (scored). Feed the chosen subset to `attach_foundation`. |
| `attach_foundation` | Bulk-create draft delegation edges for the selected (objective, provider control) pairs. Each runs LLM validation; none credits until confirmed. |

### Compliance

| Tool | Description |
|------|-------------|
| `list_compliance_frameworks` | Available frameworks (OWASP ASVS, ISO 27001, SOC 2, NIST CSF, GDPR, FedRAMP, PCI DSS, EU CRA). |
| `select_compliance_frameworks` | Select frameworks for a model. |
| `get_compliance_report` | Coverage report for a selected framework. |
| `auto_map_controls` | AI-powered semantic mapping of controls to framework requirements. |
| `map_control_to_requirement` | Manual control-to-requirement mapping. |
| `auto_remediate` | LLM-powered gap closure — proposes new assets, attackers, and controls for uncovered framework requirements. |

### Components

| Tool | Description |
|------|-------------|
| `add_component` / `edit_component` / `remove_component` | Components bridge trust boundaries (security architecture) to repositories (code organization). `Component(id, name, repo_url, path, trust_boundary_ids)` scopes controls to the codebase that implements them. Used for multi-repo systems and per-repo threat models. `edit_component` also accepts optional per-component level grades: `target_sl` (IEC 62443 Security Level, 1-4), `eal` (Common Criteria Evaluation Assurance Level, 1-7), `fips_level` (FIPS 140-3 Security Level, 1-4). |

### Systems and Workspaces

| Tool | Description |
|------|-------------|
| `list_workspaces` | List available workspaces. |
| `update_organization` | Set per-organization level grades: `target_ml` (IEC 62443-4-1 Maturity Level, 1-5), `csf_tier` (NIST CSF Tier, 1-4). Admin-only. Use `clear_target_ml` / `clear_csf_tier` to explicitly reset to NULL. |
| `list_systems` / `get_system` / `create_system` | Manage systems (groups of related models). |
| `add_model_to_system` | Add a model to a system. |
| `get_system_dependencies` | Cross-model dependency graph with satisfaction status for assumptions linked to other models. |
| `link_dependency` | Link a cross-model assumption to a target model — dual-path satisfaction (controls OR manual attestation). |
| `select_system_compliance_frameworks` / `get_system_compliance_report` | System-level compliance aggregation. |

### Setup and Operations

| Tool | Description |
|------|-------------|
| `get_setup_status` | Check which onboarding steps are done. |
| `complete_setup_step` | Mark an onboarding step as done (mcp_configured, mipiti_verify_installed, ci_secret_added, ci_pipeline_added). |

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
        "MIPITI_API_KEY": "your-key"
      }
    }
  }
}
```

## License

Proprietary. Copyright (c) 2026 Mipiti, LLC. All rights reserved. See [LICENSE](LICENSE) for details.

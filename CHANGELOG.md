# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Seven new MCP tools for the recursive-tree composition surface: `get_composition_overview`, `list_effective_entities`, `list_effective_control_objectives`, `get_effective_coverage`, `get_reach_verdicts`, `list_effective_attack_paths`, `list_reconciliation_candidates`. All read-only; each wraps the matching `/api/models/{id}/composition/*` route. Returns the backend's stable empty body (`flag_enabled: false`) when `TREE_COMPOSITION_ENABLED` is off so agents render the disabled state without a separate code path. Bumps total MCP tool count to 104.
- `apply_certain_reconciliation_match(model_id, kind, own_qid, inherited_qid)` MCP tool wrapping `POST /api/models/{id}/composition/reconciliation/apply-match`. First write tool on the composition surface: soft-deletes the descendant's own duplicate entity once the operator has accepted a `certain`-tier candidate from `list_reconciliation_candidates`, so the inherited entity becomes the canonical surface for the effective-model resolver. Pre-flight validates `kind` against `{assets, attackers, components}` and rejects malformed qualified ids before HTTP; the server re-validates the candidate against current live state and refuses heuristic-tier matches. Returns the standard `_do_entity_crud` envelope (`{model, controls_carried, controls_orphaned, orphaned_control_ids}`). Bumps total MCP tool count to 105.
- Three new MCP tools for managing persisted reconciliation rejections: `reject_reconciliation_candidate(model_id, kind, own_qid, inherited_qid)`, `unreject_reconciliation_candidate(model_id, rejection_id)`, and `list_reconciliation_rejections(model_id)`. Wrap the matching `/api/models/{id}/composition/reconciliation/{reject,reject/{id},rejections}` routes. Reject persists the operator's "these are NOT duplicates" decision at org scope (idempotent on the natural key) so the candidate detector filters the pair out on subsequent reads; unreject removes by surrogate id; list returns the rejection set in `rejected_at` ascending order. Mutations do NOT bump model version (rejection is org state, not model state). Read tool returns the canonical empty body (`flag_enabled: false`, empty list) when `TREE_COMPOSITION_ENABLED` is off; write tools 503 in the same situation. Bumps total MCP tool count to 108.
- Two new write MCP tools on the composition surface: `lift_composition_entity(model_id, kind, local_id_a, local_id_b, descendant_a_id, descendant_b_id, lca_model_id, ...)` and `split_composition_entity(model_id, kind, ancestor_local_id, target_descendants)`. Wrap `POST /api/models/{id}/composition/{lift,split}`. Lift promotes a shared-anchor entity from two sibling descendants to their lowest common ancestor — soft-deletes each source's copy so the inherited entity becomes canonical for every descendant of the LCA, applies operator-confirmation knobs (`field_resolutions`, `attached_state_resolutions`, `acknowledged_third_party_subtrees`, `skip_overapplication_gate`) the server re-validates against current live state, and bumps version on all three affected models. Split is the inverse: pushes an ancestor-owned entity down to one or more target descendants, duplicates the attached state to every target, soft-deletes the ancestor's copy, and bumps version on the ancestor + every target. Pre-flight validates `kind` against `{assets, attackers, components}` and required string/list fields before HTTP. Both return the structured event payload the audit pack later surfaces under `lift_history` / `split_history`. Bumps total MCP tool count to 110.

## [0.41.0] - 2026-05-14

### Added

- Two new MCP tools: `preview_finding_remediation(finding_id)` and `apply_finding_remediation(finding_id, justification)` for operating on findings whose kind supports automatic remediation. Returns a structured diff (preview) and commits with audit-trail justification (apply). Bumps total MCP tool count to 97.
- "Remediating findings (structural drift)" section in `_INSTRUCTIONS_BASE` establishing the preview-then-apply norm: agents must surface the diff to the operator before committing remediation, and collect a one-line rationale.

### Changed

- "When you hit an implementation constraint mid-coding" section added to `_INSTRUCTIONS_BASE`. Describes the 3-step structural pattern (`import_controls` + `assign_control_to_components` -> `set_mitigation_groups` -> `add_assumption`) for recording weaker-but-feasible alternative mitigations without silently weakening existing controls.

## [Pre-0.41.0]

For releases prior to v0.41.0, see [git tags](https://github.com/Mipiti/mipiti-mcp/tags) and [GitHub Releases](https://github.com/Mipiti/mipiti-mcp/releases). Structured CHANGELOG begins from v0.41.0.

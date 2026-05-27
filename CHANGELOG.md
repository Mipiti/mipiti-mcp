# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Seven new MCP tools for the recursive-tree composition surface: `get_composition_overview`, `list_effective_entities`, `list_effective_control_objectives`, `get_effective_coverage`, `get_reach_verdicts`, `list_effective_attack_paths`, `list_reconciliation_candidates`. All read-only; each wraps the matching `/api/models/{id}/composition/*` route. Returns the backend's stable empty body (`flag_enabled: false`) when `TREE_COMPOSITION_ENABLED` is off so agents render the disabled state without a separate code path. Bumps total MCP tool count to 104.
- `apply_certain_reconciliation_match(model_id, kind, own_qid, inherited_qid)` MCP tool wrapping `POST /api/models/{id}/composition/reconciliation/apply-match`. First write tool on the composition surface: soft-deletes the descendant's own duplicate entity once the operator has accepted a `certain`-tier candidate from `list_reconciliation_candidates`, so the inherited entity becomes the canonical surface for the effective-model resolver. Pre-flight validates `kind` against `{assets, attackers, components}` and rejects malformed qualified ids before HTTP; the server re-validates the candidate against current live state and refuses heuristic-tier matches. Returns the standard `_do_entity_crud` envelope (`{model, controls_carried, controls_orphaned, orphaned_control_ids}`). Bumps total MCP tool count to 105.

## [0.41.0] - 2026-05-14

### Added

- Two new MCP tools: `preview_finding_remediation(finding_id)` and `apply_finding_remediation(finding_id, justification)` for operating on findings whose kind supports automatic remediation. Returns a structured diff (preview) and commits with audit-trail justification (apply). Bumps total MCP tool count to 97.
- "Remediating findings (structural drift)" section in `_INSTRUCTIONS_BASE` establishing the preview-then-apply norm: agents must surface the diff to the operator before committing remediation, and collect a one-line rationale.

### Changed

- "When you hit an implementation constraint mid-coding" section added to `_INSTRUCTIONS_BASE`. Describes the 3-step structural pattern (`import_controls` + `assign_control_to_components` -> `set_mitigation_groups` -> `add_assumption`) for recording weaker-but-feasible alternative mitigations without silently weakening existing controls.

## [Pre-0.41.0]

For releases prior to v0.41.0, see [git tags](https://github.com/Mipiti/mipiti-mcp/tags) and [GitHub Releases](https://github.com/Mipiti/mipiti-mcp/releases). Structured CHANGELOG begins from v0.41.0.

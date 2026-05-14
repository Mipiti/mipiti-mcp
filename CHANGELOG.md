# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.41.0] - 2026-05-14

### Added

- Two new MCP tools: `preview_finding_remediation(finding_id)` and `apply_finding_remediation(finding_id, justification)` for operating on findings whose kind supports automatic remediation. Returns a structured diff (preview) and commits with audit-trail justification (apply). Bumps total MCP tool count to 97.
- "Remediating findings (structural drift)" section in `_INSTRUCTIONS_BASE` establishing the preview-then-apply norm: agents must surface the diff to the operator before committing remediation, and collect a one-line rationale.

### Changed

- "When you hit an implementation constraint mid-coding" section added to `_INSTRUCTIONS_BASE`. Describes the 3-step structural pattern (`import_controls` + `assign_control_to_components` -> `set_mitigation_groups` -> `add_assumption`) for recording weaker-but-feasible alternative mitigations without silently weakening existing controls.

## [Pre-0.41.0]

For releases prior to v0.41.0, see [git tags](https://github.com/Mipiti/mipiti-mcp/tags) and [GitHub Releases](https://github.com/Mipiti/mipiti-mcp/releases). Structured CHANGELOG begins from v0.41.0.

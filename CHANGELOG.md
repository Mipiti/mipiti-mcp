# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`test_passes` is replaced by `test_attested`.** Verification is a read-only
  operation over evidence your project already produced. `test_passes` was the
  one assertion type that did not fit that rule, since proving a test passed
  required verification to run it.

  `test_attested` takes a `test` param naming the test the attestation must
  contain, and reads a statement your CI signed about a run it performed
  itself. Add one step after your tests: `mipiti-verify attest-tests --junit
  <report>`.

  Agents discover the new type through `get_assertion_types` as usual. The
  assertion type count is unchanged at 28.

### Fixed

- The list of assertion types `submit_assertions` accepts is now readable. It
  was carried entirely in that tool's description, which had grown past what
  clients present in full, so callers saw the prose introducing the list and
  none of the list itself.

  The description now names every type with its required and optional params, in
  a form that fits inside the limit, and is ordered so the type list comes before
  elaborating prose: a stricter client loses the prose, not the contract.

  A new `get_assertion_types` tool returns the full catalogue — descriptions,
  param descriptions and a worked example per type — as structured data rather
  than prose, optionally filtered to named types.



### Added

- `auto_resolved` finding status: a finding the platform closed because the
  condition that produced it is no longer reproduced.

  It is deliberately distinct from the closures a person makes. "The gap is
  gone" and "the gap does not matter" are opposite statements about residual
  risk, so they never share a status — `remediated` / `verified` mean someone
  fixed and confirmed it, `dismissed` means someone judged it not worth fixing,
  and `auto_resolved` means nobody decided anything and the condition simply
  stopped being found.

  `list_findings` can filter on it. `update_finding` cannot set it: it asserts
  a re-evaluation outcome that only the platform can observe, and offering it
  as a manual transition would invite forging that claim. A person recording
  that a gap does not matter uses `dismissed`, with a reason.


### Changed

- Tool docs state how mitigation credit is earned, so an agent can tell which
  controls carry an objective before choosing where to spend effort.

  Within a control objective a control is either a member of a required
  mitigation group or it is defense-in-depth. Groups are what mitigate: within
  a group AND, across groups OR. Defense-in-depth is tracked and reported, and
  does not contribute to mitigation. A control's control-objective ids
  therefore express attachment, and the role is read with
  `get_mitigation_groups`.

  `get_controls` states that contract and points at the group reader. The
  risk-reason routing states the group check as its first step: where an
  objective's required groups are empty, it is closed by establishing the
  group structure with `set_mitigation_groups`.

  `refine_control` states its acceptance criterion — a refinement is accepted
  when the control still states the protection each mapped objective relies
  on, and a rejection is a decision rather than a transient error. A control is
  a requirement that must be met to cover its objectives, so evidence that the
  system does not currently meet it means the control is unmet, never that the
  control should ask for less.

### Added

- `create_co_disposition` and `list_co_dispositions`: record and read the
  judgment that a control objective **does not apply to this system**. The
  sibling of a risk acceptance, and the difference is the claim — an acceptance
  says the exposure is real and is being carried; a disposition says the
  objective does not apply here at all.

  The objective is not removed. It stays in the control-objective matrix and in
  every coverage count, reported in its own class carrying the owner and
  justification, so a reviewer can see the judgment and challenge it. What a
  disposition changes is work: no controls are generated for the objective and
  no coverage gap is raised against it. Both kinds expire, and the objective
  returns to its underlying posture when the claim lapses.

  `list_co_dispositions` includes expired and revoked entries — a lapsed
  decision is part of the audit trail. Its `kind` filter normalises case and
  surrounding whitespace, and rejects a value that is a genuinely different
  word rather than passing it through: an unmatched filter would return an
  empty list, which reads as "nothing has been signed". `list_risk_acceptances`
  is unchanged and still returns risk acceptances only.

- `target` is now an optional param in the assertion schema on exactly two
  types: `pattern_matches` and `pattern_absent`. Its only value is
  `"feature_description"`: the assertion is verified against the model's
  feature description instead of a repository file, and it replaces `file`
  (the two are mutually exclusive). A type may accept a target only when
  both hold — its tier-1 predicate is a caller-supplied regex evaluated over
  arbitrary text, with no source-language structure, and its tier-2
  criterion and schema description are defined over the matched text itself
  rather than over the role the scanned artifact plays in the running
  system. The code-syntax types fail the first conjunct: their criterion is
  stated about code — a definition, a call, a decorator, an import — and
  their tier-2 template asks an implementation question, so a design
  specification is not a subject they are defined over. `no_plaintext_secret` fails
  the second — its schema text and tier-2 criterion bind its subject to a
  file — and loses no capability, since "the design states no credentials"
  is `pattern_absent` with a target. `assertion_types` exports
  `ASSERTION_TARGETS` (the valid target values) and `TARGET_CAPABLE_TYPES`
  (the types that accept one, derived from the specs) so the platform
  enforces the same shape the schema documents. Required params are
  unchanged.

- Functional-conformance tools, closing the coding-agent loop for behaviour verification (the functional analogue of the security control loop): `generate_functional_objectives` (derive capabilities + Given-When-Then objectives **and the concrete tests to implement** from the feature spec — the agent implements the specified tests rather than deciding what to test), `list_capabilities` / `get_capability`, `list_functional_objectives` / `get_functional_objective`, `get_functional_coverage` (per-objective + per-test state + the Capabilities × Conditions matrix), `check_functional_gaps` (applicable conditions with no objective + failing/untested objectives), `get_functional_scan_prompt` (per not-yet-verified test, its implementation brief + the objectives it proves), `add_functional_test` (manually add an extra test), and `submit_functional_tests` (evidence assertions verified by the same CI runner as security controls). The loop: generate objectives + tests → scan-prompt → implement each test → submit_functional_tests → CI verifies → get_functional_coverage.

- Seven RTL/hardware assertion types in the canonical assertion schema, extending machine-verifiable evidence to Verilog/SystemVerilog sources: `module_exists`, `module_instantiated`, `port_exists`, `parameter_defined`, `signal_exists`, `sva_assertion_present`, and `register_reset`. Mirrors the existing software taxonomy (structure / call-graph / interface / configuration / verification / semantic): `module_exists` and `signal_exists` are the structural existence checks, `module_instantiated` is the call-graph analogue, `port_exists` covers the module interface, `parameter_defined` covers configuration (with an optional RE2 value pattern), `sva_assertion_present` proves a named SystemVerilog assertion exists, and `register_reset` is the two-tier semantic type (tier 1 finds the reset-path assignment; tier 2 evaluates whether the register resets to a safe, known value). The `submit_assertions` docstring picks the new types up automatically via `format_for_docstring()`. Total assertion types: 28.

- `assertion_type_count` metric in `scripts/canonical-counts.sh` (+ `ASSERTION_TYPE_COUNT` in the doc-count gate), so README mentions of the type count are pinned to the schema instead of hand-maintained.

- `revalidate_threat_model_entities(model_id)` MCP tool wrapping `POST /api/models/{id}/revalidate-entities`. Re-runs quality validation over an existing model's assets and attackers — a fast first-pass check on every entity, with a deeper review only on the ones it flags (which confirms them, sharpens their wording, or flags them for review). Stale quality warnings are cleared first so previously-flagged entities are re-judged. Non-destructive: an entity that should be removed is left in place with a quality warning rather than deleted, so no control objective loses its asset/attacker anchor; the result is saved as a new model version (controls and COs carry forward). The validation-pass counterpart to `reevaluate_threat_model_factors`.

- `set_threat_model_parent(model_id, parent_id)` MCP tool wrapping `PATCH /api/models/{id}/parent`. Sets (or clears, with `parent_id=None`) a model's position on the recursive composition tree so child models inherit topology, control objectives, and other entities from their ancestors. Server rejects cycles and over-deep chains with HTTP 400; bumps the model version on success. Returns the updated threat model.

- Seven new MCP tools for the recursive-tree composition surface: `get_composition_overview`, `list_effective_entities`, `list_effective_control_objectives`, `get_effective_coverage`, `get_reach_verdicts`, `list_effective_attack_paths`, `list_reconciliation_candidates`. All read-only; each wraps the matching `/api/models/{id}/composition/*` route. Returns the backend's stable empty body (`flag_enabled: false`) when `TREE_COMPOSITION_ENABLED` is off so agents render the disabled state without a separate code path. Bumps total MCP tool count to 104.

### Changed

- **BREAKING — consolidated the tool surface from 162 to 129 tools** so tool selection stays reliable across MCP clients (several hard-cap the tools per request, which the old surface exceeded). No capability was removed — the sprawl was structural, and folds behind discriminator params: symmetric per-entity-type reads/removes/restores become `get_entity` / `remove_entity` / `restore_entity` with an `entity_type` (`add`/`edit` stay typed per entity; `get_capability` stays standalone); the model/system/tag scope-families become `get_risk_view` / `get_compliance_report` / `select_compliance_frameworks` / `export_report` behind a `scope`; tags and systems unify as "groups" behind a `kind`; mode-pairs fold behind a flag (`get_reachability_verdicts(composed=…)`, `recompute_verdicts(dry_run=…)`, `undo_composition_event(event_type=…)`, `preview_undo_composition(event_type=…)`, `list_reconciliation_candidates(disposition=…)`); singular getters fold into their plural (`get_controls(control_id=…)`, `get_control_objectives(co_id=…)`, `get_functional_objectives(functional_objective_id=…)`); `assign_to_components(target_type=…)` and `get_scan_prompt(kind=…)` fold their pairs; `assume_control` / `unassume_control` are removed in favour of `set_control_assumption_groups`; and nine scope-ambiguous tools are renamed (`get_system`→`get_group`, `delete_tag`→`delete_group`, `remove_model_from_tag`→`remove_model_from_group`, `list_model_tags`→`list_model_groups`, `link_dependency`→`link_system_dependency`, `submit_functional_tests`→`submit_functional_test_assertions`, `set_co_cal`→`set_control_objective_cal`, `revalidate_threat_model_entities`→`revalidate_entity_quality`, `auto_remediate`→`auto_remediate_compliance`). `restore_entity` now covers all five entity types. Because tool schemas are pinned per session, upgrading requires a teardown and re-add under a new server name.

- Corrected the server-version-changed recovery message. When the pinned tool schemas go stale mid-session, re-adding the MCP server under the **same** name reuses the pinned schemas, so the previous "remove, resume, exit again, re-add" dance did not reliably refresh them. The message now instructs a full teardown and re-add under a **new** server name (e.g. `Mipiti` → `Mipiti-1`), which forces the client to load the fresh schemas, and drops the unnecessary extra session start/exit.

- Clarified component repo-binding guidance across the `add_component` docstring, the components-lifecycle instructions, and the `model_coherence_report` `component_unbound` note. An empty `repo_url` covers two distinct cases, told apart by the component's **trust boundary**: an internal-zone component (your own code) should be bound to its repo, while an external-zone component (e.g. a third-party service, the customer's IdP, or other external infrastructure) should stay unbound — its `component_unbound` finding is a permanent external-dependency marker, not a TODO. Previously the docs framed every unbound component as "not bound yet," which could lead an agent to wrongly bind an external component to the repo.

- Documented the entity authoring contract in the asset/attacker tool docstrings (`add_asset` / `edit_asset` / `add_attacker` / `edit_attacker`) and the threat-modeling instructions: an asset names the *data or resource being protected* and its security property (not a mechanism or control), and an attacker `capability` names the *operations performable from its position* ("From [position], the attacker can [operations] …"), not just access. Entities that fall short carry a `quality_warning` and yield under-specified control objectives; the guidance is now surfaced up front rather than discoverable only after a warning.

- `get_verdict_divergence` now accepts `limit` (default 100, clamped to 1–500) and `offset` params, forwarded to the paginated backend endpoint. The tool previously always returned the first 100 rows per section with no way to reach the rest, so on a model with more than 100 divergences of a kind an agent could not review past the first page. Its docstring now points at each section's `pagination.filtered_total` and instructs raising `limit` / advancing `offset` until the whole section is seen. Rows remain confidence-sorted, so the highest-confidence calls still come first.

- `list_effective_entities`, `get_effective_coverage`, and `get_reach_verdicts` now accept `page` and `page_size` query params (defaults `page=1`, `page_size=100`) so agents don't blow their context budget on realistic models. Each also takes a kind-appropriate filter param: `kind` (single entity kind for entities), `origin` (`"own" | "cross" | "inherited"` for coverage), and `kind_filter` (`"reachable" | "unreachable" | "indeterminate"` for reach verdicts — named to disambiguate from each verdict's own `kind` field). Response shape gains `total`, `page`, and `page_size` alongside the existing data fields. Callers that omitted these params previously received every row in a single call; now they receive page 1 of 100 by default.

- `apply_certain_reconciliation_match(model_id, kind, own_qid, inherited_qid)` MCP tool wrapping `POST /api/models/{id}/composition/reconciliation/apply-match`. First write tool on the composition surface: soft-deletes the descendant's own duplicate entity once the operator has accepted a `certain`-tier candidate from `list_reconciliation_candidates`, so the inherited entity becomes the canonical surface for the effective-model resolver. Pre-flight validates `kind` against `{assets, attackers, components}` and rejects malformed qualified ids before HTTP; the server re-validates the candidate against current live state and refuses heuristic-tier matches. Returns the standard `_do_entity_crud` envelope (`{model, controls_carried, controls_orphaned, orphaned_control_ids}`). Bumps total MCP tool count to 105.

- Three new MCP tools for managing persisted reconciliation rejections: `reject_reconciliation_candidate(model_id, kind, own_qid, inherited_qid)`, `unreject_reconciliation_candidate(model_id, rejection_id)`, and `list_reconciliation_rejections(model_id)`. Wrap the matching `/api/models/{id}/composition/reconciliation/{reject,reject/{id},rejections}` routes. Reject persists the operator's "these are NOT duplicates" decision at org scope (idempotent on the natural key) so the candidate detector filters the pair out on subsequent reads; unreject removes by surrogate id; list returns the rejection set in `rejected_at` ascending order. Mutations do NOT bump model version (rejection is org state, not model state). Read tool returns the canonical empty body (`flag_enabled: false`, empty list) when `TREE_COMPOSITION_ENABLED` is off; write tools 503 in the same situation. Bumps total MCP tool count to 108.

- Two new write MCP tools on the composition surface: `lift_composition_entity(model_id, kind, local_id_a, local_id_b, descendant_a_id, descendant_b_id, lca_model_id, ...)` and `split_composition_entity(model_id, kind, ancestor_local_id, target_descendants)`. Wrap `POST /api/models/{id}/composition/{lift,split}`. Lift promotes a shared-anchor entity from two sibling descendants to their lowest common ancestor — soft-deletes each source's copy so the inherited entity becomes canonical for every descendant of the LCA, applies operator-confirmation knobs (`field_resolutions`, `attached_state_resolutions`, `acknowledged_third_party_subtrees`, `skip_overapplication_gate`) the server re-validates against current live state, and bumps version on all three affected models. Split is the inverse: pushes an ancestor-owned entity down to one or more target descendants, duplicates the attached state to every target, soft-deletes the ancestor's copy, and bumps version on the ancestor + every target. Pre-flight validates `kind` against `{assets, attackers, components}` and required string/list fields before HTTP. Both return the structured event payload the audit pack later surfaces under `lift_history` / `split_history`. Bumps total MCP tool count to 110.

- Four new MCP tools to undo prior lift / split events with the operator-confirmation flow: `preview_undo_lift_composition(model_id, lift_id)`, `undo_lift_composition_event(model_id, lift_id)`, `preview_undo_split_composition(model_id, split_id)`, and `undo_split_composition_event(model_id, split_id)`. Wrap `GET` / `POST /api/models/{id}/composition/{lift,split}/{id}/undo[/preview]`. Preview tools are read-only and return `{plan, refusal}` — exactly one is non-null. Apply tools re-run the divergence detector immediately before applying and refuse with 409 + the structured refusal block (`detail.refusal.reasons`) when state has materially evolved since the forward event (assertions submitted on the affected entity, downstream COs added that reference it, the entity edited, etc.). On success, persist the inverse state operations across all affected models and emit a structured `lift_undone` / `split_undone` activity event citing `original_event_id` so the audit pack chains undo to its forward. Pre-flight validates `model_id` and the event id are non-empty before HTTP. `lift_id` / `split_id` accept either the surrogate activity-event id or the structured event-payload id. Bumps total MCP tool count to 114.

### Fixed

- Reconciled the `repo` argument description in the `submit_assertions` tool
  documentation with the requirement stated elsewhere in the same description.
  `repo` was documented as optional and only relevant to multi-repo setups,
  while every assertion in a batch must carry an explicit `"<owner>/<repo>"`
  slug — the CI repository whose verification run should check it — or the
  `"no_repo"` sentinel, which opts the assertion out of every run. A submission
  with an empty or missing `repo` is rejected, so the old wording invited a call
  that could not succeed.

- Restored `server_version` interpolation in the MCP instructions. The instructions carried a literal `{_SERVER_VERSION}` token instead of the running server version, so every client was told to send the placeholder string; the version-check middleware then rejected all tool calls, and no fresh session could recover (the value clients need is only advertised through these instructions). The version is now spliced into the instruction text again. Added a regression test asserting the real version is present and the placeholder is absent across tiers.

- Requests now carry an `X-Mipiti-Source-System: mcp` header, so models created through this client are attributed to the MCP surface (`source_system="mcp"`) instead of defaulting to `web`. Set on the client's default headers via `setdefault`, so it rides alongside the API-key / auth headers on every request (including the generate/create stream) and an explicit caller-supplied value is preserved.

- `list_assertions` no longer fails against servers that return the origin-grouped assertion listing (`{"own": [...], "inherited": [...]}`, where inherited assertions are contributed through model composition). The client previously assumed a bare JSON array and iterated the grouping's keys, so the tool crashed with a validation error (`input_value='own'`). Both shapes are now accepted and flattened into the tool's flat-list contract; each returned assertion carries an additive `origin` field (`"own"` | `"inherited"`, with bare-list responses tagged `"own"`), and an unrecognized response shape raises a clear error instead of a per-item validation trace.

- `server_version` validator no longer bypassable via empty string. The previous shape (`if client_version and client_version != _SERVER_VERSION:`) short-circuited when an agent omitted the field, defeating the pin's safety guarantee (tool catalog + parameter schemas can change between submodule pointer bumps; the server must refuse stale calls). Empty string now rejects alongside any mismatch. Five new tests pin the staleness-rejection path so a future short-circuit reopens-the-bypass change breaks CI loudly.

- Staleness-rejection message now describes the empirically-verified recovery sequence in Claude Code (exit + `claude mcp remove` + resume + exit + `claude mcp add` + reauth + resume). The earlier wording ("Reconnect your MCP client (e.g., run /mcp in Claude Code and reconnect)") was misleading: a `/mcp` reconnect / reauth / disable+re-enable does not refresh tool descriptions in the live session — only a full server-config teardown does.

### Security

- Floored four transitively-pulled dependencies to their first fixed release via `[tool.uv] constraint-dependencies`, clearing the current `pip-audit` findings: `starlette>=1.3.1` (PYSEC-2026-248 / PYSEC-2026-249), `cryptography>=48.0.1` (GHSA-537c-gmf6-5ccf), `pydantic-settings>=2.14.2` (GHSA-4xgf-cpjx-pc3j), and `python-multipart>=0.0.31` (CVE-2026-53540). All four lockfiles recompiled; `pip-audit` now reports no known vulnerabilities.

## [0.41.0] - 2026-05-14

### Added

- Two new MCP tools: `preview_finding_remediation(finding_id)` and `apply_finding_remediation(finding_id, justification)` for operating on findings whose kind supports automatic remediation. Returns a structured diff (preview) and commits with audit-trail justification (apply). Bumps total MCP tool count to 97.
- "Remediating findings (structural drift)" section in `_INSTRUCTIONS_BASE` establishing the preview-then-apply norm: agents must surface the diff to the operator before committing remediation, and collect a one-line rationale.

### Changed

- "When you hit an implementation constraint mid-coding" section added to `_INSTRUCTIONS_BASE`. Describes the 3-step structural pattern (`import_controls` + `assign_control_to_components` -> `set_mitigation_groups` -> `add_assumption`) for recording weaker-but-feasible alternative mitigations without silently weakening existing controls.

## [Pre-0.41.0]

For releases prior to v0.41.0, see [git tags](https://github.com/Mipiti/mipiti-mcp/tags) and [GitHub Releases](https://github.com/Mipiti/mipiti-mcp/releases). Structured CHANGELOG begins from v0.41.0.

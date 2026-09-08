# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Soundness classes.** Every assertion type declares the class of the fact
  it reports, one of a closed vocabulary ordered weakest to strongest:
  `presence` (a named construct, value, dependency, file or pattern occurrence
  exists), `under_approximating_scan` (a syntactic scan; a clean result proves
  the absence of the form only), `existential_witness` (a signed run passed;
  proves the path it drove), `sound_over_approximation` (every site in a
  declared scope that can violate the property is a declared safe form or a
  reviewed exception) and `by_construction` (the sink accepts only a boundary
  type whose construction is default-denied). The class is declared once,
  here, by the fact reported; the platform and the CI verifier hold their
  tables equal to it. `AssertionTypeSpec.soundness` is required and the
  catalogue refuses to import with a missing or unknown value.
  `get_assertion_types` returns `soundness` per type, the class vocabulary
  with what each pass establishes, and the two classes that can credit a
  for-all clause. The module exports `SOUNDNESS_CLASSES`, `SOUNDNESS_RANK`,
  `SOUND_CLASSES`, `SOUNDNESS_BY_TYPE`, `SOUND_TYPES`, `soundness_of` and
  `soundness_rank_of`.
- **`typed_boundary`** (`by_construction`) and **`sink_default_deny`**
  (`sound_over_approximation`): the two witness types that credit a clause
  ranging over every entry of a surface. Both take a declared `scope`, the
  `sinks` through which the property could be violated (`callee` plus an
  optional `kind` of `call`, `constructor`, `macro`, `assign` — a store to a
  named target such as an HDL blocking or non-blocking assignment — or
  `instantiate`, and optional guarded `positions`), a reviewed `allowlist`
  (`file`, `site`, `callee`, `reason`, `reviewed_by`), optional `wrappers`,
  and the `property` in one sentence. `sink_default_deny` adds `safe_forms`,
  a non-empty subset of `literal`, `named_constant`, `literal_concat`,
  `parameter_binding`; `typed_boundary` adds `boundary_type` and its
  `constructors`. `parameter_binding` is read from the shape of the value
  at the site, never from the position it occupies, and what it establishes
  is that the statement reaching the sink is fixed. Every unclassifiable site
  is a violation, a scope that matches nothing proves nothing, and the
  residual each type carries is stated in its description. Neither takes
  `file` or `target`. Hardware sources are covered by the same rule.
- **`covers`** — a type-independent, top-level field on each object passed to
  `submit_assertions`: the objective id (`CO-NN`; `CO12` and `CO-12` name the
  same objective) or the clause ids (`cls_` + 12 hex) the evidence proves, at
  most 16. The accepted form is one definition (`COVERS_PATTERN`,
  `COVERS_MAX`, `validate_covers`) applied before a submission leaves the
  client and by the API on arrival. The clause ids to declare are named by
  `get_control_work_order` in `required_evidence`. A `covers` key on a
  functional-test submission is refused rather than dropped in transit: that
  surface records no binding, and a caller must not be left believing it
  declared one.
- **`surface_extent`** on `add_attacker` and `edit_attacker` (`whole`: the
  attacker's operations range over any entry of the interface it reaches;
  `point`: one named entry), and `attest_surface_extent` on `edit_attacker`.
  Supplying any of them attests the extent and requires `change_reason`, on
  the create as much as on the edit; the published effect is the attested
  one — an attested `whole` makes the objectives that attacker anchors
  for-all obligations — and no text describes an extent the platform arrives
  at on its own. Only `whole` is declarable on a create:
  narrowing to one named entry is a statement about the objectives the
  attacker anchors, which a create does not have yet, so the narrowing is an
  `edit_attacker` call, where it is checked against the assets those
  objectives defend. `get_entity` returns an attacker's `surface_extent` and
  `surface_extent_source`.
- Array-valued parameter formats: `ParamSpec.structure="array"` with an item
  schema (`min_items`, `enum`, `item_pattern`, `required_keys`,
  `key_enums`), applied by `validate_param_formats` on both sides; scalar
  `pattern` params are unchanged. `describe_types` exposes the item schema.

### Changed

- Parameter validation refuses a value still left as the `<...>` blank the
  guidance offered, for every declared param rather than only for those that
  declare a format. A param with no pattern was the one place an unanswered
  blank passed, and a submission that passes while saying nothing about the
  caller's code is recorded as a claim until some later check catches it; an
  immediate refusal naming the param is the better failure. Only a whole value
  of that shape is a blank, so a property sentence saying `count < limit` is
  untouched, and an array is judged item by item.

- The `submit_assertions` description is re-cut to the length a client was
  observed to truncate at, and spends it on what a cut must not lose: the
  types grouped by soundness class, strongest first; the object shape,
  including `covers` beside `params` and never inside it; and the for-all
  rule, naming `typed_boundary` when the sinks accept one boundary type and
  `sink_default_deny` when they do not. Everything else — per-param formats
  and value patterns, examples, and the `target` option on the pattern types
  — is returned in full, as data, by `get_assertion_types`, which the
  description points at. A submission carrying `covers` inside `params` is
  refused before it is sent, with the fix named.
- `test_exists` is presence: files matching a glob exist, and nothing ran.
  `function_exists` and `class_exists` on a test file are presence and never
  anchor a test. `pattern_matches`, `pattern_absent` and
  `no_plaintext_secret` state what a clean result cannot prove.
  `test_attested` states its bound (the path it drove) and that an unsigned
  statement or an unattested run is reported as a claim.
- `get_control_work_order` documents `required_evidence[]` in observable
  terms: where the order names a required class for a clause, the entry
  carries the clause text, its `clause_id` (the value to put in `covers`),
  its `quantifier`, the `required_class` that closes it, what is `missing`,
  and a `suggested_submission` **skeleton**. The skeleton is a fill-in, not a
  submission: its `<...>` placeholders are values only the caller can supply,
  and one left unreplaced is refused before the submission leaves the client
  and again on arrival, by the one format rule both ends apply — a
  placeholder that validated would be recorded as a claim about the caller's
  code that nothing backs. Its `assertion_contract` carries `soundness`,
  `universal_rule` and `sound_types`, and its acceptance criteria are
  generated from those entries, so a clause that has to hold at every site
  the attacker reaches is named as such. `behavioral` is documented as a
  compatibility field for readers written before the classes; `soundness` is
  the field to branch on. `get_sufficiency` and `get_controls` point at the
  order rather than restating the work list.
- The server instructions no longer describe an asset or attacker `status`
  field, `asset_status` / `attacker_status`, or the `asset_absent` /
  `attacker_irrelevant` risk reasons, none of which the API reports; they
  describe the attacker surface extent, the soundness classes and the for-all
  rule, and `covers`. Components are added or edited after
  `generate_threat_model`, because a component is created against a model and
  there is none to supply before one exists. A `sealed` boundary decisively
  drops reachability only once its seal is attested
  (`edit_trust_boundary` with `seal_source="attested"` and a
  `change_reason`); `add_trust_boundary` says the same. `submit_attestation`
  states that an attestation is a responsible party's claim, never a proof
  over every site.
- The published surface names only what the API answers, and says which of
  two reasons holds a name out. A tool whose call has no route, a parameter
  the receiving surface drops and a return field that never appears are
  promises nothing can keep; a shape the API does answer and this release
  does not steer agents at is an editorial decision, not a missing
  capability. The two are enumerated apart, each with the reason true of it,
  and a test fails when either reaches a tool description or the
  instructions. A guard whose stated ground its own list falsifies is worse
  than no guard: the next reader trusts the reason instead of the code.
- A submission is checked for the params its type requires as well as the
  format of the ones it carries. A submission that names one type and fills
  another type's parameter set is well-formed in every value it holds, so
  only the absence check sees it, and it is seen before the submission leaves
  the client. `missing_required_params` is exported and names each absent key
  in the same words the API uses on arrival.
- `submit_assertions` states what a resubmission does: an assertion whose
  check is unchanged is re-pointed in place, keeping its id and its verdicts,
  and a resubmission that carries no `covers` leaves a stored declaration
  standing. Evidence strength is composed per clause, so the submission
  surface states the consequence rather than a grade — a control is proven
  no more strongly than its weakest clause — and leaves the composed
  `soundness_tier` to the read that answers for it (`get_sufficiency`).
- A restored archive is published as arriving **unverified**.
  `import_threat_model_archive`, `export_report (format="archive")` and the
  server instructions say whose record the envelope's assertion verdicts and
  run-attested flags are: the origin's, kept so a third party can check them
  against the signatures, and not credit in the workspace that imports them —
  a verdict belongs to the run that produced it and the judge that decided
  it, and an importing workspace has neither. Verification is earned there by
  running it against code that workspace can reach.
- The credit path for a for-all clause is published as a read rather than a
  fixed pair of names: the two sound classes are the rule,
  `get_assertion_types` returns the types that carry them, and
  `get_control_work_order`'s
  `assertion_contract.sound_types` names the ones a platform takes. Where it
  names none, the instructions name the acts that remain — scope the asset to
  the component the attacker actually reaches, attest a `point` extent with
  its reason, or record a risk acceptance or a not-applicable disposition —
  so an obligation is never stated with nothing that discharges it.
- The `scope` param of both sound witness types says what the scope has to be
  for a clause that ranges over every entry of a surface: the region holding
  the components the control defends. A scope over test sources, vendored
  code or a sibling area witnesses those files and says nothing about the
  surface the clause ranges over.
- `get_sufficiency` publishes the composed `soundness_tier` a claim may carry
  and the rule that bounds it — a control is proven no more strongly than its
  weakest clause — so the grade is read as that bound and never as a
  control-level pass.
- The assertion type count is 30.

### Removed

- The optional `mechanism` param on `function_exists` and `class_exists`.
  Both types report **presence** — a named definition is in the tree — and a
  presence check runs no execution, so there is no execution whose mechanism
  could be named. It existed to promote a test-file target to behavioral
  evidence, which the class vocabulary now settles: a test file's definition
  existing is presence, and a run that passed is `test_attested`. A caller
  that still sends the key is unaffected — an undeclared param is ignored on
  arrival — so nothing an agent submits today breaks.

### Added

- **`get_control_work_order`** — the ticket for implementing one control:
  scan brief, what counts as proof (the assertion contract), acceptance
  criteria, steps, reconcile rules, what the calling agent may decide on
  its own, open proposals, and the model's provenance. Call it before
  implementing a control. Read-only.
- **`reconcile_model`** — reconcile a model with the code it describes.
  Takes the paths changed since the model's recorded commit plus the
  agent's observations in four buckets (`mechanism_named`,
  `component_present`, `component_absent`, `forbidden_behavior`); the
  platform decides the consequence of each. Proposals are never applied
  on the agent's word, except a component change on a code-derived model,
  which is applied and queued for a person's review.
- **`create_proposal`** / **`list_proposals`** / **`decide_proposal`** —
  raise, poll, and decide changes of scope or design (`add_component`,
  `remove_component`, `design_change`). Raising is not deciding; a
  decision is refused with 403 and an `escalation_id` unless the
  workspace's delegation policy names it for the agent at the proposal's
  tier, and the refusal is parked for a person as a `decision_request`.
- **`get_design_leverage`** — what eliminating each attacker position or
  asset by design would remove from the matrix, ranked by critical then
  high at-risk objectives removed, with an optional concrete
  `design_move` per row. Read-only.
- **`set_model_provenance`** — record where a model's description came
  from (`code` / `ticket` / `document` / `manual` / `mixed`). `code` with
  a commit SHA means the code is authoritative and the model follows it.
- **`list_decisions`** — the model's decision ledger: every judgment
  recorded on it (finding dismissed / remediated, risk accepted,
  not-applicable declared, proposal accepted / rejected / reverted,
  escalation resolved), newest first, with who decided, whether it was
  within the delegation policy, and the rationale. Filters: `agent_only`,
  `outside_policy_only`, `decision`, `limit`. The ledger is append-only;
  nothing edits it. Call it before raising a proposal or asking for a
  judgment. Read-only.

### Changed

- `function_exists` and `class_exists` accept an optional `mechanism` for a
  test-file target: the mechanism the test exercises, in the same form and
  under the same binding rule as `test_attested`'s.
- `test_attested`'s `mechanism` states the binding rule: which structural
  types anchor and on which param, that pattern types anchor by file, that a
  test file is never a mechanism, what an unbound test costs, and that
  re-submitting a test with a different `mechanism` replaces the earlier row.
- Assertion parameters may declare a value format (`ParamSpec.pattern`).
  `submit_assertions` and `submit_functional_test_assertions` refuse a value
  that does not match before sending; the platform applies the same rule.
  `test_attested`'s `mechanism` declares the accepted forms
  (`<file>::<symbol>`, `<file>::<Owner.leaf>`, `<file>::<kind>:<name>`);
  `MECHANISM_KINDS` is the one vocabulary of construct kinds, shared with the
  verifier and the platform.

- **`generate_threat_model`** accepts optional `provenance_kind`,
  `provenance_repo_url`, `provenance_commit_sha`, `provenance_ref`,
  `provenance_source_ref`, and `provenance_source_url` params so a model
  generated from a repository records its source at creation. The
  request is unchanged when they are empty.
- **`get_review_queue`** rows now carry an `item_type` (`escalation`,
  `proposal`, `open_assumption`, `stale_control`), ranked in that order;
  escalations and proposals are decided with `decide_proposal`.
- The server instructions say to call `get_control_work_order` before
  implementing a control, to reconcile with `reconcile_model`, to check
  `list_decisions` before proposing, and that a refused judgment is parked
  for a person: do not retry, poll `list_proposals`.
- **`test_attested`** takes an optional `mechanism` param
  (`<repo-relative file>::<symbol>`) naming the mechanism the test
  exercises, matching a structural assertion on the same control. The
  type's description now states what the evidence is bound to: the
  test's definition as attested, what the run reached (`mipiti-verify
  attest-tests --coverage`), and whether the test fails with the
  mechanism disabled (`mipiti-verify attest-dependence`). Omit
  `mechanism` only when the control has exactly one structural assertion.

### Removed

- **`list_workspaces`.** Every MCP credential is bound to one workspace when
  it is issued: an API key by its scope, an OAuth token by the workspace
  chosen on the consent screen. The workspace list is a control-plane view
  that only an interactive user session may read, so this tool could not
  succeed with any credential the server holds. To work in another
  workspace, connect with a credential issued for it.

### Changed

- Every release now carries the published wheel and sdist as assets of its
  (immutable) GitHub Release, with a provenance attestation over the same
  files that went to PyPI. A file taken from the Release can be checked with
  `gh attestation verify <file> --owner Mipiti` and its digest compared with
  the PyPI copy.

### Changed

- The server instructions say when `test_attested` is the right evidence and
  what it proves: a behavioral clause is shown to hold by a test that passed
  in the repository's own CI workflow at the commit under verification, beside
  a structural assertion for the mechanism, with `env` pinning a
  configuration-gated control on. Sufficiency still decides whether the clause
  is covered. The catalogue description carries the same one-line "proves".

### Changed

- **`test_passes` is replaced by `test_attested`.** Verification is a read-only
  operation over evidence your project already produced. `test_passes` was the
  one assertion type that did not fit that rule, since proving a test passed
  required verification to run it.

  `test_attested` takes a `test` param naming the test the attestation must
  contain, and reads a statement your CI signed about a run it performed
  itself. Add one step after your tests: `mipiti-verify attest-tests --junit
  <report>`. An optional `env` param pins the environment the run must have
  had (variable name to required value; `null` means unset), checked against
  the names your CI nominated when attesting.

  The platform refuses a submission whose type is not in this catalogue, so
  removing `test_passes` here retires it for new submissions; evidence of
  that type already recorded stays readable.

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

- The PyPI publish workflow now builds, publishes and creates the GitHub Release in three jobs with disjoint permissions (the build never holds a publishing credential, the publish step never runs project code), and verifies before building that the tag names a genuine release: the tag's version equals `pyproject.toml`'s, the tagged commit is on `main` and changes only that version line. A manual run must name the version it publishes and that version must already be tagged, so no run can publish an untagged tree. CI workflows run read-only with credentials dropped after checkout, action pins are Dependabot-managed.

## [0.41.0] - 2026-05-14

### Added

- Two new MCP tools: `preview_finding_remediation(finding_id)` and `apply_finding_remediation(finding_id, justification)` for operating on findings whose kind supports automatic remediation. Returns a structured diff (preview) and commits with audit-trail justification (apply). Bumps total MCP tool count to 97.
- "Remediating findings (structural drift)" section in `_INSTRUCTIONS_BASE` establishing the preview-then-apply norm: agents must surface the diff to the operator before committing remediation, and collect a one-line rationale.

### Changed

- "When you hit an implementation constraint mid-coding" section added to `_INSTRUCTIONS_BASE`. Describes the 3-step structural pattern (`import_controls` + `assign_control_to_components` -> `set_mitigation_groups` -> `add_assumption`) for recording weaker-but-feasible alternative mitigations without silently weakening existing controls.

## [Pre-0.41.0]

For releases prior to v0.41.0, see [git tags](https://github.com/Mipiti/mipiti-mcp/tags) and [GitHub Releases](https://github.com/Mipiti/mipiti-mcp/releases). Structured CHANGELOG begins from v0.41.0.

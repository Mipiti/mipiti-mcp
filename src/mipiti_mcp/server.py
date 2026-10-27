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

from . import catalog
from .assertion_types import (
    COVERS_MAX,
    COVERS_PATTERN,
    SOUND_CLASSES,
    describe_soundness_classes,
    describe_types,
    format_compact,
    validate_covers,
)
from .client import MipitiClient
from .types import ChatResponse

# ------------------------------------------------------------------
# Instructions (tier-aware)
# ------------------------------------------------------------------

# The version sent to clients on every tool call names the catalog a client
# pins when its session starts: every tool's contract and the instructions
# (catalog.py). It is computed once the tools are registered, at the end of
# this module, and written into the instructions where this marker stands.
# SERVER_VERSION, where set, overrides it (tests and local runs).
_VERSION_MARKER = "<<SERVER_VERSION>>"

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

Every tool call must include `server_version` set to `""" + _VERSION_MARKER + """`. If the server responds with an `instructions_updated` field, relay the message to the user, in a way appropriate to your environment, then continue with the current task.

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
- `generate_from_behavioural_model`: generates a model saved before its inventory (see Behavioural model) once `get_behavioural_model` reports `generation_ready`. Takes only the `model_id`. Progress reported automatically.
- `add_asset` / `edit_asset` — targeted single-entity changes without full refinement. An entity that does not apply is recorded with a non-applicability assumption or `create_co_disposition`, never by editing the entity.
- `add_attacker` / `edit_attacker` — same for attackers, plus `surface_extent`: `whole` when, from its position, the attacker's operations range over ANY entry of the interface it reaches (any endpoint, request, row, file, message or frame); `point` when they range over one named entry. Supplying it requires `change_reason` on either tool, and a person's call attests it, audited like a factor override. An attested `whole` makes the objectives that attacker anchors for-all obligations (see Controls and assertions). On `add_attacker` only `whole` is declarable — narrowing to one named entry is a statement about the objectives the attacker anchors, which a create does not have yet, so add the attacker and then narrow it with `edit_attacker`.
- **Attestations are judgments.** Attesting a boundary's seal, an attacker's position (`attest_position`), its privileges (`attest_privileges`) or its surface extent is a person's decision; a program takes it only where the workspace delegates it (`seal_attested`, `position_attested`, `privileges_attested`, `extent_attested`). A program refused is not given a 403: its edit lands unattested, the attestation is parked for a person, and the answer carries `attestation: {status: "escalated", escalation_id}`. An attestation holds for the content it was taken over: a later change to a boundary's `passes`, `crosses`, `neighbors` or `sealed`, or to an attacker's boundaries or privileges, voids it. Only attested grounds (a trusted position, attested privileges `None`, an attested seal on every blocking boundary) let reachability remove an objective.
- **Entity quality (authoring contract)**: an asset must name the *data or resource being protected* and the security property at stake (Confidentiality / Integrity / Availability / Usage), not a mechanism or control — name the key material, not "the KMS encryption". An attacker's `capability` names its position, what it holds and the *operations performable from there*, each on a named part of the system: "From [position], holding [credentials | no credential], the attacker can [concrete operations] …", never a technique or an outcome. Every claim must rest on the description, its answers or the entity's own answers. The check's verdict is read as `quality` on `get_entity`: `clean`; `advice` (a sharper wording, never a warning); `defect`, with `proposed` corrected words — apply them with `apply_entity_proposals`, naming the verdict's `input_hash`; `question`, one question for the owner; or `invalid`. Any flag (a question, a defect, an invalid verdict) may be answered with a fact through `answer_entity_question`, from the documentation or the code and naming where it is shown, never a guess: the check, shown the answer, decides again. Never weaken a true claim to clear a flag. The review queue's `entity_quality` row lists every entity with a correction, a question or advice. An entity whose `quality` reads `unchecked` is checked with `check_entity_quality`, naming it: it estimates first (RELAY THE ESTIMATE TO THE PERSON, and confirm only when they agree), never re-checks a current verdict, and is at Mipiti's cost where a platform change made the check necessary. `revalidate_entity_quality` asks every entity again whatever is stored, at your cost.
- `get_entity(entity_type=…)` — read any single entity by type + id. One reader for every entity kind: `asset`, `attacker`, `component`, `trust_boundary`, or `assumption`.
- `remove_entity(entity_type=…)` / `restore_entity(entity_type=…)` — soft-delete or restore any entity by type + id (`asset`, `attacker`, `component`, `trust_boundary`, or `assumption`); removals are audit-preserving. Every entity write (add, edit, remove, restore) answers with the model's id, version and title and, under `entities`, the records it wrote; read the whole model with `get_threat_model`.
- `reevaluate_threat_model_factors` — bulk LLM re-run of the factor decomposition (subscores + blast/recoverability/regulatory on assets; CVSS-Base + capability_prevalence on attackers) for every live entity in a model, or only those `entity_ids` names, or only those nobody rated (`unrated_only`: the entities a model reads as "not rated", one call each). Use this to re-baseline an existing model after the feature description changes meaningfully, or to refresh stale ratings — without regenerating the whole model (which would destroy controls, assertions, components). The platform's factor judgment is a calibrated *starting point*; layer deployment-specific reality on top via `edit_asset` / `edit_attacker` with a `change_reason` documenting the override (e.g., "regulatory_scope=Legal — tenant is HIPAA-covered", "capability_prevalence=Commodity — endpoint is public-internet exposed"). The rating-revision audit trail distinguishes platform suggestions from operator overrides.
- `revalidate_entity_quality` — re-run quality validation over an existing model's assets and attackers (a fast first-pass check on every entity, a deeper review only on the ones it flags). Use it to apply validation improvements to an already-generated model or clear stale quality warnings, without regenerating. Non-destructive (it flags rather than deletes) and creates no new version: it runs in the background, and the refreshed warnings appear on the next read of the model.
- `get_threat_model` — retrieve a model's structure (excludes COs by default; use `include_cos=True` to include them). The answers to its questions are counted and left out unless `include_clarifications=True`, which pages them. A read longer than 200,000 characters is cut, and `cuts` names what was cut and the read that serves it. `include_inventory_completeness=True` adds how much of the inventory the claims rest on: for each entity holding the tier down, `grounding_gaps` names every ground it lacks and the act that supplies it (the tool and its `mcp_arguments`, ready to send once the angle-bracketed values are filled).
- `query_threat_model` — ask questions about an existing model. It only answers; it never changes the model.
- `list_threat_models` — browse existing models.
- `update_threat_model` — a model's metadata: `name` (no new version; titles are unique within a workspace, case-insensitive), `parent_id` or `clear_parent` (its place on the recursive composition tree; cycles and over-deep chains are refused; no new version), and `provenance_*` (where its description came from; bumps the version).
- `delete_threat_model` — permanently delete a model and all its data.
- `export_report` — export a threat model. Its scope/format params produce a PDF, HTML, or CSV report, or the self-contained JSON audit archive of the model's current state (latest version, controls, live assertions with CI verdicts, findings, decisions in force, attestations, sufficiency signatures — independently verifiable without origin-instance access). The verdicts in it are the origin's record of what it claimed, which is what a third party checks; what an importing workspace credits is decided by its own verification (see `import_threat_model_archive`). The same tool produces a tag's auditor report (see Tags).
- `import_threat_model_archive` — restore an audit archive into a workspace as version 1 of a new model. Assigns a fresh model_id every time; title collisions auto-suffix `(imported YYYY-MM-DD)`. The restored model arrives unverified: the tier verdicts and run-attested flags on its assertions are the origin's record and are not credited here, so plan for the model to read unverified until verification runs against code this workspace can reach. It queues no judgement either: the result's `judgement` is the estimate, and `judge_objectives` with `confirm_estimate=True` queues it.

## Controls and assertions

A threat model produces control objectives. Controls are derived from these and represent specific security requirements to implement. Assertions are typed, machine-verifiable claims about system properties that prove a control is satisfied. A system property can be verified by examining source code, configuration files, infrastructure definitions, or external service settings.

**Key tools:**
- `get_controls` — lists controls with current status; pass a single control id to read just one. Use `summary_only=True` for a compact response (id, description, status, verification_status, assertion_count, co_ids, assumption_groups, attestation_dependency).
- `get_control_objectives` — lists COs with which controls cover each one; pass a single CO id to read just one. Pair with `get_reachability_verdicts` to surface composer reachability state per CO before linking assumptions or regenerating.
- `submit_assertions` — provide proof for a control. Call `get_assertion_types` for the types and their params; the tool description is prose your client may shorten. Always verify locally first: `mipiti-verify verify <type> -p key=value --project-root .` Read the target file and confirm a reviewer would agree with the claim.
- **Assertion design: prefer decomposition over breadth.** Tier 2 (semantic LLM check) evaluates each assertion with only its own check-type evidence. A single broad claim like "X calls Y to do A and B using C" will pass Tier 1 but fail Tier 2 — the mechanical evidence (e.g., a function_calls result) doesn't surface facts A, B, C. Split into multiple atomic assertions — one for each narrow aspect — each with a check type that directly shows the relevant code (`pattern_matches` on the specific line, `function_exists` for the named function, etc.). Submit them as a group on the same control. Sufficiency combines them; individually each is trivially provable.
- **Behavioral clauses need a test, not just a mechanism.** A clause such as "rejects an expired token" is shown to *exist* by a structural type (`function_exists`, `pattern_matches`) and shown to *hold* only by a test that exercised it. `test_exists` proves the test file is in the tree and nothing ran; `test_attested` proves it passed: a statement the repository's own CI workflow signed about a run against the commit under verification, which a developer machine cannot produce. It says nothing about a control the run had switched off, so pin the control on with the `env` param when it is configuration-gated, and pair it with the structural assertion for the mechanism. Coverage of the control's code path is not proven. A signed pass is strong tier-1 evidence, not a verdict: sufficiency still decides whether the clause is covered. An unsigned statement or an unattested run still covers the clause but is reported as a *claim*, never a witness.
- **A for-all clause needs a sound witness, not more tests.** Every assertion type declares a soundness class, returned by `get_assertion_types`: `presence` (a construct exists), `under_approximating_scan` (a pattern scan; clean proves absence of the form only), `existential_witness` (a signed run passed; proves the path it drove), `sound_over_approximation` (every sink site in a declared scope is a safe form or a reviewed exception) and `by_construction` (the sink accepts only a boundary type whose construction is default-denied). A clause that ranges over every entry of a surface — every endpoint, every query, every frame — is credited only by a witness of one of the two sound classes, bound to it with `covers`; `get_assertion_types` returns those classes in `sound_classes` and the types that carry them, and `get_control_work_order`'s `assertion_contract.sound_types` names the ones the platform takes. A test proves only the path it drove, and an attestation is a responsible party's claim, never a proof over every site. Read the work order before writing evidence: where the order names a required class for a clause, `required_evidence` carries the clause id to put in `covers` and a `suggested_submission` skeleton whose `<...>` placeholders you replace, and when a clause reads unverifiable by the current evidence, submit the named class rather than more tests. Where both are offered, prefer `typed_boundary` when the sinks accept a boundary type; otherwise `sink_default_deny`. Hardware sources are covered by the same two types: an assignment or a module instantiation is a sink. Where `sound_types` is empty, no type the platform offers discharges a for-all clause, and the acts that remain are the ones the order names: scope the asset to the component the attacker actually reaches, attest a `point` extent with its reason, or record a risk acceptance or a not-applicable disposition.
- **Bind evidence to what it proves.** Each submitted assertion may carry `covers`: the objective id (`CO-NN`) or, on a multi-clause control, the clause ids (`cls_…`) that `get_control_work_order` names in `required_evidence`. The form of the declaration is refused on arrival when it is malformed. A declared binding survives review; an undeclared one is inferred by review and capped below sound credit. Resubmit the assertion with `covers` to change the declaration.
- `list_assertions` / `delete_assertion` — list active assertions for a control; delete stale or incorrect ones before resubmitting.
- `update_control_status` — mark implemented or not_implemented. Requires at least one assertion BEFORE marking implemented. Always submit assertions first, then update status.
- `get_verification_report` — shows which controls are verified, which have sufficiency gaps, and which lack assertions entirely. Read `sufficiency_details` for the specific aspects that still need proof. Each `sufficiency` block also carries `misaligned_assertion_ids` (off-topic assertions that should be rebound, superseded, or rewritten — do not treat them as evidence) and `stale: true` (the stored verdict no longer matches the control's current inputs). Reading does not queue a re-evaluation: the write that changed a control queues its own, so re-read later for the refreshed verdict.
- `get_sufficiency` — quick check: do assertions for a single control collectively cover all aspects? Evaluated server-side at submission. For the per-clause work list read `get_control_work_order`: where the order names a required class for a clause, `required_evidence` carries the class, the clause id to bind evidence to, and a submission skeleton to fill in.
- `get_mitigation_groups` — get the current group structure for a CO with control details (id, description, status) for each entry. Shows numbered groups (AND within, OR across), defense-in-depth controls, and unmapped controls available for assignment. Use before `set_mitigation_groups`, when reviewing why a CO is at_risk, or to find unmapped controls.
- `set_mitigation_groups` — set which controls are required vs defense-in-depth for a CO. Use when a control is blocking a CO but is redundant with existing mitigations (e.g., HMAC signing redundant with TLS + content hash), or when restructuring alternative mitigation paths. Groups define: within group AND (all required), across groups OR (any complete group mitigates). AI-gated: rejected if the new structure doesn't satisfy the CO.
- `refine_control` — modify a control's description if it doesn't match the actual security requirement. **After an accepted refinement** the control's assertions are kept and judged again against the new description in the background: one that still fits keeps counting as evidence, and one that no longer fits is flagged, so read `get_sufficiency` once the re-judgement lands and replace what it names. Nothing is superseded by the refinement itself (`superseded_assertions` is always 0).
- `delete_control` — soft-delete a control with justification. Blocked if it is the only control covering a CO — add a replacement first.
- `import_controls` — import existing controls from JSON or free text, auto-mapped to COs and deduplicated against existing controls. They await their judgement: the groups they join credit nothing until `judge_imported_controls` is asked for.
- `edit_evidence` — attach (`action="add"`) or detach (`action="remove"`) auxiliary metadata (docs, links, artifacts) on a control. Evidence is contextual only — it does NOT prove a control is implemented. Only assertions do that.
- `regenerate_controls` — propose a regeneration of the controls (it starts nothing; `start_control_build` starts it). Supports `mode="per_co"` for thorough single-responsibility generation, and `co_ids="CO1,CO5"` to regenerate only specific COs (preserving other controls). Controls whose descriptions survive unchanged keep their implementation status, assertions, and mappings.
- `start_control_build` / `discard_control_build` — start the model's proposed control build after reviewing it, or drop a held one. See **Control builds** below.
- `list_control_revisions` / `undo_model_change` — every change to a version's controls with its author; undo the latest change (`target="controls"`, latest first, no redo), or revert the latest model version to a copy of the latest earlier version not already discarded (`target="version"`).

**Workflow — handle in this order:**

1. **Controls outside the system boundary** (externally handled): Read each not_implemented control description. If it describes something the system owner cannot implement (e.g., "restrict CI runner egress", "vendor maintains PCI DSS certification") — it belongs outside your trust boundary. Use `set_control_assumption_groups` to link it to an existing assumption, or create an assumption first with `add_assumption`. Do NOT submit codebase assertions for controls outside your boundary. The platform runs an AI relevance gate on every assumption-to-control linkage; if the assumption's description doesn't cover what the control requires, the call raises and there is no override. If rejected, either pick an assumption that covers the control or edit the assumption's description to make coverage explicit. `set_control_assumption_groups` handles both the simple single-assumption, single-group case and compound ("AS1 AND AS2") or multi-path ("AS1 OR AS2") cases.

2. **Controls already satisfied by existing code** (no code changes): use `get_controls` to list controls. For each, search the codebase for code that already implements it. If found, craft assertions that prove the implementation, verify locally, submit assertions, then call `update_control_status` to mark as implemented.

3. **Sufficiency gaps on verified controls** (no code changes): call `get_verification_report` and read `sufficiency_details` for controls that are partially verified. These are implemented but some aspects lack proof. Search the codebase for code that proves the missing aspects and submit additional assertions. If you cannot find proof for specific aspects, call `check_control_gaps` — the control's prescribed mechanism may need refinement.

4. **Controls requiring implementation** (code changes needed): before implementing, call `check_control_gaps` to verify the control's mechanism is appropriate. Then search the codebase for existing mechanisms that may already address the control. If found, call `refine_control` with `codebase_findings` — the platform evaluates whether the existing mechanism satisfies the objective and proposes a revised control if so. If accepted, submit assertions for the refined control. If rejected or no existing mechanism found, implement as prescribed, submit assertions, and update status.

Sufficiency is evaluated automatically server-side when assertions are submitted — no manual trigger needed.

Before implementing a control call `get_control_work_order`; reconcile with `reconcile_model`; check `list_decisions` before proposing; a refused judgment (403 with `escalation_id`, or for an attestation the edit's `attestation.escalation_id`) is parked for a person — do not retry, poll `list_proposals`.

**Behavioural model.** A model can carry a behavioural model: what the system does, as elements, actions and zones taken from its description. `get_behavioural_model` reads it and reports whether it has none, needs answers, is extracted, is confirmed, or has gone stale; `extract_behavioural_model` gives one to a model that has none. An extraction is paid: call it for the estimate, RELAY THE ESTIMATE TO THE PERSON, and confirm only when they agree; never confirm on your own. `get_behavioural_threats` returns the possible threats per objective: relay a possible threat to the person together with its default questions first, since an answer that settles a default removes it. Open behavioural questions appear on `get_review_queue` (`behavioural_question`, and `behavioural_link` for an element not yet linked to an asset or trust boundary). Answer a question only from what the code or the owner shows, and say unknown otherwise. Answers (`answer_behavioural_questions`), element edits (`edit_behavioural_element`), link declarations (`declare_behavioural_link`, `accept_behavioural_link_proposals`) and confirmation (`confirm_behavioural_model`) are judgments: a program's is refused with 403 and an `escalation_id` unless the workspace delegates it, so do not retry. An answer, an element edit and a confirmation each create a model version. A control's delta is read with `get_control_delta`, each edit in words beside its quotes; `submit_control_delta` stores a draft, checked and never declared. Declaring a delta is a person's act: `request_delta_second_reading` reads the text a second time (paid: RELAY THE ESTIMATE TO THE PERSON first), `declare_control_delta` without `confirm` previews the declaration and its differences, which you relay, and a program's confirmation is always parked for a person. A declared control's sufficiency is judged against its declaration (`get_sufficiency`'s `commitments`), and a cross-check asks whether its text commits to more; an open finding of it keeps the control insufficient until a person dismisses it in the app, which is never a program's act, so relay it. A `generate_threat_model` that returns `needs_answers` stopped on questions only the description's owner can answer: relay them and answer them. One that returns `extracting` saved the model and extracts its behaviour in the background. Follow an extraction with `get_behavioural_model(view="status", wait_seconds=50)`, which answers when the job moves and reports its progress meanwhile, until `extraction.job` is null; `view="questions"` pages the open questions without the whole model. Once it reports `generation_ready`, call `generate_from_behavioural_model` with the `model_id`: it takes no description (a `generate_threat_model` naming a `model_id` with a description is refused, `resume_takes_no_description`). Before submitting answers, call `answer_behavioural_questions` with `dry_run=true`: it records nothing and says whether they extract and which questions they leave or raise, so you answer those too and submit once. `get_behavioural_threats` is paged (`offset`, `limit`, `co_id`, `standing`): read on from `next_offset`. A question about the model's own structure carries `structured`, the ids its answer may name: answer it with `structured`, which edits the model at once with no extraction, where words are only read by the next extraction. Where the offer carries `new_zones` or `new_actors`, an answer may name a zone or a receiver the model lacks, and it is added. A question about what a zone holds (closure `zone_contents`: "What does the system keep in, or send to, <zone>?", or "<action> sends <values> over <channel> to <zone>, and the model holds none of it as an element") offers the `contents` form: `structured: {"elements": [...]}`, each element an id, or `{"id": "<id>", "secret": true}` for one that holds a secret. An id the offer lists under `elements` names an element already in the zone; any other id is a new element, declared in that zone, kept there, with one field (a secret where marked, else a plain value). The answer closes the question at once, with no extraction, and only widens what is analysed. An id another element holds elsewhere is refused 409 `id_in_use`; an empty or malformed list is refused 422 `structured_malformed`. The question takes one dismissal besides a fact: `disposition: "not_needed"`, saying the zone holds nothing of the system's; it stands while the zone, or what is sent there, is as it was asked about. `unknown` is refused. `get_behavioural_attackers` reads the attacker closure on a generated model: the attackers its credential classes say the inventory lacks (`add_proposed_attacker`, or `dismiss_proposed_attacker` with why, the whole proposal or, for a part of the zones nobody stands at, the `zones` no attacker reaches; where two proposals hold the same classes, name one by a `zone` of it), attackers standing for zones of several capabilities offered split (`split_grouped_attacker`, naming each part's zones, or `keep_attacker_whole` with why) and questions asking what an attacker holds (`answer_attacker_credentials`, whose answer sets its privileges by rule; `edit_attacker` then refuses a privileges change, 409 `privileges_from_holdings`). Each act is a judgment, as an answer is, and answers with the closure's counts rather than its lists. `get_inventory_judgements` reads what the per-entity checks found about the inventory: entries that may be one entity, and entities whose taxonomy tags are unchecked; `request_inventory_checks` queues the checks owed, `decide_inventory_pair` records that two entries are or are not one entity, and `declare_inventory_tags` the primitives an entity answers. Both are judgments (`inventory_pair_decided`, `inventory_tag_declared`), and nothing merges or removes an entity. `extraction.dropped_elements` lists what an extraction could not keep, with the sentence each came from: answer that sentence's question. Asking to extract again while an extraction is queued or running, or with no answer given since it started, is refused (409 `extraction_running`): poll it instead. `public` lets anyone invoke an action and authorises no one to change or read what it touches; an element changed from outside takes no writer (409 `outside_default`: answer its default question). A question marked `awaiting_fix` was answered; there is nothing more to answer. Where the code does more or less than a sentence, `decide_drift_intent` says whether that was intended or a defect (or propose it with `create_proposal` kind `drift_intent`), and a `description_revision` proposal revises the description when `drift.revision_suggested` is true. Obligations the analysis cannot settle can be model-checked: `request_model_check` is paid, so call it for the estimate, RELAY THE ESTIMATE AND ITS NOTICES TO THE PERSON, and confirm only when they agree; poll `get_model_check`, and `manage_model_check` pauses, resumes or discards it.

**Diagnosing "implemented but not verified" — check in this order.** A control that is marked implemented but still reads `partially_verified` is the most common state you will meet, and the fields are easy to misread. Work down this list and stop at the first hit; do NOT skip to a recompute.

1. `get_sufficiency` (or `get_verification_report` for the whole model) — **start here, it is free and it is usually the answer.** If `status` is `insufficient`, `details` names each uncovered clause and the evidence that would close it. That is the work list. Write those assertions.
2. Check the clause against reality. If the control describes a mechanism the system deliberately does not use (it returns 404 where the control demands 403, say), the DESCRIPTION is what is wrong — `refine_control`, do not manufacture evidence to match prose no one intends to honour.
3. `list_assertions` — only if sufficiency looks fine. A `fail` on `tier1_status`/`tier2_status` means the evidence itself is broken. `coherence_status: "pending"` is advisory: it is not a blocker and not a missing verdict.
4. `recompute_verdicts` — **only** when control-to-CO MAPPINGS look wrong (`get_verdict_divergence` shows missing/spurious mappings). It does not compute per-control sufficiency or assertion coherence, it costs credits proportional to model size, and running it for a sufficiency gap changes nothing. Its default `mode="quote"` returns the estimate and enqueues nothing: show the operator the number first, then call it with `mode="recompute"`.

The general rule: exhaust the free read-only verdict surfaces before recommending any metered write.

## When you hit an implementation constraint mid-coding

When a reviewer, hardware limit, library bound, or operator decision forces you off the prescribed mechanism (e.g., "this device only supports AES-128, not AES-256"), do NOT silently weaken the existing control or its assertions. Record the constraint structurally so the threat model reflects reality and the audit trail captures the reasoning. Use this 3-step pattern:

1. **Add the alternative control** — call `import_controls` with a single-entry `controls_json` describing the weaker-but-feasible mechanism. Set `co_ids` to the affected CO. Set `framework_refs` **honestly**: include only bindings the alternative actually satisfies — drop any that the weaker mechanism cannot meet. Then call `assign_to_components` to scope it to the constrained component(s) only, so the original control still applies elsewhere.

2. **Declare them as OR-alternatives** — call `set_mitigation_groups` on the affected CO with the original (strict) control in one group and the new (weaker) control in another (across groups = OR). Pass the operator's plain-language constraint reason in `justification` — it flows into the AI gate's verdict and the activity log.

3. **Record the constraint context** — call `add_assumption` with `linked_co_ids=[<co>]` capturing what reviewer or system imposed the constraint, the rationale, and any expiry conditions (e.g., "hardware refresh in 2027 lifts the AES-128 limit"). Then `submit_attestation` so the assumption is active.

If the alternative drops a framework binding the original carried, the platform automatically emits a `framework_binding_asymmetry` finding for the security team to triage — surfaced via `list_findings` and `get_findings_risks`.

## Assurance posture

- `assess_model` — deterministic assessment of all control objectives. Returns mitigated/at_risk/unassessed counts and progressive metrics (defined/implemented/verified COs). Use `summary_only=True` for a compact response with just the counts and a contextual `message` explaining the current state (e.g., "13 controls not implemented, blocking 35 COs"). Use `status` to filter, `offset`/`limit` to paginate, passing back the `snapshot` the first page names so every page comes from one evaluation. Each CO assessment includes `mitigated_by: "controls" | "assumption" | null` — `"assumption"` is a fully resolved state, not a gap. Only `at_risk` and `unassessed` COs require action.

**Reachability and risk reason**: Reachability per CO is exposed by `get_reachability_verdicts` (deterministic-computation provenance — re-derived from structural primitives, never persisted). Each CO assessment also includes:
- `risk_reason` — why a non-mitigated CO is at risk: `missing_controls` (implement controls), `pending_attestation` (submit an attestation for the linked boundary assumption), `expired_attestation` (renew an expired attestation), `unassessed` (generate controls or create an assumption), `coverage_gap` (controls are implemented but do not span the CO's full threat — add controls to close the gap, or dismiss/accept if intentional), `insufficient_by_design` (the controls *defined* for the CO's mitigation group would not mitigate the objective even if fully implemented — a design gap, not an implementation gap; redesign or add controls so the group can span the threat), `no_mitigation_group` (controls address the objective and none of them is grouped, so nothing states which are required together), `awaiting_judgement` (a group is built and nothing has judged whether it covers the objective). `insufficient_by_design` is more binding than `missing_controls` and takes precedence over it.

**Two of those reasons are not evidence gaps and adding controls will not move them.** `no_mitigation_group` and `awaiting_judgement` both say the objective's controls may be complete and the missing thing is a statement about them: which of them are required together, and whether that set covers the objective. Read them as such before generating anything.
- `pending_assumption_ids` / `expired_assumption_ids` — assumption IDs that need attestation action.

**Before acting on any risk_reason, check whether a control is actually REQUIRED for the objective.** `get_mitigation_groups` splits a CO's controls into numbered groups (within=AND, across=OR) and `defense_in_depth`. Only the groups earn mitigation credit. If a CO has controls attached but ALL of them sit in `defense_in_depth`, or it has no groups at all, then nothing is required to mitigate it and the CO cannot leave at-risk no matter how many controls you generate or how much evidence you submit. That is a modelling gap, not an evidence gap: decide which controls genuinely carry the objective and place them in a required group with `set_mitigation_groups` (AI-gated, so the structure has to actually satisfy the CO). Generating or proving controls in this state is wasted work.

**Action routing by risk_reason**: `missing_controls` → implement controls and submit assertions. `pending_attestation` → call `submit_attestation` for the assumption IDs listed in `pending_assumption_ids` — do NOT try to implement controls for boundary-excluded COs. `expired_attestation` → call `submit_attestation` to renew for the assumption IDs listed in `expired_assumption_ids`. `unassessed` → the CO has no controls: read the model's `proposal` in `get_control_generation_status` (or propose one with `regenerate_controls`) and, once the user agrees to its estimate, start it with `start_control_build`. If the composer says the CO is indeterminate (per `get_reachability_verdicts`), the model is missing structure — supply it (position the attacker, scope the asset to a component) rather than asserting a conclusion. If the objective genuinely does not apply to this system, record that with `create_co_disposition`: the objective stays in the matrix and the counts, carrying the owner and justification, instead of disappearing. `coverage_gap` → the controls are implemented but leave part of the CO's threat unaddressed. Inspect the linked `coverage_gap` finding via `list_findings` for the uncovered aspects + suggested control, add controls (`regenerate_controls` / `import_controls`) and submit assertions; if it's a false positive `dismiss` the finding, or if intentional record a risk acceptance / assumption. `insufficient_by_design` → the controls *defined* for the CO's mitigation group would not mitigate the objective even if fully implemented. Do NOT just implement the defined controls — that will not help. Inspect the linked `insufficient_by_design` finding via `list_findings` for the rationale, then redesign or ADD controls to the mitigation group (`regenerate_controls` / `import_controls`, then `set_mitigation_groups`) so the group can actually span the objective's threat, and submit assertions; if it's a false positive `dismiss` the finding, or if intentional record a risk acceptance / assumption. (Contrast with `missing_controls`, where the defined controls *would* mitigate the CO and you simply implement them and submit assertions.) `no_mitigation_group` → decide which controls genuinely carry the objective and place them in a required group with `set_mitigation_groups`; do NOT generate more controls, the ones that matter are already there. `awaiting_judgement` → call `judge_objective` on the CO, or `judge_objectives` for all of them at once. Nothing has decided whether its group covers it, so neither implementing nor adding controls changes the reason; the remedy is the judgement. It may come back insufficient, which moves the objective to `coverage_gap` / `insufficient_by_design` and names real work — that is the answer, not a failure.

## Gap discovery

For controls with status not_implemented, determine whether the code already implements them (submit assertions) or genuinely lacks them (submit findings):
- `get_review_queue` — start here for periodic maintenance: returns controls not reviewed in 90+ days. For each stale control, verify its assertions still hold against the current codebase.
- `get_scan_prompt` — returns targeted prompts for scanning the codebase against specific not_implemented controls (this is the security-control kind; the same tool serves the functional-conformance per-test briefs when you pass the functional kind — see Functional conformance).
- `check_control_gaps` — AI-powered gap analysis across all controls.
- `submit_findings` — report confirmed gaps where controls are missing.
- `list_findings` / `update_finding` — track finding lifecycle.
- `get_findings_risks` — workspace-wide dashboard: open findings, active risk acceptances, and at-risk Control Objectives in one call. Use as the triage entry point when the operator asks "what's open?" / "what should I work on next?".
- `get_risk_view` — Prioritized Risk View rows for a specific target (pass the scope — a model, or a tag) with risk dimensions, control coverage counts, and open-finding counts per CO. Use when narrowing from workspace-wide to a specific target.
- `get_remediation_leverage` — for one model, the not-yet-satisfied controls ranked by how many control objectives each closes, plus a greedy minimal fix order. Use to prioritize implementation: which controls to build first for the shortest path to coverage; each entry names its owning model, so a high-leverage control inherited from a parent model is clear.
- `list_risk_acceptances` — see which risks have been explicitly accepted on a model (with owner, justification, review deadline) so you can separate intentional acceptances from genuinely unaddressed gaps.
- `create_risk_acceptance` — record a deliberate acceptance of a control objective's residual risk (owner, justification, review deadline) so a known-and-accepted decision is explicit and auditable rather than an implicit gap.
- `create_co_disposition` — record that a control objective DOES NOT APPLY to this system (owner, justification, review deadline). The sibling of a risk acceptance, and the difference is the claim: an acceptance says the exposure is real and is being carried; a disposition says the objective does not apply here at all. The objective is NOT removed — it stays in the matrix and in every coverage count, reported in its own class with the owner and justification attached, so a reviewer can challenge the judgment. What it does suppress is work: no controls are generated for it and no coverage gap is raised against it.
- `list_co_dispositions` — see every signed judgment on a model's objectives (both kinds, including expired and revoked ones, which are part of the audit trail). Read this before authoring a new one: an existing judgment may already cover the objective, or may have expired and need re-signing rather than duplicating.
- `recompute_verdicts` — `mode="quote"` (the default) returns the cost estimate and enqueues nothing; `mode="recompute"` forces a fresh evaluation of every control's coverage verdict and every live CO's group-sufficiency verdict when the surfaced divergences look stale; `mode="retry_parked"` re-runs only the verdicts a transient failure parked. Work runs in the background, with a spend status object (an exhausted status means the work is queued and resumes automatically — never dropped).
- `judge_objective` — have ONE control objective's mitigation group judged. The right tool for an objective reading `awaiting_judgement`; prefer it over `recompute_verdicts`, which sweeps the whole model and costs accordingly. Runs in the background and may consume credits. It is not a repair: the judgement can come back insufficient.
- `judge_objectives` — the same for every objective that has no judgement for its current controls and none queued (the diagnosis's `not_judged` count). Call once for the estimate and show the user, then again with `confirm_estimate=True` to queue; any credits it consumes are metered as each judgement runs. Objectives with no mitigation group come back in `ungrouped` and are not judged.

## Remediating findings (structural drift)

The platform emits structural-drift findings (e.g. duplicate controls that accumulated from prior platform behavior, framework-binding asymmetries when mitigation groups have inconsistent compliance coverage) via list_findings. For findings whose kind supports automatic remediation, you can offer the operator a one-click cleanup flow:

1. Call remediate_finding(finding_id) to see the proposed change: without `apply` it only previews. The response is a structured diff scoped to that one finding — typically very small.

2. SHOW THE OPERATOR THE DIFF. Do not commit silently. The operator should see exactly which controls would be merged, what framework refs would consolidate, etc.

3. Get the operator's confirmation AND a one-line rationale (e.g. "cleaning up duplicates from pre-fix trigger bug").

4. Call remediate_finding(finding_id, apply=True, justification=<rationale>) to commit. The platform records who, what, and why for the audit trail.

Never apply remediation without preview. The platform does not enforce this — it's the agent's responsibility to surface the change before committing.

**Diagnose-and-hand-off findings.** Some finding kinds have NO automatic remediation handler (`remediate_finding` returns 422) — they describe a gap for you to resolve directly with the control tools, then submit assertions / `update_finding`: `coverage_gap` (the CO's controls do not span its full threat → add the missing controls via `regenerate_controls` / `import_controls`, or `dismiss` if a false positive, or record a risk acceptance / assumption if intentional), `insufficient_by_design` (the controls *defined* for the CO's mitigation group would not mitigate it even if fully implemented → do NOT just implement the defined controls; redesign or add controls to the mitigation group via `regenerate_controls` / `import_controls` + `set_mitigation_groups` so the group can span the threat, or `dismiss` if a false positive, or record a risk acceptance / assumption if intentional), `control_mechanism` (an existing control's mechanism is wrong and could not be corrected automatically → edit, split, or remove it; the finding's details list the control's full CO-set so you see the blast radius before changing a shared control), `misclassified_defense_in_depth` (a defense-in-depth control is load-bearing for a CO's coverage → promote it into that CO's mitigation group via `set_mitigation_groups`). Do not call `remediate_finding` for these kinds.

## Project setup

- `get_setup_status` — check which onboarding steps are done and which are pending. Call before suggesting setup actions to avoid repeating completed steps.
- `complete_setup_step` — mark an onboarding step as done. Call after completing a setup action: `mcp_configured` (after MCP server is connected), `mipiti_verify_installed` (after installing mipiti-verify), `ci_secret_added` (after adding the API key to CI secrets), `ci_pipeline_added` (after adding the verification job to CI).

## Trust boundaries and assumptions

Trust boundaries and assumptions are versioned (CRUD creates new model versions with carry-forward).

**Decision rule — control or assumption?** If a security requirement can be implemented and machine-verified in the codebase → it is a **control**. If it describes a property that must be upheld by an external party (customer, vendor, operator) and cannot be implemented by the system owner → it is an **assumption**. The trust boundary is the dividing line. When in doubt: if you cannot write a codebase assertion that proves it, it is an assumption.

- `get_threat_model` — returns existing trust boundaries (along with assets, attackers, and assumptions). Use this to review current boundaries before adding or modifying them.
- `add_trust_boundary` / `edit_trust_boundary` — create or edit trust boundaries (defines where trust transitions occur); soft-delete one with `remove_entity(entity_type="trust_boundary")`. `sealed=True` on its own is a suggestion; only an attested seal (`edit_trust_boundary` with `seal_source="attested"` and a `change_reason`, by a person or a program the workspace delegates `seal_attested` to) lets reachability decisively drop an objective past the boundary. A change to the boundary's `passes`, `crosses`, `neighbors` or `sealed` voids the attestation.
- `add_assumption` — add an assumption, optionally linking it to COs it covers via `linked_co_ids`. Linked assumptions can mitigate COs when attested.
- `edit_assumption` — update description and/or linked COs.
- `remove_entity(entity_type="assumption")` — soft-delete an assumption (preserved for audit). Its CO links are cleared and its attestations retired; controls whose `assumption_groups` name it keep their groups, which credit nothing through it while it is deleted.
- `restore_entity(entity_type="assumption")` — restore a soft-deleted assumption to active. Its CO links are not restored (set them again with `edit_assumption`), and it must be attested again before it counts anywhere it is linked or grouped.
- `submit_attestation` — record that a responsible party affirmed an assumption holds. Provide `attested_by`, `statement`, and `expires_at` (ISO 8601, e.g. "2027-03-29T00:00:00Z"). Expiry triggers CO re-evaluation. Attesting accepts the assumption: a program is refused (403 with `escalation_id`) unless the workspace delegates `assumption_accepted` to it. Editing an assumption's description retires its attestation. An attestation is a claim: it can cover an existential clause and never a for-all one, and a CI-minted attestation is no stronger than the weakest assertion behind it.
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
3. Convert to controls — `convert_assumption_to_controls` retires the assumption linkage and proposes the control build its COs owe; `start_control_build` starts it
4. Accept risk — `create_risk_acceptance` (the exposure is real and is being carried), or `create_co_disposition` (the objective does not apply to this system at all). Both are signed, owned, justified and expiring; `list_co_dispositions` shows what is already recorded.

## Composition (recursive-tree multi-model)

Threat models can compose hierarchically — a child model inherits assets, attackers, components, trust boundaries, and baseline controls from its parent (and transitively from ancestors). With composition enabled, the effective model = own ⊕ inherited; the platform computes effective control objectives, coverage, compliance, reachability, attack paths, and finding inheritance over that composed view.

**When to use**: a child model that shares a security baseline with its parent (e.g., a feature built on top of a multi-tenant platform that already has auth / MFA / RBAC / KMS controls). Composition lets the child operator focus on the feature's delta while the parent's controls credit the child automatically.

### Reading the composed view

Start with the overview, then drill in, all through `get_composition`:
- `get_composition(view="overview")` — flag state, tree position, own-vs-inherited counts, reconciliation badge. Cheapest call (~1-2KB). Use first.
- `get_composition(view="entities")` — full own + inherited entity set per kind.
- `get_composition(view="objectives")` — effective CO list (classified own / cross / inherited).
- `get_composition(view="coverage")` — effective coverage / compliance numbers.
- `get_composition(view="attack_paths")` — AttackPath references resolved against the effective entity set (paths spanning inherited entities resolve cleanly).
- `get_reachability_verdicts(composed=True)` — composed reachability verdicts.

### Reconciliation — surfaced cross-tree duplicates

When the same entity is authored on both the child and an ancestor (e.g., both name an "API Gateway" component), the detector surfaces it as a reconciliation candidate. Two tiers:
- `certain` — identical name AND identical structural refs (same trust boundary / asset attachments). Auto-merge eligible.
- `heuristic` — identical name only; structural refs differ. Triage needed.

Tools:
- `list_reconciliation_candidates` — the paginated candidate list with names, source-model titles, and reasons; `disposition="rejected"` lists the pairs rejected on the model instead.
- `decide_reconciliation_candidate` — `decision="apply"` collapses a candidate onto the inherited entity; `decision="reject"` records "these are NOT duplicates" (the detector filters the pair out of future queues, durable at org scope); `decision="unreject"` undoes a rejection.

### Mutations — lift and split

When the operator confirms a duplicate should be reconciled, lift it to the lowest common ancestor (LCA). Inverse: split an ancestor entity down to specific descendants when the entity isn't shared after all.
- `lift_composition_entity` — promote shared-anchor entity from two descendants to their LCA. Carries operator confirmations (LCA, third-party subtree acknowledgements, field-resolutions, attached-state resolutions, optional over-application-gate override). Emits `lift_applied`; audit pack surfaces under `lift_history`.
- `split_composition_entity` — push an ancestor entity down to operator-chosen descendants. Emits `split_applied`; audit pack `split_history`.

### Undo with divergence detection

Both lift and split mutations are reversible. The divergence detector refuses the undo with enumerated reasons if state has continued to evolve since the mutation (e.g., entity edited after lift, re-lifted further up, descendant collision, attached-state mutation, model deletion).
- `undo_composition_event(…)` — by default (`dry_run=True`) a read-only preview of undoing a lift or split (pass the event type / id), returning `{plan, refusal}`; with `dry_run=False` it applies the inverse. Always preview FIRST. An applied undo emits one of:
  - `lift_undone` — citing `original_event_id`.
  - `split_undone` — citing `original_event_id`.

**Operator pattern**: preview → inspect plan or refusal-reasons → if clean proceed with apply; if refused, surface the enumerated reasons (operator decides whether to edit the divergence manually or accept it).

## Cross-model dependencies (delegation)

Distinct from the parent/composition tree (containment): a *reliance* edge declares that one model depends on a control implemented in ANOTHER model — the right tool when a product is built on shared services (auth, logging, a shared datastore) rather than being a sub-part of them. The target is always a provider *control*, so credit terminates at a proven mechanism. Reliance is scoped to the current workspace: a consumer can only delegate to provider models in the SAME workspace (these tools don't see models across workspace boundaries), so pick the foundation from this workspace's models. These tools are available when the recursive-tree feature is enabled.

- `declare_foundation` — mark a shared-service model as a foundation that advertises specific controls other models can delegate to.
- `attach_foundation` — bulk flow: without `selections` it proposes which of a consumer's objectives each foundation capability covers (read-only, scored); with the chosen subset as `selections` it creates draft delegation edges for them.
- `manage_reliance` — one edge at a time. `action="create"` declares a dependency: `delegated` (consumer has no local control for an objective; the provider handles it — pass `source_objective_id`) or `relied_upon` (consumer keeps its own control but its validity depends on the provider's — pass `source_control_id`). `action="confirm"` promotes a draft edge to active: edges run LLM semantic validation on creation and carry NO credit until confirmed, and only when validation returned `valid` (a `partial` or mode-mismatch is refused — never silently credited). `action="delete"` removes an edge.
- `list_reliance` — a model's dependency edges (as consumer) plus who relies on it (as provider — the blast radius before changing its controls).

A delegated objective is credited only while the provider control stays verified; if the provider control regresses or a refined mechanism no longer satisfies the consumer, the edge breaks and a finding is raised on the consumer.

## Tags (grouping)

A *tag* is an overlapping, semantics-free grouping of models — for audit scopes, ad-hoc selections, products or portfolios. It is a label, not a relationship: a model may carry MANY tags, and a tag never affects posture or credit (that's what delegation and composition are for). Use tags to organize and to get an aggregate view across a chosen set of models. The group tools act on tags.

- `create_group` / `delete_group` — create or remove a tag (deleting affects the grouping only, never the member models).
- `add_model_to_group` / `remove_model_from_group` — manage membership; a model can be in many tags at once. A model added to a tag takes on the frameworks the tag selected.
- `list_groups` / `get_group` / `list_model_groups` — browse tags, read one with its members, or list a model's tags.
- `get_group_dependencies` — the reliance edges among a tag's members, each with its status and whether it credits its objective.
- `get_risk_view` — aggregate per-CO risk across a tag's members (`scope="tag"`). Delegation-aware, so a CO mitigated via a verified cross-model delegation reads as covered, consistent with the per-model assessment.

A tag can also be a **compliance / audit scope** spanning several models: `select_compliance_frameworks` scoped to the tag selects frameworks for the tag and propagates them to its members; `get_compliance_report` scoped to the tag gives cross-model requirement coverage; `export_report` scoped to the tag produces the signed auditor HTML (every member's report, after the reliance edges among the members with their status).

## Functional conformance

Functional conformance proves a feature does what it was *specified* to do — the parallel of security controls, verified by the same assertion + CI engine. Capabilities are the behaviours the feature must deliver; each is tested against a taxonomy of operating conditions (nominal, boundary, dependency-failure, …), and a Functional Objective is a Given-When-Then acceptance criterion. Two ways to establish coverage:

**Generate (top-down).** `generate_functional_objectives` derives capabilities, objectives, and the concrete tests to write; `get_scan_prompt` (pass the functional kind) returns the per-test brief; implement each test, register it with `add_functional_test`, then submit `TEST_EXISTS` + `TEST_ATTESTED` evidence with `submit_assertions` (pass `functional_test_id`) so CI verifies it.

**Import (bottom-up) — bring the tests you already have.** `import_functional_tests` registers your existing codebase tests (optionally with the objectives they cover; the platform verifies each association is applicable before accepting it). For tests you don't map yourself, `suggest_functional_test_mappings` proposes which objective each one actually proves (judged on behaviour, with a confidence) and `associate_functional_test` confirms a mapping — so an existing suite counts toward conformance, not only Mipiti-specified tests.

- `get_capabilities` — every capability, or one by `capability_id`.
- `get_functional_coverage` — the Capability × Condition coverage report; `gaps_only=True` returns just the actionable gaps (uncovered cells, failing/untested objectives).
- `set_functional_satisfaction_groups` / `get_functional_satisfaction_groups` — when several tests must *together* prove an objective, group them (within a group all must pass; any complete group proves the objective).
- `get_sufficiency` with `functional_test_id` — whether a test's submitted evidence is sufficient to prove the objective it targets.
"""

_INSTRUCTIONS_COMPLIANCE = """\

## Compliance

1. `list_compliance_frameworks` — available frameworks (SOC 2, ISO 27001, etc.).
2. `import_compliance_framework` — import a customer-specific framework (regulatory, contractual, or internal program not covered by the built-ins). Accepts a JSON body with `name`, `requirements`, and the optional `level_definitions` per-level legend.
3. `select_compliance_frameworks` — activate frameworks for a model (or, by scope, for a tag). **Automatically triggers auto-remediation** for a model: maps existing controls, excludes non-applicable requirements by taxonomy, and suggests/applies new entities for remaining gaps. Returns `auto_remediate_jobs` with job IDs for polling.
4. `get_compliance_report` — coverage report for a model, or for a tag by scope (run after auto-remediation completes).
5. `auto_remediate_compliance` — re-trigger auto-remediation manually (e.g. after model changes).
6. `auto_map_controls` — map controls to framework requirements (runs automatically during auto-remediation, but can be triggered independently).
7. `map_control_to_requirement` — manually map a specific control to a specific requirement (use when auto-mapping misses or misassigns).

### Per-entity grades

Some frameworks (IEC 62443, ISO/SAE 21434, NIST CSF, FIPS 140-3, Common Criteria) carry per-entity level grades alongside the control-to-requirement mapping:

- `edit_component` with `target_sl` / `eal` / `fips_level` — set per-component IEC 62443 SL (1-4), CC EAL (1-7), FIPS 140-3 (1-4). Orthogonal axes; set whichever the customer program requires.
- `set_control_objective_cal` — set per-CO ISO/SAE 21434 Cybersecurity Assurance Level (1-4). Lives on the CO identity table; survives soft-delete.
- `update_organization` — set per-org IEC 62443-4-1 Maturity Level (1-5) and NIST CSF Tier (1-4). Admin-only.

## Workspaces

- Every MCP credential is bound to one workspace when it is issued (an API key by its scope, an OAuth token by the workspace chosen on the consent screen), and every tool operates in that workspace. To work in another workspace, connect with a credential issued for it; there is no tool that lists or switches workspaces.

## Components

Components bridge security architecture (trust boundaries) to code organization (repos). Add components to a model to scope controls to specific codebases AND to ground the deterministic reachability composer's asset-boundary derivation.

- `add_component` — create a component with name, repo_url, and optional path (for monorepos) and trust_boundary_ids.
- `edit_component` — modify a component; delete one with `remove_entity(entity_type="component")`.
- `get_controls` with `component_id` — filter controls by component.
- `assign_to_components` — link an asset (or a control) to one or more components. For an asset this drives the reachability composer's per-CO verdicts.

### When to populate components

`generate_threat_model` proposes speculative components (with `repo_url=""`) when no topology has been supplied. These are a starting point — refine them as code grounding emerges:

- **Existing codebase**: a component is created against a model, so there is none to supply before one exists. Call `generate_threat_model` first, with the services you found written into `feature_description`, then `edit_component` on each speculative component it proposed, swapping `repo_url` and `path` to the real values, or `add_component` for the ones it missed.
- **Planning conversation, no code yet**: call `generate_threat_model` directly; the LLM-proposed speculative components serve as a topology starting point the user/developer refines as the design firms up. `repo_url` stays empty until code exists; the coherence report flags `component_unbound` findings on speculative components so they're visible to auditors.

A component with empty `repo_url` is the natural signal "speculative — not yet bound to code." A component with a populated `repo_url` is grounded. There is no separate status field — the binding is the state.

But an empty `repo_url` covers two different things, and the component's trust boundary tells them apart. A component in one of YOUR internal zones (your own backend/frontend/service repos) is your code — ground it to the repo. A component in an EXTERNAL trust zone — e.g. a third-party service, the customer's IdP, or other infrastructure you call but do not own — has no repo of yours; leave it unbound, where `component_unbound` is the correct permanent marker of an external dependency, not a TODO. The test is the trust boundary, never "does some client code touch it": client code for almost every dependency lives in your repo, so that alone never justifies binding an external component.
"""

_INSTRUCTIONS_ASYNC = """\

## Long-running operations

`generate_threat_model`, `generate_from_behavioural_model`, `refine_threat_model`, `auto_remediate_compliance`, `auto_map_controls`, and `check_control_gaps` run LLM pipelines that may take several minutes. They block until complete and report progress automatically; no polling is needed for the operation itself. Entity writes (`add_asset`, `edit_asset`, `add_attacker`, `edit_attacker`, `remove_entity`) run as background jobs and report progress while they wait; a job a client stops waiting for finishes or fails on its own, so read the model before writing again.

**Control builds.** A model's controls are built only by a build someone starts. Generating or refining a model, editing an entity, and `regenerate_controls` each PROPOSE a build and start nothing: their result carries `controls_status: "proposed"` and a `proposal` (what it would build, `estimated_credits` with its basis, and the `model_version`, `set_revision` and `scope_revision` a start must name), and `get_control_generation_status` shows the same `proposal`. Do not report controls as built, or wait for them, until a build has been started. The proposal also names what to review first: `flagged_entities` (a judge's warning, a rating nobody chose, a suspected duplicate) and `pending_attestations` (a seal, position or privileges that, once attested, would remove objectives from the build); neither blocks a start. Review the model with the user, show them the estimate, and once they agree call `start_control_build(model_id, model_version, set_revision, scope_revision, confirm_estimate=True)`. A `review_stale` refusal means the model, its controls or the objectives the build would author changed since you read the values: review again and start with the values it returns. A started build holds the model until it publishes: other writers of its controls are refused (`generation_active`), and reads show the last published controls. Poll `get_control_generation_status` (it returns `terminal` and a `hint`) until the status is terminal, then read the controls with `get_controls`. `deferred` means the workspace's daily background-analysis budget is used up; the build resumes automatically at the daily reset — surface that, no action needed. `paused` means someone stopped it: its work so far is kept but not published, and only `resume_control_generation` continues it. To stop a build the user did not want, call `pause_control_generation`; once it shows `paused`, `discard_control_build` drops its work and proposes it again, and the model can be deleted as usual.

**Every change to the controls is a revision.** `list_control_revisions` shows who changed what; `undo_model_change(target="controls")` undoes the latest change (latest first, no redo); `undo_model_change(target="version")` replaces the latest model version with a copy of the latest earlier version not already discarded, keeping the replaced one in the history as discarded.

**Strengthening runs when asked.** A completed build reports `strengthening` and a `diagnosis` (objectives covered, uncovered, undecided, judging, not judged, or waiting on an assumption decision). `judging` counts objectives whose judgement is queued: wait for them. `not_judged` counts objectives with no judgement for their current controls and none queued: to have them judged now, call `judge_objectives` (estimate first, then `confirm_estimate=True`). Unless the workspace strengthens automatically, nothing works on the uncovered ones until `strengthen_controls` is called: call it once to get the estimate, show the user, and call it again with `confirm_estimate=True` and the `model_version` and `set_revision` the estimate returned to start. A gap only the environment can close is answered with an assumption, never a control: an accepted one is bound into the group, and otherwise a proposal waits in the review queue for a person to accept (with an expiry) or reject.
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
        text = _INSTRUCTIONS_BASE + _INSTRUCTIONS_COMPLIANCE + _INSTRUCTIONS_ASYNC
    else:
        text = _INSTRUCTIONS_BASE + _INSTRUCTIONS_ASYNC
    return text.replace(_VERSION_MARKER, _SERVER_VERSION)


#: The instructions' text a catalog covers: every tier's parts, before the
#: version is written into them.
_INSTRUCTION_PARTS = [_INSTRUCTIONS_BASE, _INSTRUCTIONS_COMPLIANCE, _INSTRUCTIONS_ASYNC]

# Set at the end of this module, once every tool is registered.
_SERVER_VERSION = ""
CATALOG: dict = {}
CATALOG_VERSION = ""
#: The recorded catalogs, read only when a call names an older version.
_CATALOG_HISTORY = catalog.shipped_history

mcp = FastMCP("Mipiti")


# ------------------------------------------------------------------
# Server version check middleware
# ------------------------------------------------------------------

from fastmcp.server.middleware import Middleware


class VersionCheckMiddleware(Middleware):
    """Run a tool call only under the contract its session pinned
    (catalog.compatible).

    A call naming the current version runs. A call naming a recorded catalog
    in which the called tool's contract is the one it has now runs, and its
    result carries ``instructions_updated``: the session's instructions are
    older, its tool is not. Any other call is refused with the update message
    without executing the tool: an unknown or missing version, or a tool
    whose contract changed. A missing version is refused, never treated as
    current, or omitting it would run a call under any contract.
    """

    async def on_call_tool(self, context, call_next):
        message = context.message if context else None
        args = (getattr(message, "arguments", None) or {}) if message else {}
        tool = getattr(message, "name", "") or ""
        decision = catalog.compatible(
            args.get("server_version", "") or "", tool, _SERVER_VERSION, CATALOG,
            _CATALOG_HISTORY)
        if decision == "refuse":
            raise ToolError(_INSTRUCTIONS_UPDATE_MESSAGE)
        result = await call_next(context)
        if decision == "notice":
            return _with_notice(result)
        return result


def _with_notice(result):
    """The result with ``instructions_updated`` beside it: a content block the
    agent reads, and the same key in the result's metadata."""
    from fastmcp.tools import ToolResult
    from mcp.types import TextContent

    notice = {"instructions_updated": _INSTRUCTIONS_UPDATE_MESSAGE}
    return ToolResult(
        content=[*result.content, TextContent(type="text", text=json.dumps(notice))],
        structured_content=result.structured_content,
        meta={**(result.meta or {}), **notice},
        is_error=result.is_error,
    )


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


_JUSTIFICATION_MIN_CHARS = 10
_JUSTIFICATION_MAX_CHARS = 2000


def _check_justification_length(justification: str) -> None:
    """Enforce the platform's bounds on an AI-gated justification before the
    call, so an out-of-range value fails here with the limit named rather than
    as a validation error from the server."""
    length = len(justification.strip())
    if length < _JUSTIFICATION_MIN_CHARS:
        raise ToolError(f"justification must be at least {_JUSTIFICATION_MIN_CHARS} characters.")
    if length > _JUSTIFICATION_MAX_CHARS:
        raise ToolError(
            f"justification must be at most {_JUSTIFICATION_MAX_CHARS} characters "
            f"(got {length}). State the reasoning; evidence belongs in assertions."
        )


async def _await_backend_job(client: MipitiClient, job_id: str, ctx: Context,
                             timeout: float = 600, heartbeat: bool = False) -> dict:
    """Poll a backend job until completion, reporting progress via MCP protocol.

    Detects client disconnect (when running over Streamable HTTP transport) and
    aborts polling early so we don't keep doing work for a dead client. The
    backend job itself is intentionally NOT cancelled — it continues running so
    that a retry with the same Idempotency-Key can pick up the cached result.

    ``heartbeat``: a poll that carries no progress of its own still reports
    one (indeterminate, naming the job's state), so a client whose idle timer
    a silent wait would outlast keeps receiving progress while the job runs.
    It never interrupts a numeric sequence: once the job has advertised a
    total, only that sequence is emitted.
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
            raise ToolError(
                f"Operation timed out after {timeout}s waiting for job {job_id}; the "
                "job goes on and finishes or fails on its own. Read the model to see "
                "whether it saved.")

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
        elif heartbeat and locked_total is None:
            poll_counter += 1
            await _safe_report_progress(
                ctx, poll_counter, None, f"job {job_id}: {status or 'running'}")

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


#: The collection each entity kind lives in on a model.
_COLLECTIONS = {
    "asset": "assets", "attacker": "attackers", "component": "components",
    "trust_boundary": "trust_boundaries", "assumption": "assumptions",
}

#: The keys under which a write's answer carries a whole model, or a list of
#: them: an entity write's ``model``, a lift's three, a split's and an undo's.
_MODEL_KEYS = ("model", "lca_model", "descendant_a_model", "descendant_b_model",
               "ancestor_model", "descendant_models", "source_descendant_models")


def _model_ref(model: Any) -> Any:
    """A whole model as a write's answer names it: its id, version and title.
    The model itself is read with ``get_threat_model``."""
    if not isinstance(model, dict):
        return model
    return {k: model[k] for k in ("id", "version", "title") if k in model}


def _without_models(answer: Any) -> Any:
    """``answer`` with every whole model it carries under ``_MODEL_KEYS``, at
    its top level or under ``models``, replaced by its ``_model_ref``; every
    other key as sent."""
    if not isinstance(answer, dict):
        return answer
    out = dict(answer)
    for key in _MODEL_KEYS:
        value = out.get(key)
        if isinstance(value, list):
            out[key] = [_model_ref(m) for m in value]
        elif isinstance(value, dict):
            out[key] = _model_ref(value)
    if isinstance(out.get("models"), dict):
        out["models"] = _without_models(out["models"])
    return out


def _entity_change(answer: Any, kind: str, entity_ids: tuple = ()) -> Any:
    """An entity write's answer as an agent reads it: every key the platform
    sent, ``model`` reduced to its id, version and title, and ``entities``:
    by collection, the records of the entities the write named (``entity_ids``,
    those it ``added``, the one an add restored instead). An answer with no
    model (a refusal, a rejection) is returned as sent."""
    if not isinstance(answer, dict) or not isinstance(answer.get("model"), dict):
        return answer
    model = answer["model"]
    named: dict = {_COLLECTIONS[kind]: [*entity_ids,
                                        answer.get(f"restored_{kind}_id") or ""]}
    for collection, ids in (answer.get("added") or {}).items():
        named.setdefault(collection, []).extend(ids or [])
    entities: dict = {}
    for collection, ids in named.items():
        by_id = {e.get("id"): e for e in model.get(collection) or [] if isinstance(e, dict)}
        found = [by_id[i] for i in dict.fromkeys(ids) if i and i in by_id]
        if found:
            entities[collection] = found
    return {**_without_models(answer), "entities": entities}


def _closure_change(answer: Any) -> Any:
    """An act on the attacker closure as an agent reads it: what the act did
    (``added``, ``attacker``, ``dismissed_set``, ``dismissed_zones_now``,
    ``split``, ``moved``, ``dismissed_split``), the model's
    ``credential_classes`` and how many of each list the closure now holds
    (``counts``); the lists themselves are read with
    ``get_behavioural_attackers``."""
    if not isinstance(answer, dict) or "proposals" not in answer:
        return answer
    lists = ("proposals", "dismissed", "dismissed_zones", "reported", "questions",
             "splits", "dismissed_splits")
    out = {k: v for k, v in answer.items() if k not in lists}
    out["counts"] = {k: len(answer.get(k) or []) for k in lists if k in answer}
    return out


#: The most characters a model read answers with before it cuts, each cut
#: stated: the bound the behavioural threats read keeps.
_MODEL_READ_MAX_CHARS = 200_000
_CLARIFICATIONS_PAGE_DEFAULT = 50
#: What a compacted collection keeps of each entity: what names it. The
#: entity is read whole with ``get_entity``.
_COMPACT_FIELDS = {
    "assets": ("id", "name", "security_properties", "deleted"),
    "attackers": ("id", "capability", "deleted"),
    "trust_boundaries": ("id", "description", "deleted"),
    "components": ("id", "name", "deleted"),
    "assumptions": ("id", "description", "status", "deleted"),
}


def _chars(obj: Any) -> int:
    return len(json.dumps(obj, default=str))


def _compact(entity: Any, keep: tuple) -> Any:
    if not isinstance(entity, dict):
        return entity
    return {k: entity[k] for k in keep
            if k in entity and (k != "deleted" or entity[k])}


def _bounded_model(read: dict) -> dict:
    """``read`` within ``_MODEL_READ_MAX_CHARS``, every cut stated under
    ``cuts`` with the read that serves what it left out: the objectives first
    (``get_control_objectives``), then each entity collection, largest first,
    compacted to the fields that name its entities (``get_entity`` reads one
    whole), and only then, if the read is still over the bound, the page of
    clarifications asked for (a smaller page here). The clarifications go last
    because no other read serves them as this one does. A read within the
    bound is returned as it is, with no ``cuts``."""
    if _chars(read) <= _MODEL_READ_MAX_CHARS:
        return read
    out = dict(read)
    cuts: list = []
    if "control_objectives" in out:
        cuts.append({"field": "control_objectives",
                     "omitted": len(out.pop("control_objectives") or []),
                     "read_with": "get_control_objectives (offset, limit)"})
    for name in sorted(_COMPACT_FIELDS, key=lambda n: -_chars(out.get(n) or [])):
        if _chars(out) <= _MODEL_READ_MAX_CHARS:
            break
        entities = out.get(name)
        if not isinstance(entities, list) or not entities:
            continue
        keep = _COMPACT_FIELDS[name]
        out[name] = [_compact(e, keep) for e in entities]
        cuts.append({"field": name, "compacted": len(entities), "kept": list(keep),
                     "read_with": "get_entity"})
    if _chars(out) > _MODEL_READ_MAX_CHARS and "clarifications" in out:
        out.pop("clarifications_next_offset", None)
        cuts.append({"field": "clarifications",
                     "omitted": len(out.pop("clarifications") or []),
                     "read_with": "get_threat_model (a smaller clarifications_limit)"})
    out["cuts"] = cuts
    return out


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


def _controls_build_fields(result: Any) -> dict:
    """What a generate/refine result says about the model's controls: the
    ``controls_status``, the proposed build (``proposal``) and its objective
    count (``controls_expected``), each only when the backend sent it."""
    out: dict = {}
    for key in ("controls_status", "proposal"):
        value = getattr(result, key, None)
        if value:
            out[key] = value
    expected = getattr(result, "controls_expected", None)
    if expected is not None:
        out["controls_expected"] = expected
    return out


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
    provenance_kind: str = "",
    provenance_repo_url: str = "",
    provenance_commit_sha: str = "",
    provenance_ref: str = "",
    provenance_source_ref: str = "",
    provenance_source_url: str = "",
    model_id: str = "",
) -> dict:
    """Generate a threat model from a feature description: trust
    boundaries, assets (Confidentiality, Integrity, Availability, Usage),
    capability-defined attackers, the control objective matrix and
    assumptions. A multi-step pipeline; progress is reported automatically.

    **Similar models:** where an existing model of the workspace overlaps
    the description, nothing is generated: ``{"similar_models": [{"id",
    "title", "reason"}], "suggestion"}``. Refine a candidate with
    ``refine_threat_model`` (usually right: it keeps controls and history),
    or retry with ``force=True`` once the operator confirms it is distinct.

    **Saved first:** where the platform models what the system does, the
    model is saved holding the description and generated from it later.
    ``extracting: true`` (``model_id``, ``job``): its behaviour is extracted
    in the background. ``needs_answers: true`` (``model_id``,
    ``questions``): RELAY THE QUESTIONS TO THE PERSON and answer them with
    ``answer_behavioural_questions``. Then poll ``get_behavioural_model``
    until ``generation_ready`` is true and call
    ``generate_from_behavioural_model`` with the ``model_id`` (``next`` says
    so). No control build is proposed until then. Deprecated: ``model_id``
    here; with an empty description it does the same, with one it is
    refused (``resume_takes_no_description``).

    Answer: ``{model_id, version, title, asset_count, attacker_count,
    control_objective_count, controls_status, ...}``. ``proposed``: a build
    is proposed (``proposal``: what it builds, ``estimated_credits``, the
    ``model_version``, ``set_revision`` and ``scope_revision`` a start
    names); review it with the user, then ``start_control_build`` with
    ``confirm_estimate=True``. ``none_owed``: nothing is owed;
    ``unavailable`` / ``error``: read ``get_control_generation_status``. A
    ``governor`` at ``warning`` or ``exhausted``: relay it; queued work
    resumes at ``resets_at``, never dropped.

    Args:
        feature_description: Description of the feature or system to
            threat model. Can be a few sentences or a detailed spec.
        force: Skip the similar-model detection and always create a
            new model. Default False: the check fires unless the
            operator or agent has explicit reason to bypass it.
        parent_id: Optional ID of an existing model to wire the new
            model under as a child on the recursive composition tree.
            The child then inherits the parent's topology and
            participates in composition (delta / inherited control
            credit). Default None: the model is created flat.
        provenance_kind: Where the description came from, one of
            ``code``, ``ticket``, ``document``, ``manual``, ``mixed``.
            Empty (default) records nothing. For an existing repository
            pass ``provenance_kind="code"`` with ``provenance_repo_url``
            and ``provenance_commit_sha`` (the HEAD you gathered from):
            the code is then authoritative and the model follows it.
            Any other kind means the description is intent and the code
            is measured against it. The same record can be set later
            with ``update_threat_model``.
        provenance_repo_url: Repository URL the description was
            gathered from (``code`` kind).
        provenance_commit_sha: Commit SHA the description was gathered
            at (``code`` kind).
        provenance_ref: Branch or tag name at that commit (optional).
        provenance_source_ref: Identifier of the ticket or document the
            description came from (``ticket`` / ``document`` kinds).
        provenance_source_url: URL of that ticket or document.
        model_id: Deprecated: use ``generate_from_behavioural_model``. With
            an empty ``feature_description`` it does the same; with a
            description it is refused (``resume_takes_no_description``).
    """
    if model_id.strip():
        if feature_description.strip():
            raise ToolError(
                "resume_takes_no_description (422): model_id names a model awaiting its "
                "first generation, which is generated from its own stored description "
                "and answers, so it takes no description. Call "
                "generate_from_behavioural_model(model_id), or omit model_id to generate "
                "a new model from this description.")
        return await _resume_generation(model_id.strip(), ctx)
    if not feature_description.strip():
        raise ToolError("feature_description is required: describe the feature or system.")
    progress = _StreamProgress(ctx)
    try:
        provenance = None
        if provenance_kind.strip():
            provenance = {
                "kind": provenance_kind.strip(),
                "repo_url": provenance_repo_url,
                "commit_sha": provenance_commit_sha,
                "ref": provenance_ref,
                "source_ref": provenance_source_ref,
                "source_url": provenance_source_url,
            }
        result = await _get_client().generate_threat_model(
            feature_description,
            force_generate=force,
            parent_id=parent_id,
            on_progress=progress,
            provenance=provenance,
        )
        await progress.complete()
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
        return _generation_answer(result)
    except Exception as exc:
        raise _api_error(exc) from exc


class _StreamProgress:
    """A generation stream's progress, forwarded to the client.

    Tracks the last ``(progress, total)`` seen so the final "Complete"
    notification emits ``(total, total)`` and keeps the MCP invariants:
    progress monotonically non-decreasing and ``total`` constant across one
    progressToken sequence. Clients may drop a sequence that violates
    either."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._last_total = 0.0

    async def __call__(self, progress, total, message) -> None:
        self._last_total = total
        await _safe_report_progress(self._ctx, progress, total, message)

    async def complete(self) -> None:
        # Without a step event in the stream, any (progress, total) here
        # would break the sequence's invariants, so nothing is sent.
        if self._last_total > 0:
            await _safe_report_progress(
                self._ctx, self._last_total, self._last_total, "Complete")


def _next_for_saved_model(model_id: str, *, extracting: bool) -> str:
    """What an agent does next with a model saved before its inventory."""
    first = (f"Poll get_behavioural_model(model_id={model_id!r}, view='status', "
             "wait_seconds=50) until extraction.job is null, then answer any questions "
             "it lists with answer_behavioural_questions"
             if extracting else
             "Relay the questions to the person and answer them with "
             f"answer_behavioural_questions; then poll get_behavioural_model(model_id="
             f"{model_id!r}, view='status', wait_seconds=50)")
    return (f"{first}. Once generation_ready is true, call "
            f"generate_from_behavioural_model(model_id={model_id!r}).")


def _generation_answer(result: Any) -> dict:
    """What a generation's stream answered, as the tools return it: a model
    saved before its inventory (``extracting`` or ``needs_answers``), prose
    with nothing written, or the generated model."""
    if isinstance(result, ChatResponse):
        extracting = getattr(result, "extracting", None)
        if isinstance(extracting, dict):
            # Saved first: the model holds the description and its
            # behaviour is being extracted in the background.
            model_id = extracting.get("model_id", "")
            return {
                "generated": False,
                "extracting": True,
                "model_id": model_id,
                "version": extracting.get("version"),
                "title": extracting.get("title", ""),
                "job": extracting.get("job"),
                "estimate": extracting.get("estimate"),
                "message": result.content,
                "next": _next_for_saved_model(model_id, extracting=True),
            }
        stopped = getattr(result, "needs_answers", None)
        if isinstance(stopped, dict):
            # The generation stopped on owner questions: the model is
            # saved holding the description, with no inventory yet.
            model_id = stopped.get("model_id", "")
            return {
                "generated": False,
                "needs_answers": True,
                "model_id": model_id,
                "version": stopped.get("version"),
                "questions": list(stopped.get("questions") or []),
                "message": result.content,
                "next": _next_for_saved_model(model_id, extracting=False),
            }
        # Only a backend that does not take the named intent answers a
        # generation in prose; nothing was written.
        return {"generated": False, "message": result.content}
    tm = result.threat_model
    # `model_id` is the persisted model id; `threat_model.id` is the
    # generated in-memory id, which can be present even when the model was
    # not saved: returning it yields an id that 404s on the next fetch.
    # Prefer `model_id`, and if it is absent treat the generation as not
    # persisted rather than reporting an unusable id.
    model_id = getattr(result, "model_id", "") or ""
    if not model_id:
        raise RuntimeError(
            "Threat model was generated but not saved (no model id "
            "returned). This is usually a transient storage error; please "
            "retry the generation."
        )
    gov = getattr(result, "governor", None)
    return {
        "model_id": model_id,
        "version": tm.version,
        "title": tm.title,
        "asset_count": len(tm.assets),
        "attacker_count": len(tm.attackers),
        "control_objective_count": len(tm.control_objectives),
        **({"governor": gov} if gov else {}),
        **_controls_build_fields(result),
    }


async def _resume_generation(model_id: str, ctx: Context) -> dict:
    """Generate ``model_id``, a model awaiting its first generation, from its
    behavioural model, reporting the stream's progress. A refusal comes back
    as data."""
    progress = _StreamProgress(ctx)
    try:
        result = await _get_client().generate_from_behavioural_model(
            model_id, on_progress=progress)
        await progress.complete()
        if isinstance(result, dict):
            return result
        return _generation_answer(result)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def generate_from_behavioural_model(
    server_version: str,
    model_id: str,
    ctx: Context,
) -> dict:
    """Generate the threat model of a model awaiting its first generation,
    from its behavioural model. Mutating; saves the model's next version.

    A generation where the platform models what the system does saves the
    model first (``generate_threat_model`` answers ``extracting`` or
    ``needs_answers``). Once ``get_behavioural_model`` reports
    ``generation_ready: true``, call this with its ``model_id``: the
    inventory steps run from the stored description and the answers to its
    questions. It takes no description. Progress is reported automatically;
    it takes minutes.

    Answer: as ``generate_threat_model``'s, ``controls_status`` and the
    proposed control build included; ``needs_answers`` with the
    ``questions`` when it stopped on questions.

    Refusals come back as data, ``{generated: false, http_status: 409, code,
    message}``: ``not_awaiting_generation`` (the model has been generated,
    or its behavioural model still asks questions or is being extracted:
    read ``get_behavioural_model``, and refine a generated model with
    ``refine_threat_model``), ``generation_in_progress`` (another generation
    of the model is running: do not start another; poll
    ``get_behavioural_model``, whose ``generation_ready`` turns false and
    whose version moves when it saves). A model that is not there is a 404
    error.

    Args:
        model_id: The model, as ``generate_threat_model`` returned it.
    """
    if not model_id.strip():
        raise ToolError("model_id is required.")
    return await _resume_generation(model_id.strip(), ctx)


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

    ``controls_status`` / ``proposal`` / ``controls_expected`` say what the
    refined model owes in controls, as for ``generate_threat_model``: a
    proposed build that runs only when ``start_control_build`` starts it.

    When the instruction cannot be applied — a targeted change naming an
    entity the model does not have — nothing is written and the answer is
    ``{model_id, changed: false, message}``, the message saying why.
    ``semantic_rejections`` is sent by a broad rewrite only; a targeted
    change runs no such guard and reports it empty.
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
        if isinstance(result, ChatResponse):
            # The refine could not apply (a targeted change naming an entity
            # the model does not have) and said why; nothing was written.
            return {"model_id": model_id, "changed": False,
                    "message": result.content}
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
            **_controls_build_fields(result),
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
        if not isinstance(result, ChatResponse):
            # Only a backend that does not take the named intent can treat
            # a question as a change; say what happened rather than report
            # an empty answer.
            return {"model_id": model_id, "answer": None, "changed": True,
                    "version": result.version,
                    "message": "The platform handled the question as a change "
                               "to the model and wrote a new version."}
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


_PROVENANCE_KINDS = ("code", "ticket", "document", "manual", "mixed")


@mcp.tool()
async def update_threat_model(
    server_version: str,
    model_id: str,
    name: Optional[str] = None,
    parent_id: Optional[str] = None,
    clear_parent: bool = False,
    provenance_kind: str = "",
    provenance_repo_url: str = "",
    provenance_commit_sha: str = "",
    provenance_ref: str = "",
    provenance_source_ref: str = "",
    provenance_source_url: str = "",
) -> dict:
    """Change a threat model's metadata: its name, its parent, where its
    description came from. Mutating; pass only what changes.

    - ``name`` (1-120 chars) renames it; no new version. Titles are unique
      within a workspace, case-insensitive (409 on a clash).
    - ``parent_id`` wires it under a parent on the recursive composition
      tree, so it inherits the parent's topology and objectives;
      ``clear_parent=True`` makes it a tree root. Cycles (409) and chains
      past the platform's maximum depth (400) are refused. No new version.
    - ``provenance_kind`` (``code``, ``ticket``, ``document``, ``manual``,
      ``mixed``) records where the description came from, with the other
      ``provenance_*`` values. ``code`` with ``provenance_commit_sha`` means
      the code is authoritative and the model follows it
      (``reconcile_model`` measures it against the code); any other kind
      means the description is intent and the code is measured against it.
      Bumps the model version.

    Changes apply in that order. Returns ``{model_id, name?, parent?,
    provenance?}``, one entry per change applied. A failure raises and
    names the changes already applied.
    """
    if parent_id and clear_parent:
        raise ToolError("Pass parent_id or clear_parent, not both.")
    kind = provenance_kind.strip()
    if kind and kind not in _PROVENANCE_KINDS:
        raise ToolError(f"provenance_kind must be one of {', '.join(_PROVENANCE_KINDS)}.")
    if name is None and not parent_id and not clear_parent and not kind:
        raise ToolError("Nothing to change: pass name, parent_id, clear_parent or provenance_kind.")
    client = _get_client()
    out: dict = {"model_id": model_id}
    try:
        if name is not None:
            out["name"] = (await client.rename_model(model_id, name)).model_dump()
        if parent_id or clear_parent:
            out["parent"] = _dump(await client.set_parent(
                model_id, None if clear_parent else parent_id))
        if kind:
            out["provenance"] = await client.set_model_provenance(
                model_id, kind,
                repo_url=provenance_repo_url, commit_sha=provenance_commit_sha,
                ref=provenance_ref, source_ref=provenance_source_ref,
                source_url=provenance_source_url,
            )
    except Exception as exc:
        applied = [k for k in ("name", "parent", "provenance") if k in out]
        err = _api_error(exc)
        if applied:
            raise ToolError(f"{err} (already applied: {', '.join(applied)})") from exc
        raise err from exc
    return out


@mcp.tool()
async def declare_foundation(
    server_version: str,
    model_id: str,
    provides: list[dict],
    visibility: str = "workspace",
) -> dict:
    """Mark a model as a shared foundation that advertises providable controls.

    Mutating: records this model as a foundation and stores its advertised controls; other models can then delegate to them (see ``attach_foundation``). A foundation is a shared service (auth, logging, a shared datastore) whose controls other models can rely on.

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

    Use this to inspect existing dependencies before creating or deleting edges (``manage_reliance`` / ``attach_foundation``), or to understand what breaks if this model's controls change.

    Args:
        model_id: ID of the model to inspect.
    """
    try:
        return await _get_client().list_reliance(model_id)
    except Exception as exc:
        raise _api_error(exc) from exc


_RELIANCE_ACTIONS = ("create", "confirm", "delete")


@mcp.tool()
async def manage_reliance(
    server_version: str,
    action: Literal["create", "confirm", "delete"],
    model_id: str = "",
    provider_model_id: str = "",
    provider_control_id: str = "",
    mode: str = "",
    source_objective_id: str = "",
    source_control_id: str = "",
    edge_id: str = "",
    accept_partial_as_relied_upon: bool = False,
) -> dict:
    """Create, confirm or delete one cross-model reliance edge. Mutating.

    ``action="create"`` declares that ``model_id`` relies on a provider
    control (the target is ALWAYS a control, so credit ends at a proven
    mechanism). ``mode`` is ``delegated`` (this model does not implement the
    objective; pass ``source_objective_id``) or ``relied_upon`` (this model's
    own control depends on the provider's; pass ``source_control_id``). The
    provider must be in the same workspace. The edge enters ``draft``, runs
    LLM semantic validation, and carries no credit until confirmed. Returns
    the edge.

    ``action="confirm"`` promotes the draft ``edge_id`` to active, the
    credit-soundness gate: refused unless validation returned ``valid``; a
    ``partial`` result or a mode mismatch is never silently credited.
    Returns the edge.

    ``action="delete"`` permanently removes ``edge_id``, withdrawing any
    credit the consumer derived from it (its coverage can move); neither
    model's controls change. Returns ``{deleted: true, edge_id}``.

    ``list_reliance`` shows a model's edges and their ids.
    """
    if action not in _RELIANCE_ACTIONS:
        raise ToolError(f"action must be one of {', '.join(_RELIANCE_ACTIONS)}.")
    if action == "create":
        missing = [n for n, v in (("model_id", model_id),
                                  ("provider_model_id", provider_model_id),
                                  ("provider_control_id", provider_control_id),
                                  ("mode", mode)) if not v.strip()]
        if missing:
            raise ToolError(f"action='create' requires {', '.join(missing)}.")
    elif not edge_id.strip():
        raise ToolError(f"action='{action}' requires edge_id.")
    try:
        client = _get_client()
        if action == "create":
            return await client.create_reliance(
                model_id, provider_model_id, provider_control_id, mode,
                source_objective_id, source_control_id,
            )
        if action == "confirm":
            return await client.confirm_reliance(edge_id, accept_partial_as_relied_upon)
        await client.delete_reliance(edge_id)
        return {"deleted": True, "edge_id": edge_id}
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def attach_foundation(
    server_version: str,
    model_id: str,
    foundation_model_id: str,
    selections: Optional[list[dict]] = None,
) -> dict:
    """Delegate this model's objectives to a foundation's controls, in bulk.

    Without ``selections`` it is read-only: it returns candidate
    (objective ↔ provider control) pairs with a match score, and nothing is
    created or credited. Show them to the operator.

    With ``selections`` — a list of ``{"source_objective_id": ...,
    "provider_control_id": ...}``, typically the confirmed subset of those
    candidates — it is mutating: each becomes a ``delegated`` draft edge that
    runs LLM validation and carries no credit until confirmed with
    ``manage_reliance(action="confirm")``. Returns ``{created, failed}``.

    Args:
        model_id: the consumer model.
        foundation_model_id: the foundation to delegate to.
        selections: the pairs to delegate; omit to get the candidates.
    """
    try:
        client = _get_client()
        if selections is None:
            return await client.propose_attach_foundation(model_id, foundation_model_id)
        return await client.attach_foundation(
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
    include_inventory_completeness: bool = False,
    include_clarifications: bool = False,
    clarifications_offset: int = 0,
    clarifications_limit: int = _CLARIFICATIONS_PAGE_DEFAULT,
) -> dict:
    """Get a threat model by ID: its trust boundaries, assets, attackers,
    assumptions and components. Read-only.

    The answers to its questions are counted (``clarification_count``) and
    left out unless ``include_clarifications=True``, which pages them
    (``clarifications_offset``, ``clarifications_limit``: default 50, at most
    200; ``clarifications_next_offset`` null at the end). A read over 200,000
    characters is cut, and ``cuts`` says what and how to read it: the
    objectives, then the clarifications, then each entity collection,
    largest first, kept as rows that name its entities.

    ``include_inventory_completeness=True`` (latest version only) adds
    ``inventory_completeness``: how much of the inventory the claims rest on,
    with ``bounded_by`` (the entities holding the tier down) and
    ``grounding_gaps``, keyed by entity id. Each gap names a ``ground`` the
    entity lacks (``position``, ``privileges``, ``extent``, ``components``,
    ``flagged``, ``inherited``), a ``detail``, and ``acts``: each act's
    ``mcp_tool`` and ``mcp_arguments`` (that tool's arguments, the entity
    named and lists comma-separated; ``fields`` is the REST body), a value
    in angle brackets being yours to fill. Taking every listed act grounds the entity; a gap with no
    act says no act can supply it on this deployment. An attestation an act
    names is a judgment (see ``edit_attacker``). ``null`` when the record
    could not be read.

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
        include_cos: Include control objectives inline (default False:
            the answer carries no ``control_objectives`` key; read them
            with ``get_control_objectives``).
        include_inventory_completeness: Add the completeness record and
            its ``grounding_gaps`` (default False).
        include_clarifications: Include a page of the answers to the
            model's questions (default False).
        clarifications_offset: The first answer of the page.
        clarifications_limit: Answers per page.
    """
    if include_inventory_completeness and version is not None:
        raise ToolError(
            "include_inventory_completeness reads the latest version; omit version.")
    if clarifications_offset < 0 or not 1 <= clarifications_limit <= _PAGE_MAX:
        raise ToolError(f"clarifications_offset must be 0 or more and "
                        f"clarifications_limit between 1 and {_PAGE_MAX}.")
    try:
        if include_inventory_completeness:
            model = await _get_client().get_model(
                model_id, version, include="inventory_completeness")
        else:
            model = await _get_client().get_model(model_id, version)
    except Exception as exc:
        raise _api_error(exc) from exc
    out = model.model_dump() if include_cos else model.model_dump(
        exclude={"control_objectives"})
    clarifications = out.pop("clarifications", None) or []
    out["clarification_count"] = len(clarifications)
    if include_clarifications:
        end = clarifications_offset + clarifications_limit
        out["clarifications"] = clarifications[clarifications_offset:end]
        out["clarifications_next_offset"] = end if end < len(clarifications) else None
    return _bounded_model(out)


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

    The archive carries the model's current state, and the import creates it
    as version 1 of a new model: its controls, live assertions, decisions in
    force and open findings. Earlier versions, activity and chat are not
    carried.

    The restored model arrives UNVERIFIED. The tier verdicts on its
    assertions, the attested flag on a verification result, and the facts a
    verification run reported are the origin's record of what it claimed —
    kept with the model as that record, and not credited here: a verdict
    belongs to the run that produced it and the judge that decided it, and
    this workspace has neither. Verification is earned here by running it
    against code this workspace can reach, so plan for a restored model to
    read unverified until it has. The same holds for the judgements of its
    mitigation groups: the import queues none, and its objectives read
    awaiting judgement until someone asks for them.

    Args:
        envelope: The full archive dict returned by
            ``export_report (scope="model", format="archive")``.
        workspace_id: Target workspace to import into.

    Returns:
        ``{"model_id": "<new id>", "judgement": {...}}``. ``judgement`` is
        what judging the imported model would cost (the answer
        ``judge_objectives`` gives without ``confirm_estimate``: ``scope``,
        ``estimate``, ``ungrouped``), with ``available: false`` when no
        estimate could be made. Show it to the user; call
        ``judge_objectives(model_id, confirm_estimate=True)`` to queue the
        judgements once they agree.
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
    """A model's proposed control build and its last started one. Read-only.

    A build runs only when started. ``proposal`` (or null): ``mode``,
    ``objective_count``, ``estimated_credits`` (``estimate_basis``
    history|bootstrap), the ``model_version`` / ``set_revision`` /
    ``scope_revision`` ``start_control_build`` names, and what to review:
    ``flagged_entities``, ``pending_attestations`` (attestations that would
    remove objectives from the build); ``flags_evaluated`` /
    ``attestations_evaluated`` false when not computed. Poll until
    ``terminal``; ``hint`` names the next act.

    ``status``: ``queued | generating | deferred | pausing | paused |
    blocked | complete | failed | skipped | discarded | none``. ``deferred``
    waits for the budget reset; ``paused`` keeps its work until
    ``resume_control_generation`` or ``discard_control_build``. ``blocked``
    has ``code`` (``dependency_unavailable`` or ``analysis_incomplete``),
    ``message``, ``retry_after_seconds``: relay it and retry with
    ``resume_control_generation``, never ``regenerate_controls`` (re-bills).

    Running: ``ready_cos`` / ``target_cos`` are progress, not coverage.
    ``selfheal_activity`` is a SAMPLE of a strengthening round: read
    ``refining_total`` / ``authoring_total`` / ``set_aside_total``;
    ``set_aside`` waits for a person, NOT a failure.

    ``complete``: figures come from ``diagnosis``: ``covered``,
    ``uncovered``, ``undecided`` (``strengthen_controls``), ``judging``
    (wait), ``not_judged`` (``judge_objectives``), ``no_group`` (group),
    ``grouping``, ``no_control`` (start the build), ``awaiting_attestation``
    (attest), ``awaiting_assumption`` (review queue), ``mitigated_elsewhere``
    (nothing owed). ``covered_cos`` of ``judged_cos``;
    ``awaiting_judgement_cos`` = ``not_judged`` + ``judging``;
    ``excluded_cos``, ``dispositioned_cos`` the rest. ``analysis_pending``:
    figures may still move.
    """
    try:
        return _dump(
            await _get_client().get_control_generation_status(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def pause_control_generation(
    server_version: str,
    model_id: str,
    ctx: Context,
) -> dict:
    """Pause a model's background control generation. Mutating.

    Use when the user asks to stop a build — for example one started by
    mistake — or before deleting a model whose controls are still being
    built. A running build stops at its next step (``status`` ``pausing``,
    then ``paused``); a queued or waiting one is paused at once. Everything
    already done is kept in the build's staging copy; nothing is published,
    nothing new is started or billed, and nothing resumes it except
    ``resume_control_generation``. A paused build still holds the model: to
    drop it instead, call ``discard_control_build`` once it shows ``paused``.
    Pausing is idempotent.

    Returns one of:
    - ``{paused: true, model_id, status, status_detail}`` — ``status`` is
      ``pausing`` (still stopping) or ``paused``.
    - ``{paused: false, http_status: 409, code: "not_running", status}`` —
      there is no generation to pause; read ``status``.

    Args:
        model_id: ID of the threat model whose control generation to pause.
    """
    try:
        return _dump(
            await _get_client().pause_control_generation(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def resume_control_generation(
    server_version: str,
    model_id: str,
    ctx: Context,
) -> dict:
    """Resume control generation that was paused, or retry one that stopped
    before finishing. Mutating.

    Use when ``get_control_generation_status`` returns ``status: "paused"``
    (someone paused it) or ``status: "blocked"`` (``blocked.code``
    ``dependency_unavailable`` or ``analysis_incomplete``). A paused run
    resumes at once. For a blocked one the platform checks the services it
    depends on first, so a retry while one is still down costs nothing and
    changes nothing.

    Returns one of:
    - ``{resumed: true, status: "queued", status_detail}`` — the run resumes
      where it stopped (only the unfinished work, billed to the original
      generation). Poll ``get_control_generation_status`` until ``complete``.
    - ``{resumed: false, http_status: 409, code: "pause_in_progress"}`` — the
      run is still stopping after a pause; resume once it shows ``paused``.
    - ``{resumed: false, http_status: 503, code: "dependency_unavailable",
      message, retry_after_seconds, ...}`` — still unavailable; relay the
      message and try again after ``retry_after_seconds``.
    - ``{resumed: false, http_status: 409, code: "retry_too_soon",
      retry_after_seconds, ...}`` — a retry was just tried; wait.
    - ``{resumed: false, http_status: 409, code: "not_blocked", status}`` —
      nothing is paused; read ``status``.

    Args:
        model_id: ID of the threat model whose paused control generation to
            resume.
    """
    try:
        return _dump(
            await _get_client().resume_control_generation(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def strengthen_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    co_ids: Optional[str] = None,
    confirm_estimate: bool = False,
    model_version: Optional[int] = None,
    set_revision: Optional[int] = None,
) -> dict:
    """Strengthen a model's controls: work on the objectives whose mitigation
    groups the background judge found do not cover them (the ``uncovered``
    and ``undecided`` of ``get_control_generation_status``'s ``diagnosis``).
    Mutating only with ``confirm_estimate=True``; consumes credits then.
    ``not_judged`` objectives have nothing to strengthen from: judge them
    first with ``judge_objectives``.

    1. Call with ``confirm_estimate=False`` (the default): nothing starts or
       is charged; the answer carries ``diagnosis``, ``scope``, ``estimate``
       (``credits``, ``per_objective``, ``basis``) and the
       ``model_version`` / ``set_revision`` the model stands at. Show the
       user the estimate.
    2. Once they agree, call with ``confirm_estimate=True`` and those two
       values (their review of the model as it stood). A background run
       starts (``started: true``); poll ``get_control_generation_status``.
       It holds the model like any build: pausable, resumable, discardable.

    A gap only the environment can close (hosting, a third party) is never
    answered with a control: an accepted assumption stating it is bound
    into the group; otherwise an assumption proposal waits in the
    review queue (``get_review_queue`` / ``decide_proposal``) and the objective
    counts as ``awaiting_assumption``. A rejected one is not proposed again.

    Refusals come back as data, ``{started: false, http_status, code}``:
    409 ``review_stale`` (the model or its controls changed since the
    estimate: confirm again with the values returned), 409
    ``generation_active`` (a build holds the model), 402 (the balance cannot
    cover the estimate).

    Args:
        model_id: ID of the threat model.
        co_ids: Optional comma-separated objective IDs, of those diagnosed
            uncovered or undecided; omit for all.
        confirm_estimate: False (default) estimates; True starts the run.
        model_version: With ``confirm_estimate=True``: the estimate's value.
        set_revision: With ``confirm_estimate=True``: the estimate's value.
    """
    parsed: list[str] | None = None
    if co_ids:
        parsed = [c.strip() for c in co_ids.split(",") if c.strip()]
    try:
        return _dump(await _get_client().strengthen_controls(
            model_id, co_ids=parsed, confirm_estimate=confirm_estimate,
            model_version=model_version, set_revision=set_revision))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def judge_objectives(
    server_version: str,
    model_id: str,
    ctx: Context,
    co_ids: Optional[str] = None,
    confirm_estimate: bool = False,
) -> dict:
    """Have judged every objective whose mitigation group has no judgement for
    its current controls and none queued (the diagnosis's ``not_judged``, or
    objectives reading ``awaiting_judgement``). Mutating only with
    ``confirm_estimate=True``; may consume credits then. Adding or
    implementing controls does not move such an objective; a judgement
    does. ``judging`` objectives are already queued: wait for them.

    1. Call with ``confirm_estimate=False`` (the default): nothing is queued
       or charged; the answer carries ``diagnosis``, ``scope``, ``ungrouped``
       and ``estimate`` (``credits``, ``objectives``, ``computed_at``,
       ``rate_version``). Show the user the estimate.
    2. Once they agree, call with ``confirm_estimate=True``: each objective
       in ``scope`` is queued (``confirmed: true``, ``queued``), metered at
       actuals as it runs, and ``status_detail`` is the fresh status.

    ``ungrouped`` objectives have no mitigation group and are never judged:
    group their controls with ``set_mitigation_groups`` first.

    A judgement is not a repair: it can come back insufficient or undecided,
    which counts the objective as ``uncovered`` or ``undecided``, work for
    ``strengthen_controls``. ``judge_objective`` does the same for one.

    Refusals come back as data, ``{confirmed: false, queued: 0,
    http_status, code, message}``: 409 ``control_generation_in_progress``
    (poll ``get_control_generation_status``), 402 ``insufficient_credits`` /
    ``quota_exceeded`` (with ``estimated_credits``), 503 (judging
    unavailable). An unknown id in ``co_ids`` is a 400 error.

    Args:
        model_id: ID of the threat model.
        co_ids: Optional comma-separated objective IDs; omit for every
            objective with no judgement and none queued.
        confirm_estimate: False (default) estimates; True queues.
    """
    parsed: list[str] | None = None
    if co_ids:
        parsed = [c.strip() for c in co_ids.split(",") if c.strip()]
    try:
        return _dump(await _get_client().judge_objectives(
            model_id, co_ids=parsed, confirm_estimate=confirm_estimate))
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
    """Propose a regeneration of the model's controls. Starts nothing.

    A regeneration re-authors controls from the current COs; its publish
    creates the next model version. Controls whose descriptions survive
    unchanged KEEP their implementation status, evidence, notes, assertions,
    and Jira / compliance mappings. Controls whose descriptions change or
    disappear are soft-deleted (still queryable via
    ``get_controls(include_deleted=True)``). When ``co_ids`` is given, only
    those COs' controls are regenerated — all other controls are left as-is.

    This tool records the regeneration as the model's PROPOSED build and
    returns at once with ``status: "proposed"`` and ``proposal`` (``mode``,
    ``objective_ids``, ``objective_count``, ``estimated_credits``, and the
    ``model_version``, ``set_revision`` and ``scope_revision`` a start must
    name). A proposal
    merges with any already proposed for the model, the broader one winning.
    Show the user what it would build and cost; once they agree, call
    ``start_control_build`` with those values and ``confirm_estimate=True``.
    A build someone started holds the model, so this is refused (409
    ``generation_active``) until it finishes, or is resumed and finishes, or
    is discarded.

    To rebuild everything, omit ``co_ids``. To fix only stale/orphaned CO
    mappings without re-authoring control text, prefer ``remap_control``
    (mechanical, no LLM).

    Args:
        model_id: ID of the threat model.
        mode: "batch" (default) or "per_co" (most thorough — one LLM call
            per CO).
        batch_size: COs per batch in batch mode (default 15). Smaller =
            more accurate and more granular progress, but more LLM calls.
        co_ids: Optional comma-separated CO IDs to regenerate (e.g.
            "CO1,CO5"). Omit to regenerate all controls.
    """
    # Workaround for Claude Code MCP array serialization bug
    # (anthropics/claude-code#18260) — accept comma-separated string
    parsed_co_ids: list[str] | None = None
    if co_ids:
        parsed_co_ids = [c.strip() for c in co_ids.split(",") if c.strip()]
    try:
        return _dump(await _get_client().regenerate_controls(
            model_id, mode=mode, batch_size=batch_size, co_ids=parsed_co_ids,
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def start_control_build(
    server_version: str,
    model_id: str,
    ctx: Context,
    model_version: Optional[int] = None,
    set_revision: Optional[int] = None,
    confirm_estimate: bool = False,
    scope_revision: Optional[str] = None,
) -> dict:
    """Start the model's proposed control build. Mutating only with
    ``confirm_estimate=True``; consumes credits then.

    A model's controls are built only by a build someone starts. Generating
    or refining the model, editing an entity and ``regenerate_controls``
    each PROPOSE one; ``get_control_generation_status`` shows it as
    ``proposal``.

    1. Call with ``confirm_estimate=False`` (the default). Nothing starts and
       nothing is charged; the answer is ``{started: false, proposal,
       message}``, the proposal carrying a fresh ``estimated_credits`` and
       the ``model_version``, ``set_revision`` and ``scope_revision`` the
       model stands at. Show the user what it would build and cost, and
       what it lists to review.
    2. Call again with ``confirm_estimate=True`` and those three values once
       they have reviewed the model. The build starts (``{started: true,
       job_id, model_version, status: "queued", status_detail}``) and holds
       the model until it publishes, fails or is discarded: other writers of
       the model's controls are refused meanwhile, and reads show the last
       published controls. Poll ``get_control_generation_status`` until
       ``terminal``; the publish is one step, after which ``get_controls``
       shows the result.

    Refusals come back as data:
    - ``{started: false, http_status: 404, code: "no_proposal"}`` — nothing
      is proposed for the model.
    - ``{started: false, http_status: 409, code: "review_stale", proposal,
      model_version, set_revision, scope_revision, estimated_credits}`` —
      the model, its controls or the objectives the build would author
      changed since the values were read (or none were named). Review again
      and start with the values returned.
    - ``{started: false, http_status: 409, code: "generation_active",
      status}`` — a build already holds the model.
    - ``{started: false, http_status: 402, ...}`` — the balance this
      workspace bills to cannot cover the estimate.

    Args:
        model_id: ID of the threat model.
        model_version: With ``confirm_estimate=True``: the proposal's
            ``model_version``.
        set_revision: With ``confirm_estimate=True``: the proposal's
            ``set_revision``.
        confirm_estimate: False (default) returns the proposal and its
            estimate and starts nothing; True starts the build.
        scope_revision: With ``confirm_estimate=True``: the proposal's
            ``scope_revision``.
    """
    pin = {"scope_revision": scope_revision} if scope_revision is not None else {}
    try:
        return _dump(await _get_client().start_control_build(
            model_id, model_version=model_version, set_revision=set_revision,
            confirm_estimate=confirm_estimate, **pin))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def discard_control_build(
    server_version: str,
    model_id: str,
    ctx: Context,
) -> dict:
    """Discard a model's held control build. Mutating.

    A build that is ``queued``, ``deferred``, ``paused`` or ``blocked`` holds
    the model without running. Discarding it drops everything it staged — the
    model keeps its published controls exactly as they were — releases the
    model, and proposes the build again so it can be started later. The
    credits it already consumed are not returned. A running build must be
    paused first (``pause_control_generation``, then wait for ``paused``).

    Returns one of:
    - ``{discarded: true, model_id, status: "discarded", proposal,
      status_detail}``.
    - ``{discarded: false, http_status: 409, code: "pause_first", status}`` —
      the build is running; pause it first.
    - ``{discarded: false, http_status: 409, code: "not_held", status}`` —
      no build holds the model.

    Args:
        model_id: ID of the threat model whose held build to discard.
    """
    try:
        return _dump(await _get_client().discard_control_build(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_control_revisions(
    server_version: str,
    model_id: str,
    version: int = 0,
) -> dict:
    """List every change to a model version's set of controls. Read-only.

    Each write to a version's published controls — a build's publish, an
    import, an edit, a deletion, an undo — is a set revision with its author.
    Returns ``{model_id, model_version, latest_version, discarded, revisions,
    undo_target}``; each revision carries ``revision``, ``job_id`` (the
    build that wrote it, if any), ``started_by``, ``started_at``,
    ``controls`` (the ids it touched), ``undo_of`` (the revision it undid,
    for an undo) and ``undone_by`` / ``undone_at``. ``undo_target`` is the
    revision ``undo_model_change(target="controls")`` would undo (null when none, and for any
    version but the latest). ``discarded`` is true for a version a revert
    replaced.

    Args:
        model_id: ID of the threat model.
        version: Model version to read (0 = the latest live version).
    """
    try:
        return _dump(await _get_client().list_control_revisions(
            model_id, version=version))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def undo_model_change(
    server_version: str,
    model_id: str,
    target: Literal["controls", "version"],
    ctx: Context,
) -> dict:
    """Undo the latest change to a model's controls, or revert its latest
    version. Mutating.

    ``target="controls"`` restores exactly what the latest set revision of
    the latest version replaced (``list_control_revisions``'
    ``undo_target``). Changes are undone latest first, one per call; the
    undo is itself recorded, and the next undo goes to the change before
    it. There is no redo. Verdicts the undo returns to are served again
    rather than re-judged. Answers ``{applied: true, model_id,
    model_version, undone, revision, controls}``: ``undone`` is the revision
    undone, ``revision`` the one the undo recorded, ``controls`` the ids it
    restored.

    ``target="version"`` creates a new version copying the latest earlier
    version not already discarded — the model, its controls and their
    objective metadata — and marks the replaced version discarded. Version
    numbers are never reused, and the discarded version stays readable in
    the history. Findings on controls the revert removes are resolved.
    Answers ``{applied: true, model_id, model_version, copied_from,
    discarded}``: ``model_version`` is the new version.

    A refusal comes back as ``{applied: false, http_status: 409, code,
    message}``: ``generation_active`` (a build holds the model), and for
    controls ``nothing_to_undo`` or ``set_diverged`` (a control the change
    touched has changed since; undo the later change first), for a version
    ``no_earlier_version``.
    """
    if target not in ("controls", "version"):
        raise ToolError('target must be "controls" or "version".')
    try:
        client = _get_client()
        if target == "controls":
            return _dump(await client.undo_control_change(model_id))
        return _dump(await client.revert_model_version(model_id))
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

    **After an accepted refinement** the control's assertions are kept
    and judged again against the new description in the background: an
    assertion that still fits keeps counting as evidence, and one that no
    longer fits is flagged as not aligned with the control. Read
    ``get_sufficiency`` once that re-judgement lands, and replace the
    assertions it names. The refinement itself supersedes nothing; the
    response's ``superseded_assertions`` is always 0.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control to refine (e.g., "CTRL-03").
        description: Proposed new control description (optional if
            codebase_findings provided).
        justification: Why this refinement is appropriate (10 to 2000
            characters).
        codebase_findings: Description of existing code that may already
            satisfy this control's objective (optional). When provided
            without description, the platform proposes a description.
    """
    if not description.strip() and not codebase_findings.strip():
        raise ToolError("Either description or codebase_findings is required.")
    _check_justification_length(justification)
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
    """How coherent a model's structure is: its component bindings, the
    repos its controls' assertions name, and whether every CO is
    structurally reachable. Read-only.

    Pass ``co_id`` to keep only the findings about that CO (404 if it does
    not exist). Each finding carries ``type``, ``severity``, a ``message``
    and the ids it concerns, so its fix can be called directly:

    - ``control_component_unknown``, ``assertion_repo_orphan``,
      ``control_unscoped_with_scoped_assertions``:
      ``assign_to_components(target_type="control")``.
      ``assertion_repo_mismatch``: rebind the assertion or rescope the
      control.
    - ``asset_component_unknown``: ``edit_asset`` with corrected
      ``component_ids``.
    - ``component_unbound``: for your own code, ``edit_component`` with the
      real ``repo_url``. An external-zone component (a third-party service,
      a customer's IdP) stays unbound: the finding is a permanent marker of
      an external dependency, not a TODO, and client code touching it is no
      reason to bind it.
    - ``co_attacker_unpositioned``: ``edit_attacker`` with
      ``trust_boundary_ids``. ``co_asset_unbounded``:
      ``assign_to_components(target_type="asset")``.
      ``co_no_shared_boundary``: reposition the attacker or rescope the
      asset; if the boundaries truly do not meet, that is the answer.
      ``co_missing_entity``: ``restore_entity``, or remove the CO.

    An indeterminate reachability verdict means the structure it needs is
    missing: supply it. It never means the objective is inapplicable, which
    is a separate claim recorded with ``create_co_disposition``.
    ``get_reachability_verdicts`` returns the raw verdicts.
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


_COMPOSITION_VIEWS = ("overview", "entities", "objectives", "coverage", "attack_paths")


@mcp.tool()
async def get_composition(
    server_version: str,
    model_id: str,
    view: Literal["overview", "entities", "objectives", "coverage", "attack_paths"] = "overview",
    page: int = 1,
    page_size: int = 100,
    kind: str | None = None,
    origin: str | None = None,
) -> dict:
    """A model's composed view: its own entities with everything inherited
    from its ancestors on the recursive tree. Read-only.

    ``view`` selects what is returned:

    - ``overview`` (default, ~1-2KB, read it first): ``{model_id,
      model_version, flag_enabled, tree: {parent_id, ancestor_chain, depth,
      child_ids}, counts: {entities, control_objectives,
      reconciliation_candidates}, warnings}``.
    - ``entities``: the effective entity set keyed by kind (trust
      boundaries, components, assets, attackers, attack paths), each entry
      ``{kind, qualified_id, owner_model_id, owner_title, origin, entity}``.
      Paginated (``page``, ``page_size``); ``kind`` (e.g. ``"attackers"``)
      keeps one kind.
    - ``objectives``: effective COs ``{co_qid, asset_qid, attacker_qid,
      security_properties, origin}``, where ``origin`` is ``own``,
      ``cross`` (inherited, with a local asset or attacker) or
      ``inherited``.
    - ``coverage``: per effective CO ``{co_qid, is_covered, own_credit,
      inherited_credit, contributing_controls}`` — the composed figures, not
      the per-model ``get_verification_report``. Paginated; ``origin``
      filters by contributing-control origin.
    - ``attack_paths``: ``{effective_paths, lattice_positions,
      authored_paths, suggestions: {missing_path, dangling_path}}`` against
      the composed topology.

    Where composition is not available, every view returns its shape empty
    with ``flag_enabled: false`` rather than an error. Composed reachability
    is ``get_reachability_verdicts(composed=True)``.
    """
    if view not in _COMPOSITION_VIEWS:
        raise ToolError(f"view must be one of {', '.join(_COMPOSITION_VIEWS)}.")
    try:
        client = _get_client()
        if view == "overview":
            return _dump(await client.composition_index(model_id))
        if view == "entities":
            return _dump(await client.composition_entities(
                model_id, page=page, page_size=page_size, kind=kind))
        if view == "objectives":
            return _dump(await client.composition_control_objectives(model_id))
        if view == "coverage":
            return _dump(await client.composition_coverage(
                model_id, page=page, page_size=page_size, origin=origin))
        return _dump(await client.composition_attack_paths(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


_RECONCILIATION_KINDS = {"assets", "attackers", "components"}


_RECONCILIATION_DECISIONS = ("apply", "reject", "unreject")


def _check_candidate_pair(kind: str, own_qid: str, inherited_qid: str) -> None:
    """The candidate pair an apply or a reject names, refused before the call
    when it cannot name one."""
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


@mcp.tool()
async def decide_reconciliation_candidate(
    server_version: str,
    model_id: str,
    decision: Literal["apply", "reject", "unreject"],
    kind: str = "",
    own_qid: str = "",
    inherited_qid: str = "",
    confirm_heuristic: bool = False,
    rejection_id: str = "",
) -> dict:
    """Decide a reconciliation candidate from
    ``list_reconciliation_candidates``. Mutating.

    ``kind`` is ``assets``, ``attackers`` or ``components``; ``own_qid`` /
    ``inherited_qid`` are the pair's qualified ids (``"child:A1"``,
    ``"parent:A1"``).

    - ``decision="apply"`` records that the descendant's own entity IS the
      inherited one: the own entity stays in the model and is left out of its
      composed view, so the inherited entity is canonical and credit keys on
      it. The record is dropped when the pair stops matching (an edit, a
      re-parent). A ``heuristic``-tier candidate is
      refused unless ``confirm_heuristic=True`` acknowledges its structural
      divergence. The server re-validates the pair (400 when the model has
      moved since: refresh the list). Bumps the model version; returns
      ``{model, controls_carried, controls_orphaned,
      orphaned_control_ids}``, ``model`` being its id, version and title.
    - ``decision="reject"`` records "these are NOT duplicates" at org scope,
      so the pair leaves the active queue for everyone. Idempotent on the
      pair; no new version. Returns the record; keep its ``id``.
    - ``decision="unreject"`` removes the rejection ``rejection_id`` (from
      ``list_reconciliation_candidates(disposition="rejected")``), returning
      the pair to the queue. Returns ``{ok: true}``.

    503 where composition is not available on the backend.
    """
    if decision not in _RECONCILIATION_DECISIONS:
        raise ToolError(f"decision must be one of {', '.join(_RECONCILIATION_DECISIONS)}.")
    if decision == "unreject":
        if not model_id or not model_id.strip():
            raise ToolError("model_id is required and must be non-empty.")
        if not rejection_id or not rejection_id.strip():
            raise ToolError("rejection_id is required and must be non-empty.")
    else:
        _check_candidate_pair(kind, own_qid, inherited_qid)
    try:
        client = _get_client()
        if decision == "apply":
            return _without_models(_dump(await client.apply_certain_reconciliation_match(
                model_id, kind, own_qid, inherited_qid,
                confirm_heuristic=confirm_heuristic,
            )))
        if decision == "reject":
            return _dump(await client.reject_reconciliation_candidate(
                model_id, kind, own_qid, inherited_qid,
            ))
        return _dump(await client.unreject_reconciliation_candidate(
            model_id, rejection_id,
        ))
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
    ``undo_composition_event(event_type="lift")``, which previews unless
    ``dry_run=False``; the inverse operation is ``split_composition_entity``.

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

    Returns ``{lift_id, lca_model, descendant_a_model, descendant_b_model,
    applied_migrations, lift_event}``, each model being its id, version and
    title (read one with ``get_threat_model``).

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
        return _without_models(_dump(
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
        ))
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

    Returns ``{split_id, ancestor_model, descendant_models,
    applied_duplications, split_event}``, each model being its id, version
    and title (read one with ``get_threat_model``).

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
        return _without_models(_dump(
            await _get_client().split_composition_entity(
                model_id,
                kind,
                ancestor_local_id,
                target_descendants,
            ),
        ))
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
        justification: Why this group structure is appropriate (10 to 2000
            characters). The gate weighs it alongside the objective and the
            controls' own descriptions, so state the reasoning, not evidence.
    """
    import json as _json
    try:
        parsed_groups = _json.loads(groups)
    except _json.JSONDecodeError:
        raise ToolError("groups must be valid JSON: {\"1\": [\"CTRL-01\"], ...}")
    if not isinstance(parsed_groups, dict):
        raise ToolError("groups must be a JSON object")

    did_list = [s.strip() for s in defense_in_depth.split(",") if s.strip()] if defense_in_depth else []

    _check_justification_length(justification)

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
async def edit_evidence(
    server_version: str,
    model_id: str,
    control_id: str,
    action: Literal["add", "remove"],
    type: str = "code",
    label: str = "",
    url: str = "",
    evidence_index: int = 0,
) -> dict:
    """Attach or detach an auxiliary evidence item (doc, link, artifact
    reference) on a control. Mutating.

    Evidence is contextual metadata only: it does NOT count toward a
    control's implementation status, and removing it changes neither the
    status nor any assertion. Only assertions prove controls.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        action: "add" attaches an item; "remove" detaches one.
        type: add — "code", "test", "config", "document" or "link" (default
            "code").
        label: add — human-readable description of the item (required).
        url: add — optional file path or URL pointing at the artifact.
        evidence_index: remove — zero-based position of the item in the
            control's ``evidence`` array (read it with
            ``get_controls(control_id=...)``; default 0, the first item).
    """
    if action not in ("add", "remove"):
        raise ToolError('action must be "add" or "remove".')
    if action == "add" and not label.strip():
        raise ToolError("label is required.")
    try:
        client = _get_client()
        if action == "add":
            return _dump(await client.add_evidence(model_id, control_id, type, label, url))
        return _dump(await client.remove_evidence(model_id, control_id, evidence_index))
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

    The saved controls are added to the model's current controls as one
    change (undoable with ``undo_model_change``); no model version is
    created, and it is refused while a control build holds the model. Nothing
    runs for them unprompted: the result's ``awaiting_judgement`` lists them,
    and the mitigation groups they join credit nothing and read awaiting
    judgement until ``judge_imported_controls`` is called (estimate first,
    then ``confirm_estimate=True``).

    Args:
        model_id: ID of the threat model.
        controls_json: JSON array of {description, co_ids?, framework_refs?}.
        free_text: Free-text controls (narrative/CSV/bullets).
        source_label: Origin label (e.g., "ISO 27001").
        auto_map: Auto-map controls to COs using LLM (default: True).

    Returns ``{imported, controls, awaiting_judgement, hint}`` once saved.
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
async def judge_imported_controls(
    server_version: str,
    model_id: str,
    ctx: Context,
    confirm_estimate: bool = False,
) -> dict:
    """Have the imported controls awaiting their judgement judged. Mutating
    only with ``confirm_estimate=True``; may consume credits then.

    Controls saved by ``import_controls`` are not judged unprompted: the
    mitigation groups they join credit nothing until this runs. It judges
    every objective those controls join, priced and charged as
    ``judge_objectives`` prices and charges them.

    1. Call with ``confirm_estimate=False`` (the default). Nothing is queued
       and nothing is charged; the answer carries ``awaiting_judgement`` (the
       control ids), ``co_ids`` (the objectives they join), ``scope``,
       ``ungrouped`` and ``estimate``. Show the user the estimate.
    2. Call again with ``confirm_estimate=True`` once they agree. The
       judgements are queued (``confirmed: true``, ``queued``) and the
       controls stop awaiting (``awaiting_judgement`` comes back empty).

    ``ungrouped`` lists objectives with no mitigation group: nothing can be
    judged there until their controls are grouped with
    ``set_mitigation_groups``. When nothing awaits, the answer says so and
    does nothing.

    Refusals come back as data, ``{confirmed: false, queued: 0,
    http_status, ...}``: 409 while a control build is running, 402 when the
    balance this workspace bills to cannot cover the estimate, 503 when
    judging is unavailable on this deployment.

    Args:
        model_id: ID of the threat model.
        confirm_estimate: False (default) returns the estimate and queues
            nothing; True queues the judgements.
    """
    try:
        return _dump(await _get_client().judge_imported_controls(
            model_id, confirm_estimate=confirm_estimate))
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
    snapshot: str = "",
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

    Paging: a read with ``limit`` that leaves pages beyond its own names a
    ``snapshot`` of the whole assessment, with ``snapshot_expires_at``. Pass
    it back with each later page: the pages are then served from that one
    evaluation, as of its ``evaluated_at``, so they agree with each other and
    nothing is evaluated again. A snapshot is kept for 10 minutes, and only
    the 5 newest of a model, so other paged reads of the model can replace
    it sooner. One not found comes back as ``{http_status: 410, code:
    "snapshot_not_found", message}``: read again without it, from the first
    page.

    Args:
        model_id: ID of the threat model to assess.
        summary_only: If True, return only summary counts (no per-CO details).
        status: Optional filter — "mitigated", "at_risk", or "unassessed".
        offset: Skip the first N control objectives.
        limit: Max control objectives to return (0 = all).
        snapshot: The ``snapshot`` an earlier page named; empty (default)
            evaluates the model now.
    """
    try:
        return _dump(await _get_client().assess_model(
            model_id, summary_only=summary_only,
            status=status or "", offset=offset, limit=limit,
            snapshot=snapshot.strip(),
        ))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_review_queue(server_version: str) -> dict:
    """Returns the workspace's review queue: what needs a decision or a
    re-check, ranked. Read-only; no side effects.

    Each row carries an ``item_type``, one of ``escalation`` (a judgment an
    agent was refused and parked for a person), ``proposal`` (an open change
    of scope or design, or an ``assumption`` proposal: a precondition a
    strengthening run found only the environment can meet),
    ``unaccepted_assumption`` (an assumption something depends on that is
    not accepted — never attested, lapsed, or its text changed since it was
    attested — with the controls and objectives that wait on it),
    ``open_assumption``, ``behavioural_question`` (an open question about
    what the system does, answered with ``answer_behavioural_questions``),
    ``behavioural_link`` (an element of the behavioural model not yet linked
    to an asset or trust boundary, or linked to one that lacks the property
    at stake; see ``get_behavioural_links``), ``not_applicable_refuted`` (a
    person's statement that a property does not apply to an asset, which
    the behavioural model contradicts: under a confirmed model it no longer
    counts, under an unconfirmed one it still does; ask the person to revise
    or revoke it, or to confirm the model), ``position_disagreement`` (an
    attested attacker position a producer would place elsewhere),
    ``behavioural_attacker`` (``get_behavioural_attackers``),
    ``inventory_judgement`` (``get_inventory_judgements``), or
    ``stale_control`` (an implemented/verified
    control whose assertions have not been checked in 90+ days). Rows are
    ranked: escalations, then proposals and the behavioural rows by risk
    tier, then position disagreements, unaccepted assumptions, open
    assumptions and stale controls. Escalations
    and proposals are decided with ``decide_proposal``; an unaccepted
    assumption is accepted with ``submit_attestation``; for each stale
    control, verify its assertions against the codebase. Accepting an
    assumption is a person's judgment unless the workspace delegates it.
    Start here for periodic maintenance.
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

    **Authoring contract**: name the *data or resource being protected* and
    the security property at stake (Confidentiality / Integrity /
    Availability / Usage), not a mechanism or control ("per-organization
    key-wrapping material", not "KMS encryption"). An asset phrased as a
    mechanism is flagged with a ``quality_warning`` and yields
    under-specified control objectives. An asset that does not apply is
    recorded with a non-applicability assumption or
    ``create_co_disposition``; there is no status to set.

    The platform reasons the factor decomposition and composes ``impact``
    with the prompt generation uses, so factors are calibrated alike;
    override one afterwards with ``edit_asset`` and a ``change_reason``.
    ``component_ids`` links the asset to the deployable units that hold it,
    which feeds reachability (several for a multi-instance asset, e.g. a
    session token on client and cache).

    A proposal matching a soft-deleted asset is gated: it either restores
    that asset (``auto_restored: true``, ``restored_asset_id``,
    ``discarded_fields``; its CO tombstones revive) or is refused as similar
    (``{accepted: false, classification: "similar", candidate_restore_id}``,
    nothing saved). A normal create returns ``{model, entities,
    controls_carried, ...}``: ``model`` is the model's id, version and title,
    ``entities.assets`` the asset as created. 503: an evaluator is
    unavailable, retry with backoff; 502: it answered malformed, retry.

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
        return _entity_change(await _await_backend_job(
            client, started["job_id"], ctx, heartbeat=True), "asset")
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
    ``quality_warning`` (see ``add_asset``). There is no status field to
    set.

    The composed ``impact`` is server-derived from the factor fields;
    there is no way to set it directly. To change the rating, set
    factor values (the platform composes the new rating) and supply
    ``change_reason`` documenting the operator override of the
    LLM-generated factors. The reason is captured in the
    rating-revision audit trail.

    LLM-gated on identity-bearing fields (name, description,
    security_properties). Factor and notes edits skip the gate.

    Outcomes when identity fields change:
    - **Accepted edit** (LLM classifies as ``preserve``) — ``{model,
      entities, controls_carried, ...}``: the model's id, version and title,
      and the asset as it now stands.
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
        return _entity_change(await _await_backend_job(
            client, started["job_id"], ctx, heartbeat=True), "asset", (asset_id,))
    except Exception as exc:
        raise _api_error(exc) from exc


_ATTACKER_FACTOR_PARAMS = (
    "attack_vector", "privileges_required", "attack_complexity",
    "user_interaction", "capability_prevalence",
)

# How far an attacker's operations range over the interface it reaches.
# ``whole`` = any entry of that interface (any endpoint, request, row,
# file, message or frame); ``point`` = one named entry.
_SURFACE_EXTENTS = ("point", "whole")


def _validate_surface_extent(value: Optional[str]) -> None:
    if value is not None and value not in _SURFACE_EXTENTS:
        raise ToolError(
            f"surface_extent must be one of {list(_SURFACE_EXTENTS)}, not {value!r}."
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
    surface_extent: Optional[str] = None,
    change_reason: Optional[str] = None,
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
    archetype, trust_boundary_ids); the backend reasons the factors.
    Override one later via ``edit_attacker`` with a ``change_reason``.

    Three outcomes (normal create / auto-restore / similar-rejection)
    mirror ``add_asset`` (``entities`` holds the attacker). 503 on
    factor-reasoning or restore-candidate evaluator outage, 502 on malformed
    restore-candidate response.

    ``surface_extent`` says how much of the reached interface this
    attacker's operations range over. An attacker ranging over the whole
    interface makes the objectives it appears in for-all obligations,
    which only a sound witness (``typed_boundary`` /
    ``sink_default_deny``) can credit. Declaring it here is a statement about
    the attacker's reach, taken with its ``change_reason``: a person's is
    recorded attested; a program's only under a workspace rule delegating
    ``extent_attested``, otherwise the attacker is added, the extent lands
    unattested and the attestation waits for a person (the answer's
    ``attestation.escalation_id``). Only ``whole``
    is declarable on a create: narrowing to one named entry is a statement
    about the objectives the attacker anchors, and a create has none yet —
    add the attacker, then narrow it with ``edit_attacker`` and a
    ``change_reason``, where the narrowing is checked against the assets
    those objectives defend. There is no attacker status to set.

    Args:
        model_id: ID of the threat model.
        capability: Attacker capability description (required).
        position: Position/access level.
        archetype: Archetype (e.g., "insider", "external").
        trust_boundary_ids: Comma-separated ids of the boundaries the
            attacker has crossed. Naming them attests the position: a
            person's is recorded attested; a program's only under a rule
            delegating ``position_attested``, otherwise the position lands
            suggested and the attestation waits for a person
            (``attestation.escalation_id``).
        surface_extent: ``"whole"`` when, from its position, the attacker's
            operations range over ANY entry of the interface it reaches
            (any endpoint, request, row, file, message or frame). Requires
            ``change_reason``. Omit to leave it undeclared, which is the
            ordinary case.
        change_reason: Required when ``surface_extent`` is supplied —
            documents the declaration for the audit trail.
    """
    _validate_surface_extent(surface_extent)
    if surface_extent == "point":
        raise ToolError(
            "Narrowing an attacker to a single named entry is a declaration "
            "about the objectives it anchors, which do not exist yet — add the "
            "attacker, then narrow it with edit_attacker and a change_reason, "
            "where the declaration is checked against the assets those "
            "objectives defend."
        )
    if surface_extent and not (change_reason and change_reason.strip()):
        raise ToolError(
            "change_reason is required when declaring an attacker's surface "
            "extent. The extent decides whether the objectives this attacker "
            "anchors are for-all obligations, so the declaration is recorded "
            "with its reason."
        )
    body: dict[str, Any] = {"capability": capability}
    if surface_extent:
        body["surface_extent"] = surface_extent
    if change_reason is not None:
        body["change_reason"] = change_reason
    if position:
        body["position"] = position
    if archetype:
        body["archetype"] = archetype
    if trust_boundary_ids:
        body["trust_boundary_ids"] = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()]
    try:
        client = _get_client()
        started = await client.start_add_attacker(model_id, **body)
        return _entity_change(await _await_backend_job(
            client, started["job_id"], ctx, heartbeat=True), "attacker")
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
    surface_extent: Optional[str] = None,
    attest_surface_extent: Optional[bool] = None,
    attest_privileges: Optional[bool] = None,
    change_reason: Optional[str] = None,
) -> dict:
    """Edit an attacker; only the fields given change.

    ``capability`` names the operations performable from the position
    ("From [position], the attacker can …"), else it gets a
    ``quality_warning``. Identity fields are LLM-gated. The composed
    ``likelihood`` comes from the factors. An edit of ``attack_vector`` or
    ``privileges_required`` creates a model version (reachability reads
    both); other factor edits are recorded as rating revisions. The answer's
    ``model`` is the model's id, version and title; ``entities.attackers``
    the attacker as it now stands.

    Attesting is a judgment: a person's edit attests what it writes
    (``trust_boundary_ids``, ``privileges_required``, ``surface_extent``)
    and ``attest_*`` attests the value as it stands. A program attests
    only under a workspace rule for that attestation; otherwise its edit
    lands unattested and the answer's ``attestation`` names the parked
    ``escalation_id`` (never a 403). A refused program's extent never
    lowers an attested one. ``"point"`` is REFUSED where an asset of the
    attacker's objectives sits on several components and is not
    split-knowledge, and never makes a universal clause existential.

    400 when factor fields, ``surface_extent``, ``attest_surface_extent``
    or ``attest_privileges`` come without ``change_reason``; 503/502 on an
    evaluator outage or malformed answer. 409 ``privileges_from_holdings``
    for a privileges change on an attacker whose credential classes are
    stated: its privileges follow from them, so say what it holds instead
    (``answer_attacker_credentials``).

    Args:
        attack_vector: Network | Adjacent | Local | Physical.
        privileges_required: None | Low | High.
        attack_complexity: Low | High.
        user_interaction: None | Required.
        capability_prevalence: Commodity | Targeted | Rare.
        trust_boundary_ids: Comma-separated ids of the boundaries the
            attacker has crossed; replaces the set.
        attest_position: true attests the current position.
        surface_extent: ``whole`` (any entry of the interface reached) or
            ``point`` (one named entry).
        attest_surface_extent: true attests the current extent.
        attest_privileges: true attests the current ``privileges_required``,
            whatever its value.
        change_reason: Why; required as above.
    """
    _validate_surface_extent(surface_extent)
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
    if surface_extent is not None:
        body["surface_extent"] = surface_extent
    if attest_surface_extent is not None:
        body["attest_surface_extent"] = attest_surface_extent
    if attest_privileges is not None:
        body["attest_privileges"] = attest_privileges
    if change_reason is not None:
        body["change_reason"] = change_reason
    factor_sent = any(k in body for k in _ATTACKER_FACTOR_PARAMS)
    declared = ("surface_extent" in body or "attest_surface_extent" in body
                or bool(attest_privileges))
    if (factor_sent or declared) and not (change_reason and change_reason.strip()):
        raise ToolError(
            "change_reason is required when editing rating factors, attesting "
            "the surface extent or attesting the privileges. Each is a "
            "declaration, recorded with its reason for the audit trail."
        )
    try:
        client = _get_client()
        started = await client.start_edit_attacker(model_id, attacker_id, **body)
        return _entity_change(await _await_backend_job(
            client, started["job_id"], ctx, heartbeat=True), "attacker", (attacker_id,))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def reevaluate_threat_model_factors(
    server_version: str,
    model_id: str,
    ctx: Context,
    change_reason: Optional[str] = None,
    entity_ids: str = "",
    unrated_only: bool = False,
) -> dict:
    """Re-run the LLM factor judgment on a model's live assets and
    attackers: every one, those ``entity_ids`` names, or only those nobody
    rated (``unrated_only``; with both, the unrated among those named).
    Re-baselines factors after a bug fix or description change, or rates
    what reads "not rated", without regenerating the model (which would
    destroy controls, assertions, components). One call per entity in
    scope; an id naming no live asset or attacker is refused (400) before
    any call; a scope naming none makes no call.

    Each entity's factors and rationale are replaced with a fresh
    decomposition and its impact / likelihood re-derived from them. Each
    re-rating is a rating revision recorded with ``change_reason``
    (default "LLM factor re-evaluation"), told apart from overrides made
    with ``edit_asset`` / ``edit_attacker``. The judgment is a starting
    point: layer deployment-specific factors on top with those, and a
    ``change_reason`` saying why.

    Per-entity soft-fail: a failure on one entity lands in
    ``failed_entities`` (``id``, ``kind``, ``reason``) and the rest still
    persist; 503 only when every entity in scope failed, with nothing
    persisted. Soft-deleted entities are skipped.

    Re-ratings keep the model version, except where an answer changes an
    attacker's ``attack_vector`` or ``privileges_required``: reachability
    reads both, so the run saves one new version carrying every answer,
    and a proposal reviewed before it reads ``review_stale``. Privileges an
    answer changes are no longer attested.

    Args:
        model_id: ID of the threat model to re-rate.
        change_reason: Optional audit-trail reason (default "LLM factor
            re-evaluation").
        entity_ids: Optional comma-separated asset and attacker ids (e.g.
            "A-03,T-14"); omit for every live entity.
        unrated_only: Only entities whose ``rating_source`` is
            ``unrated``. Default False.

    Returns ``{model_id, in_scope, assets_reevaluated,
    attackers_reevaluated, deltas: {assets, attackers}, failed_entities}``:
    ``in_scope`` how many entities the scope named, ``deltas`` each
    re-rated entity's factors and composed rating before and after.
    """
    ids = _class_list(entity_ids)
    scope: dict[str, Any] = {}
    if ids:
        scope["entity_ids"] = ids
    if unrated_only:
        scope["unrated_only"] = True
    try:
        client = _get_client()
        # Runs as a background job (scales with entity count); poll it so the
        # work stays off the backend event loop and the transport stays warm.
        started = await client.start_reevaluate_factors(
            model_id, change_reason=change_reason, **scope,
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
    coverage rows with ``resolve_verdict_divergences(action="accept")``; set
    aside rows the structural model got right with
    ``resolve_verdict_divergences(action="dismiss")``.

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
async def resolve_verdict_divergences(
    server_version: str,
    model_id: str,
    action: Literal["accept", "dismiss"],
    items: str,
    reason: str,
) -> dict:
    """Accept a batch of coverage divergences as mapping changes, or dismiss
    a batch of divergences. Mutating.

    ``action="accept"``: each ``missing_mapping`` ADDS its CO to the
    control, each ``spurious_mapping`` REMOVES it, one version per affected
    control. Items are validated one by one: the answer separates
    ``applied`` from ``skipped`` (stale, would orphan, already so). To accept
    only confident rows, filter ``get_verdict_divergence``'s coverage rows
    by ``p_covers`` (near 1.0 for missing, near 0.0 for spurious) first.
    ``reason`` (min 10 chars) is recorded on each control's history.

    ``action="dismiss"``: the structural model was right and the LLM was
    not; the model does not change. A dismissal is keyed to the row's
    current verdict input, so the row reappears once its control or
    objective changes. Works for coverage and ``group_sufficiency`` rows.

    Args:
        model_id: ID of the threat model.
        action: "accept" or "dismiss".
        items: JSON array of rows. accept: ``{"control_id", "co_id", "kind"}``
            with kind ``missing_mapping`` or ``spurious_mapping``. dismiss:
            ``{"kind", "co_id", "control_id"?, "group_id"?}`` (control_id for
            coverage kinds, group_id for group_sufficiency).
        reason: Why (accept: min 10 chars; dismiss: non-empty).
    """
    import json as _json

    if action not in ("accept", "dismiss"):
        raise ToolError('action must be "accept" or "dismiss".')
    try:
        parsed = _json.loads(items)
    except (ValueError, TypeError) as exc:
        raise ToolError("items must be a JSON array of divergence objects.") from exc
    if not isinstance(parsed, list) or not parsed:
        raise ToolError("items must be a non-empty JSON array.")
    if action == "accept" and len(reason.strip()) < 10:
        raise ToolError("reason must be at least 10 characters to accept.")
    if not reason.strip():
        raise ToolError("reason must not be empty.")
    try:
        client = _get_client()
        if action == "accept":
            return _dump(await client.accept_coverage_divergences(
                model_id, parsed, reason.strip(),
            ))
        return _dump(await client.dismiss_verdict_divergences(
            model_id, parsed, reason.strip(),
        ))
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
    internal) is not covered by Mipiti's built-in frameworks. After
    import, the framework is selectable on threat models exactly like
    a built-in.

    Fields: ``name`` (required), ``version``, ``description``,
    ``requirements`` (required, non-empty), ``level_definitions``.

    Each requirement takes ``id`` and ``description`` (required), ``level``
    (integer, default 1), the optional grouping ``chapter_id`` /
    ``chapter_name`` / ``section_id`` / ``section_name`` / ``title``,
    ``scope`` (``component``, the default, or ``system``: covered if ANY
    model satisfies it) and ``level_specific_text`` (per-level text).

    ``level_definitions`` and ``level_specific_text`` are keyed by the
    level as a string integer ("1", "2"): the key is the ordinal the
    ``level <= target_level`` filter compares, so a non-integer key is
    refused (400). Labels ("Baseline", "SL3") go in each value's ``name``.
    A level value is ``{"name", "description", "source"}``, where ``source``
    is ``authoritative`` (paraphrased from the published standard) or
    ``mipiti_convention`` (tiers you defined).

    Example::

        {
          "name": "ACME Tiered",
          "level_definitions": {
            "1": {"name": "Baseline", "description": "Minimum.",
                  "source": "mipiti_convention"}
          },
          "requirements": [
            {"id": "ACME-PWD", "description": "Passwords meet policy",
             "level": 1, "level_specific_text": {"1": "Min 8 characters."}}
          ]
        }

    Args:
        framework_json: The framework body as a JSON string.
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

    Generation reads no components, so add or edit them after
    ``generate_threat_model``, not before.

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

    Returns ``{model, entities, ...}``: the model's id, version and title,
    and ``entities.components`` the component as created.
    """
    tb_ids = [t.strip() for t in trust_boundary_ids.split(",") if t.strip()] if trust_boundary_ids else []
    try:
        return _entity_change(_dump(await _get_client().add_component(
            model_id, name, repo_url, path, tb_ids or None,
        )), "component")
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

    Returns ``{model, entities, ...}``: the model's id, version and title,
    and ``entities.components`` the component as it now stands.
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
        return _entity_change(_dump(await _get_client().edit_component(
            model_id, component_id, **fields)), "component", (component_id,))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Cross-Model Dependencies ===


@mcp.tool()
async def get_group_dependencies(
    server_version: str,
    group_id: str,
) -> dict:
    """The reliance edges among a tag's member models. Read-only; no side effects.

    Returns ``{tag_id, tag_name, models, edges, total}``: one row per edge a
    member declared on another model's control (``manage_reliance`` /
    ``attach_foundation``), with both models' titles, the ``mode``
    (``delegated`` or ``relied_upon``), the source objective or control, the
    provider control, its ``status`` (``draft``, ``active``, ``broken``,
    ``rejected``), ``validation_verdict`` and ``credit_state`` (whether it
    credits its objective now). Empty when no member relies on another.

    Use it to review the cross-model dependencies of a product or audit
    scope before an auditor export, or to find broken edges. A model's own
    edges, in both directions, are ``list_reliance``.

    Args:
        group_id: ID of the tag.
    """
    try:
        return await _get_client().get_tag_dependencies(group_id)
    except Exception as exc:
        raise _api_error(exc) from exc


# === Assertions & Verification ===


@mcp.tool()
async def get_assertion_types(
    server_version: str,
    types: Optional[str] = None,
) -> dict:
    """List the assertion types submit_assertions accepts, with their params.

    Read-only. Returns the catalogue as structured data: every type, what it
    proves, its ``soundness`` class, which params it requires, which it
    accepts (an array-valued param carries its ``item_schema``), and a
    worked example. ``soundness_classes`` defines the five classes by the
    fact a pass establishes, weakest to strongest — ``presence``,
    ``under_approximating_scan``, ``existential_witness``,
    ``sound_over_approximation``, ``by_construction`` — and
    ``sound_classes`` names the two that can credit a for-all clause.
    ``covers`` gives the accepted form of a binding declaration.

    Call this before writing assertions. submit_assertions names the types and
    their required params in its own description, but descriptions are prose a
    client may present only in part, and a half-list reads exactly like a whole
    one. This returns data, so what you get back is the complete contract.

    Args:
        types: Optional comma-separated type names to return (e.g.
            "file_exists,pattern_absent"). Omit for all of them.
    """
    # server_version is enforced by VersionCheckMiddleware before the tool runs.
    names = [t for t in (types or "").split(",") if t.strip()] or None
    catalogue = describe_types(names)
    if names and not catalogue:
        raise ToolError(
            f"No such assertion type(s): {types}. Call get_assertion_types with "
            "no arguments to see every type."
        )
    return {
        "assertion_types": catalogue,
        "count": len(catalogue),
        "soundness_classes": describe_soundness_classes(),
        "sound_classes": list(SOUND_CLASSES),
        "covers": {"pattern": COVERS_PATTERN, "max": COVERS_MAX},
    }


# A client was observed to cut this description at 2048 characters, so it is
# written to the byte: the type list is generated and grows with the
# catalogue, and every sentence beside it has to earn its space. What must
# survive a cut is here; the same contract in full, with per-param formats and
# examples, is one get_assertion_types call away.
_SUBMIT_ASSERTIONS_DOC = f"""\
Typed claims about a control, assumption or functional test; CI checks later.
get_assertion_types returns it all as data.

By class, strongest first, as name(required) [opt: optional]:
{format_compact()}

Each: type, params, description, repo ("<owner>/<repo>" or "no_repo"), covers
beside them, never in params: the CO-NN or cls_ ids proved. A for-all clause
takes only typed_boundary (sinks accept one boundary type) or, when they do
not, sink_default_deny, bound with covers.
"""

_COVERS_IN_PARAMS = (
    "covers is a top-level field of the assertion, beside type, params, "
    "description and repo -- never a param. Move it out of params."
)

_COVERS_NOT_HERE = (
    "covers is not carried on a functional test's evidence. A binding "
    "between evidence and a control clause is declared with control_id."
)


def _refuse_malformed(assertions: list, *, covers_accepted: bool = True) -> None:
    """A param whose format the catalogue declares, and a ``covers``
    declaration, are checked before the submission leaves the client, with
    the same rule the platform applies on arrival.

    ``covers_accepted=False`` refuses the declaration outright, for a
    submission whose surface does not carry one: a field that would be
    dropped in transit has to be refused where the caller can see it, or the
    caller records a binding that does not exist.

    Both halves of a param check run here: the format of the values that are
    present, and the presence of the ones the type requires. A submission
    that names one type and fills another type's parameter set is otherwise
    well-formed in every value it carries, so only the absence check catches
    it, and it is caught where the caller can still edit the submission.
    """
    from .assertion_types import missing_required_params, validate_param_formats

    errors: list[str] = []
    for a in assertions:
        if not isinstance(a, dict):
            continue
        params = a.get("params") or {}
        type_name = str(a.get("type", ""))
        errors.extend(missing_required_params(type_name, params))
        errors.extend(validate_param_formats(type_name, params))
        if isinstance(params, dict) and "covers" in params:
            # Inside params a binding would ride the dedup key and change the
            # assertion's identity, so the same declaration would name a
            # different row on every edit.
            errors.append(_COVERS_IN_PARAMS)
        if "covers" in a:
            if covers_accepted:
                errors.extend(validate_covers(a.get("covers")))
            else:
                errors.append(_COVERS_NOT_HERE)
    if errors:
        raise ToolError("; ".join(errors[:5]))


@mcp.tool(description=_SUBMIT_ASSERTIONS_DOC)
async def submit_assertions(
    server_version: str,
    model_id: str,
    assertions_json: str,
    control_id: Optional[str] = None,
    assumption_id: Optional[str] = None,
    functional_test_id: Optional[str] = None,
) -> dict:
    """Submit machine-verifiable assertions for a control, an assumption or
    a functional test. Name exactly one of ``control_id``,
    ``assumption_id`` and ``functional_test_id``.

    A functional test's assertions (``test_exists``, ``test_attested``)
    are its evidence for functional conformance; they carry no ``covers``,
    which binds evidence to a control clause and is refused there. Read the
    resulting state with ``get_functional_coverage`` or ``get_sufficiency``
    (``functional_test_id``).

    Each object carries ``type``, ``params``, ``description``, ``repo`` and
    optionally ``covers`` (top-level, never inside ``params``): the
    objective id (``CO-NN``) or clause ids (``cls_`` + 12 hex, named by
    ``get_control_work_order``'s ``required_evidence``) the evidence
    proves. Prefer the objective id; name clause ids on a multi-clause
    control, where an objective ref only scopes review and sound credit
    needs the clause. A malformed declaration is refused on arrival with
    the accepted form. Resubmitting an assertion whose check is unchanged
    re-points it: the new ``covers`` is adopted onto the row that is
    already there, keeping its id and its verdicts. A resubmission that
    carries no ``covers`` leaves a stored declaration standing —
    withdrawing one is its own act, never a side effect of resubmitting.

    Composition rule, in observable terms: a clause is covered by the best
    admissible evidence bound to it. An existential clause takes an
    anchored test (``claimed`` when unsigned or unattested, ``witnessed``
    when signed and reviewed) or an attestation; a for-all clause takes
    only a witness of a sound class — ``typed_boundary``
    (``constructed``) or ``sink_default_deny`` (``sound``), where the
    platform offers them, which its work order reports in ``sound_types``
    — that passed both tiers, bound with ``covers`` and whose scope covers
    every on-path component. Presence and scan types cover no runtime
    clause on their own. A control is proven no more strongly
    than its weakest clause: one for-all clause with no sound witness
    leaves the control unproven however much evidence the others carry.
    """
    named = [n for n in (control_id, assumption_id, functional_test_id) if n]
    if len(named) != 1:
        raise ToolError(
            "Name exactly one of control_id, assumption_id or functional_test_id.")
    try:
        assertions = json.loads(assertions_json)
    except json.JSONDecodeError:
        raise ToolError("assertions_json must be valid JSON array.")
    if not isinstance(assertions, list):
        raise ToolError("assertions_json must be a JSON array.")
    _refuse_malformed(assertions, covers_accepted=not functional_test_id)
    try:
        if functional_test_id:
            return _dump(await _get_client().submit_functional_tests(
                model_id, functional_test_id, assertions,
            ))
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

    Each assertion also carries ``covers`` (the objective or clause ids it
    was declared to prove; empty when undeclared) and, where the platform
    surfaces it, ``tier1_attested`` and ``evidence_provenance`` (whether
    the run that verified it was signed and by what class of identity).

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
    """Permanently delete a single assertion from a control or assumption. Mutating and destructive: the assertion record is removed, not soft-deleted, and its contribution to sufficiency/verification is dropped. It does NOT itself re-run verification; the deletion queues a background re-evaluation of the control's sufficiency, which a later ``get_sufficiency`` read reports once it lands.

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
      ``"stale"`` means the stored verdict no longer reflects the current
      control description, active assertion set or the rules it was
      computed under. Reading does not queue a re-evaluation: the write that
      changed a control queues its own. Call this tool again later for the
      refreshed verdict.
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

    A drift item means the accepted evidence changed (a test's definition,
    a witness's scope or allowlist) and its verdict was withdrawn until
    reviewed again.

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
    control_id: str = "",
    functional_test_id: str = "",
) -> dict:
    """Whether the submitted assertions of one control, or of one functional
    test, together prove it. Read-only; name exactly one id.

    For a control this explains ``verification_status:
    "partially_verified"``. ``status`` is ``sufficient | insufficient |
    pending``, with ``freshness`` (``fresh | stale | pending``) beside it;
    insufficient carries ``details`` naming EACH uncovered clause and the
    evidence that would close it. A ``soundness_tier`` is the weakest
    clause's tier: a control is proven no more strongly than its thinnest
    clause. It is composed over the evidence as it stands now
    (``strength_basis: now``), beside ``soundness_tier_at_evaluation``, and
    ``clause_strength`` lists each clause's tier now and when judged, with
    each piece of evidence marked ``passes_now``: relay a clause whose
    evidence no longer passes. Reading does not queue a re-evaluation. For
    the whole model use ``get_verification_report``.

    ``commitments`` is what it was checked against: a person's declaration
    (``basis: "declaration"``; an open cross-check finding keeps it
    insufficient: ``get_control_delta``) or a reading of the text.

    Act by submitting the named assertions; a clause describing a mechanism
    the system does not use calls for ``refine_control``, not evidence.
    ``get_control_work_order`` serves the per-clause list: where the order
    names a required class for a clause, ``required_evidence`` carries the
    clause id for ``covers`` and a ``suggested_submission`` skeleton whose
    ``<...>`` placeholders you replace. For a for-all clause prefer
    ``typed_boundary``, else ``sink_default_deny``. ``class_mismatch`` means
    the bound evidence is the wrong CLASS and more of it will not help. An
    attestation covers an existential clause, never a for-all one; that
    clause's only other exits are a risk acceptance or a not-applicable
    disposition.

    For a functional test it is whether its evidence proves the objectives
    it is associated with, with the reasoning; it can read pending or
    absent until evidence is submitted.
    """
    if bool(control_id) == bool(functional_test_id):
        raise ToolError("Name exactly one of control_id or functional_test_id.")
    try:
        client = _get_client()
        if functional_test_id:
            return _dump(await client.get_functional_test_sufficiency(
                model_id, functional_test_id,
            ))
        return await client.get_sufficiency(model_id, control_id)
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

    Returns finding rows with their lifecycle status; use to triage gaps or to find a ``finding_id`` for ``update_finding`` / ``remediate_finding``. Each row carries an ``origin`` ("own" for findings recorded on this model, "inherited" for findings contributed through model composition, with ``inherited_from_*`` context); inherited findings are included in the listing.

    Args:
        model_id: ID of the threat model.
        control_id: Optional filter to findings on one control. Empty (default) returns findings for all controls.
        status: Optional lifecycle filter, one of "discovered", "acknowledged", "remediated", "verified", "dismissed", "auto_resolved". Empty (default) returns all statuses.
            ``auto_resolved`` is closed by the platform, not by a person: the
            condition that produced the finding is no longer reproduced. It is
            deliberately distinct from ``remediated``/``verified`` (a person
            fixed and confirmed it) and from ``dismissed`` (a person judged it
            not worth fixing) — "the gap is gone" and "the gap does not matter"
            are opposite statements about residual risk, so they never share a
            status.
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

    Use to acknowledge, remediate, verify, or dismiss a finding previously recorded by ``submit_findings`` / ``list_findings``. This records a MANUAL status transition — the machine-set ``auto_resolved`` state is not among the statuses it accepts; for gaps whose kind has an automatic fix, ``remediate_finding`` performs the actual cleanup instead.

    Args:
        model_id: ID of the threat model.
        finding_id: ID of the finding to update.
        status: New lifecycle status, one of "discovered", "acknowledged", "remediated", "verified", "dismissed". ``auto_resolved`` is NOT settable here: it asserts that a condition is no longer reproduced, which is a claim only the platform can make from its own re-evaluation. Setting it by hand would forge that claim, so this tool refuses it — use ``dismissed`` (with a reason) to record that a gap does not matter, which is the judgment a person is entitled to make.
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
async def remediate_finding(
    server_version: str,
    finding_id: str,
    ctx: Context,
    apply: bool = False,
    justification: str = "",
) -> dict:
    """Preview, and on confirmation apply, the platform's remediation of a
    finding.

    Without ``apply`` it is read-only: it returns a structured diff of what
    the remediation would change, shaped by the finding's kind (for
    ``structural_duplicate_controls``: which controls are kept, which
    dropped, and the CO mappings and framework refs the survivor takes).
    Show the operator that diff and get explicit confirmation.

    With ``apply=True`` it commits the change, recording ``justification``
    (a one-line operator rationale, required) on the audit trail. Never
    apply without having shown the preview: the platform records who acted
    but does not enforce the preview — the agent does.

    404 when the finding does not exist; 422 when its kind has no automatic
    remediation (resolve those with the control tools); applying a finding
    already remediated or dismissed is refused (409).

    Args:
        finding_id: ID of the finding.
        apply: False (default) previews; True applies.
        justification: With ``apply=True``: the operator's rationale.
    """
    if not apply:
        try:
            return _dump(await _get_client().preview_finding_remediation(finding_id))
        except Exception as exc:
            raise _api_error(exc) from exc
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
    """Add a trust boundary. Creates a new model version. Returns ``{model,
    entities, ...}``: the model's id, version and title, and
    ``entities.trust_boundaries`` the boundary as created.

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
            (an air-gap / network-segmented enclave). On its own this is a
            suggestion: only an ATTESTED seal lets reachability decisively
            rule an asset unreachable instead of indeterminate, and the
            attestation is recorded with ``edit_trust_boundary``
            (``seal_source="attested"`` with a ``change_reason``), by a
            person or a program the workspace delegates ``seal_attested``
            to. Default False (assume a lateral pivot is possible). Set it
            only when the isolation is real and attestable.
    """
    parsed_crosses = [c.strip() for c in crosses.split(",") if c.strip()] if crosses else []
    parsed_passes = (
        [v.strip() for v in passes.split(",") if v.strip()] if passes is not None else None
    )
    try:
        return _entity_change(await _get_client().add_trust_boundary(
            model_id, description, parsed_crosses or None, parsed_passes,
            sealed=sealed,
        ), "trust_boundary")
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
    """Edit a trust boundary. Creates a new model version. Returns ``{model,
    entities, ...}``: the model's id, version and title, and
    ``entities.trust_boundaries`` the boundary as it now stands.

    Attesting the seal is a judgment: a person's edit attests it; a
    program's only under a workspace rule delegating ``seal_attested``,
    otherwise the edit lands with the seal unattested and the answer's
    ``attestation`` names the parked ``escalation_id`` (never a 403). Any
    change to ``passes``, ``crosses``, ``neighbors`` or ``sealed`` voids an
    attested seal: the attestation is of the content as it stood.

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
            it can flip CO verdicts. Setting it attests the seal, as above.
            Omit to leave unchanged.
        seal_source: "attested" | "unattested". Only an attested seal lets
            reachability decisively rule an objective unreachable past the
            boundary; an unattested (default or generated) seal is treated as
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
        return _entity_change(await _get_client().edit_trust_boundary(
            model_id, tb_id, **kwargs), "trust_boundary", (tb_id,))
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
    """Add an assumption. Creates a new model version. Returns ``{model,
    entities, ...}``: the model's id, version and title, and
    ``entities.assumptions`` the assumption as created.

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
        return _entity_change(await _get_client().add_assumption(
            model_id, description, parsed,
            assumption_type=assumption_type,
            exclusion=exclusion,
        ), "assumption")
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
    """Edit an assumption. Creates a new model version. Returns ``{model,
    entities, ...}``: the model's id, version and title, and
    ``entities.assumptions`` the assumption as it now stands.

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
        return _entity_change(await _get_client().edit_assumption(
            model_id, assumption_id, **kwargs), "assumption", (assumption_id,))
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

    Attesting accepts the assumption, which is a judgment about the world
    the platform cannot check: a program may do it only under a workspace
    delegation rule for ``assumption_accepted``; otherwise the call is
    refused with HTTP 403 and an ``escalation_id`` and the attestation is
    parked for a person. An attestation holds for the text it was given
    for: editing the assumption's description retires it, and the
    assumption must be accepted again. An assumption need not be linked to
    an objective to be accepted — one bound into a control's group (see
    ``strengthen_controls``) counts only while it is accepted.

    An attestation is a responsible party's claim, never a proof over every
    site: it can cover an existential clause of a control (its tier reads
    ``claimed``) and never a for-all one, where only a sound witness
    counts. An attestation the platform mints from CI results is no
    stronger than the weakest assertion behind it. The exits for a
    universal objective that cannot be proven are a risk acceptance or a
    not-applicable disposition.

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
        justification: Why this group structure is appropriate (10 to 2000
            characters when groups is non-empty; optional when clearing, at
            most 2000 characters if given).
    """
    import json as _json
    try:
        parsed_groups = _json.loads(groups)
    except _json.JSONDecodeError:
        raise ToolError("groups must be valid JSON: {\"1\": [\"AS1\"], ...}")
    if not isinstance(parsed_groups, dict):
        raise ToolError("groups must be a JSON object")

    if parsed_groups:
        _check_justification_length(justification)
    elif len(justification.strip()) > _JUSTIFICATION_MAX_CHARS:
        _check_justification_length(justification)

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
    """Convert a violated or retired assumption to controls. Mutating.

    Retires the assumption's CO linkage and, when any CO it covered is left
    with no control, proposes a control build for those COs: the result's
    ``proposal`` (null when nothing is owed) is started with
    ``start_control_build`` after review, and authors the controls then.
    Nothing is authored by this call. Use when an assumption is no longer
    valid and the system owner needs to implement controls instead.

    Side effect on control-level linkage: this assumption is also removed
    from every assumption_groups entry on every control that referenced it.
    Any group left empty by the removal is dropped; a control's status is
    not changed, and a control left with no group is no longer backed by
    an assumption. Underlying assumptions are not deleted — only the
    linkages.

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
# (1) generate — generate_functional_objectives → get_scan_prompt (functional) →
#     write tests → add_functional_test → submit_assertions (functional_test_id) →
#     CI verifies → get_functional_coverage.
# (2) import existing tests — import_functional_tests → suggest_functional_test_mappings
#     → associate_functional_test → (optionally) set_functional_satisfaction_groups →
#     get_sufficiency (functional_test_id).


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
async def get_capabilities(
    server_version: str, model_id: str, capability_id: str = "",
) -> dict:
    """A model's capabilities (behaviours the feature must deliver), or one
    of them. Read-only.

    Without ``capability_id``: every capability, each with its id,
    name/description and a summary of its component and asset bindings.
    With it: that capability with its bound components and assets.

    Args:
        model_id: ID of the threat model.
        capability_id: Optional; omit to list every capability.
    """
    try:
        client = _get_client()
        cap_id = capability_id.strip()
        if cap_id:
            return _dump(await client.get_capability(model_id, cap_id))
        return _dump(await client.list_capabilities(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_functional_coverage(
    server_version: str, model_id: str, gaps_only: bool = False,
) -> dict:
    """A model's functional coverage report, or just its actionable gaps.
    Read-only.

    By default the whole picture: per-objective state (verified / covered /
    failing / untested), the Capabilities × Conditions matrix, and the
    applicable / missing-objective / not-applicable cell accounting. With
    ``gaps_only=True`` only what needs action: applicable conditions with no
    objective yet, and objectives that are failing or have no passing test.

    Args:
        model_id: ID of the threat model.
        gaps_only: Return only the actionable gaps (default False).
    """
    try:
        client = _get_client()
        if gaps_only:
            return _dump(await client.get_functional_gaps(model_id))
        return _dump(await client.get_functional_coverage(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_functional_test(
    server_version: str, model_id: str, description: str,
    functional_objective_ids: str, status: str = "not_implemented",
    component_ids: str = "",
) -> dict:
    """Hand-author a single functional test and map it to one or more objectives. Mutating.

    Generation (generate_functional_objectives) already specifies the tests to implement, so use this only to register an extra test that generation did not produce; a manually-added test survives regeneration/refresh. For bulk-registering tests that already exist in your codebase, use import_functional_tests instead. This records the test at the status you claim — it does not run or verify anything; CI verification happens only when you attach TEST_EXISTS/TEST_ATTESTED evidence via submit_assertions with functional_test_id.

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
      ``entity_id`` e.g. ``A-01``. A live asset or attacker also carries
      ``quality``: the quality check's ``outcome`` (``clean``, ``advice``,
      ``defect``, ``question``, ``invalid``, or ``unchecked`` while none
      answers it as it stands), the ``warning``, the ``proposed`` correction
      or the ``question``, and the ``input_hash`` that
      ``apply_entity_proposals`` and ``answer_entity_question`` name.
    - ``attacker`` — the attacker with its factor decomposition, its
      ``surface_extent`` (``unset`` / ``point`` / ``whole``) and
      ``surface_extent_source``, which says whether a person attested it.
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
      layer — status / justification / linked CO IDs).
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
    ctx: Context,
) -> dict:
    """Soft-delete a single entity of any core type. Mutating: creates a
    new model version. Reversible with ``restore_entity`` using the same
    ``entity_type`` — the entity's ID is preserved (never reused) so a
    restore reinstates the same ID and all its links. To change an
    entity's fields instead of removing it, use the typed ``edit_*`` tool.

    Runs as a background job, reporting progress while it waits; a job a
    client stops waiting for finishes or fails on its own. A removal that
    is refused (the entity is not found or already deleted, or it is the
    last live asset or attacker) fails with the reason.

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
    - ``assumption`` — marked deleted (kept for the audit trail); its CO
      links are cleared and its attestations retired; controls whose
      ``assumption_groups`` name it keep their groups, which credit
      nothing through it while it is deleted.

    Returns ``{model, entities, controls_carried, controls_orphaned,
    orphaned_control_ids}``: the model's id, version and title, and the
    entity as removed.

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
        started = await client.start_remove_entity(model_id, entity_type, entity_id)
        return _entity_change(_dump(await _await_backend_job(
            client, started["job_id"], ctx, heartbeat=True)), entity_type, (entity_id,))
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
      structure intact. Its CO links are not restored (set them again
      with ``edit_assumption``), and re-attestation is required before it
      counts anywhere it is linked or grouped.

    Returns the entity-change result: ``{"model": {id, version, title},
    "entities", "controls_carried", "controls_orphaned",
    "orphaned_control_ids", ...}``, ``entities`` holding the entity as
    restored.

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
        return _entity_change(_dump(await restorer(model_id, entity_id)),
                              entity_type, (entity_id,))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_risk_view(
    server_version: str,
    scope: Literal["model", "tag"],
    scope_id: str,
) -> dict:
    """Prioritized Risk View — one row per live Control Objective — at a chosen scope. Read-only; no side effects.

    ``scope`` selects the aggregation boundary and how ``scope_id`` is interpreted:

    - ``"model"`` — a single threat model (``scope_id`` = model id). One row per live CO with derived risk tier, asset impact, attacker likelihood, control coverage counts (``coverage_ratio``), and open-finding count (``open_findings``). Tombstoned COs are excluded; pair with ``get_threat_model`` if historical context is needed. Use to triage which COs need attention on one model — a single call ranks the work, no per-CO fan-out.
    - ``"tag"`` — every member model of a tag (``scope_id`` = tag id). The same row shape with ``model_id`` and ``model_title`` added per row, so rows can be grouped by source model without an extra lookup, and delegation-aware (``delegation_mitigated`` / ``delegating_controls``): a CO mitigated via a verified cross-model delegation reads as covered, consistent with each model's own assessment. Use for a product, portfolio or audit-scope posture rollup.

    Args:
        scope: aggregation boundary — "model" or "tag".
        scope_id: id of the model or tag selected by ``scope``.
    """
    if scope not in ("model", "tag"):
        raise ToolError("scope must be 'model' or 'tag'.")
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.get_model_risk_view(scope_id))
        return _dump(await client.get_tag_risk_view(scope_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_compliance_report(
    server_version: str,
    scope: Literal["model", "tag"],
    scope_id: str,
    framework_id: str,
    level: Optional[int] = None,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 0,
) -> dict:
    """Compliance gap-analysis report for one framework at a chosen scope. Read-only; no side effects. Requires PRO tier.

    Evaluates every framework requirement against the mapped controls in scope and classifies each as covered, partial, uncovered, unmapped, or excluded, then returns coverage counts plus per-requirement rows. The framework must first be activated at the same scope via ``select_compliance_frameworks`` (with the matching ``scope``), otherwise there is nothing to report on.

    ``scope`` selects the boundary and how ``scope_id`` is read:

    - ``"model"`` — a single threat model (``scope_id`` = model id).
    - ``"tag"`` — rolled up across every member model of a tag (``scope_id`` = tag id).

    Filtering / pagination:

    - ``level`` — level filter for level-aware frameworks; returns only requirements at or below this level (e.g. 1 for L1 only). Omit (or 0) for all levels. Honored for all scopes.
    - ``status`` — one of "covered", "partial", "uncovered", "unmapped", "excluded"; empty = all statuses. **Model scope only.**
    - ``offset`` / ``limit`` — per-requirement row pagination; offset skips the first N rows, limit caps rows returned (0 = no explicit limit). **Model scope only.**

    A tag report is neither paginated nor status-filtered; passing ``status``, ``offset``, or ``limit`` with ``scope="tag"`` raises an error rather than silently returning unfiltered rows.

    Args:
        scope: report boundary — "model" or "tag".
        scope_id: id of the model or tag selected by ``scope``.
        framework_id: framework to report on (already selected at this scope; see ``list_compliance_frameworks``).
        level: optional level filter; omit for all levels.
        status: optional per-requirement status filter (model scope only).
        offset: skip the first N requirement rows, pagination (model scope only). Default 0.
        limit: max requirement rows to return, 0 = no explicit limit (model scope only).
    """
    if scope not in ("model", "tag"):
        raise ToolError("scope must be 'model' or 'tag'.")
    if scope == "tag" and (status or offset or limit):
        raise ToolError(
            "status/offset/limit are supported only for scope='model'; "
            "tag compliance reports are not paginated or status-filtered."
        )
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.get_compliance_report(
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
    scope: Literal["model", "tag"],
    scope_id: str,
    framework_ids: str,
) -> dict:
    """Select (activate) compliance frameworks at a chosen scope. Requires PRO tier. Mutating.

    Discover valid ids with ``list_compliance_frameworks`` (or add a custom one via ``import_compliance_framework``); view the resulting gap analysis with ``get_compliance_report`` at the same ``scope``. Re-calling replaces the scope's framework selection.

    ``scope`` selects the target and how ``scope_id`` is read:

    - ``"model"`` — a single threat model (``scope_id`` = model id). Activating a framework also kicks off background auto-remediation: it auto-maps existing controls to requirements, excludes non-applicable requirements by taxonomy, and suggests/applies new entities for the remaining gaps. The response includes ``auto_remediate_jobs``, which run and complete on their own; re-trigger later with ``auto_remediate_compliance`` if the model changes.
    - ``"tag"`` — a tag (``scope_id`` = tag id). Records the frameworks against the tag AND propagates them to every member model, and to every model added to the tag later, making the tag a compliance scope (e.g. an audit boundary) spanning several models.

    Args:
        scope: target boundary — "model" or "tag".
        scope_id: id of the model or tag selected by ``scope``.
        framework_ids: comma-separated framework ids (e.g. "asvs-4.0,nist-csf").
    """
    if scope not in ("model", "tag"):
        raise ToolError("scope must be 'model' or 'tag'.")
    parsed_ids = [f.strip() for f in framework_ids.split(",") if f.strip()]
    try:
        client = _get_client()
        if scope == "model":
            return _dump(await client.select_compliance_frameworks(scope_id, parsed_ids))
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
    """Export a threat model or a tag as a downloadable document. Read-only; no side effects on the source.

    ``scope`` selects what is exported and how ``scope_id`` is read; ``format`` selects the representation:

    - ``scope="model"`` (``scope_id`` = model id) supports ``format`` ∈ {``csv``, ``pdf``, ``html``, ``archive``}:
        - ``csv`` — the model's current state rendered as CSV; returned inline as UTF-8 text in ``content``.
        - ``pdf`` / ``html`` — rendered document returned base64-encoded in ``content_b64`` (with ``content_type``). Runs as a server-side job; progress is reported automatically while it completes, which may take time for large models.
        - ``archive`` — the self-contained, independently-verifiable JSON audit bundle of the model's current state: its latest version and controls, live assertions (with Tier 1 / Tier 2 verdicts and attested flags) and the runs behind them, open findings and those a person closed, risk acceptances and other decisions in force, assumption overrides, attestations, and instance sufficiency signatures; each control's per-clause evidence basis travels with it. Earlier versions, activity and chat are not in it. Those verdicts are the origin's record of what it claimed, which is what a third party checks against the signatures; an importing workspace credits what its own verification establishes (see ``import_threat_model_archive``). Returned as ``{..., "envelope": <dict>}``; feed the envelope to ``import_threat_model_archive`` to restore it into any workspace. **Model scope only.**
    - ``scope="tag"`` (``scope_id`` = tag id) supports only ``format="html"``: the signed auditor report, every member model's report after the reliance edges among the members (each with its status and whether it credits its objective), in one HTML document returned inline in ``content``. ``csv``, ``pdf``, and ``archive`` are rejected for tag scope.

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
async def list_groups(server_version: str) -> dict:
    """List the workspace's tags. Read-only; no side effects.

    A tag is a named, overlapping grouping of threat models, for audit
    scopes, products, ad-hoc selections or portfolios. A model may carry many
    tags, and a tag never affects posture or credit. Returns ``{"tags": [...]}``,
    each with ``id``, ``name``, ``description`` and ``model_ids``.

    Discover tag IDs here before the tag risk, compliance, dependency or
    export tools, or before adding/removing members. For a single model's
    tags use ``list_model_groups``.
    """
    try:
        return await _get_client().list_tags()
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def create_group(
    server_version: str,
    name: str,
    description: str = "",
    model_ids: list[str] | None = None,
) -> dict:
    """Create a tag, optionally with its first members. Mutating.

    A tag groups models for viewing and reporting without asserting any
    relationship between them and without moving credit. Names are unique
    within the workspace (409 on a clash). Every model named in ``model_ids``
    must be one the caller can access in this workspace.

    Args:
        name: the tag name (unique within the workspace).
        description: optional description.
        model_ids: optional initial member model ids.

    Returns the created tag.
    """
    try:
        return await _get_client().create_tag(name, description, model_ids or [])
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def add_model_to_group(
    server_version: str, group_id: str, model_id: str,
) -> dict:
    """Add a threat model to a tag. Mutating.

    Links the model into the tag without moving or copying it; the model
    stays independently editable, and may belong to many tags. The model
    takes on the compliance frameworks the tag selected, marked as the
    tag's, so removing a framework from the tag removes it from the model
    again; a framework the model selected itself is left as it is.

    Args:
        group_id: ID of the tag.
        model_id: ID of the threat model to add.

    Returns the updated tag.
    """
    try:
        return await _get_client().add_model_to_tag(group_id, model_id)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def get_group(server_version: str, group_id: str) -> dict:
    """Get one tag by ID, with its member model ids. Read-only; no side effects.

    Returns ``{id, workspace_id, name, description, created_at, model_ids}``.
    Discover tag IDs with ``list_groups``.

    Args:
        group_id: ID of the tag.
    """
    try:
        return await _get_client().get_tag(group_id)
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def delete_group(server_version: str, group_id: str) -> dict:
    """Delete a tag. Mutating; the member models are not affected.

    The tag's framework selections, requirement exclusions and relevance
    data are deleted with it. Frameworks it propagated to its members stay
    selected on them.

    Args:
        group_id: ID of the tag to delete.
    """
    try:
        await _get_client().delete_tag(group_id)
        return {"deleted": True, "group_id": group_id}
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def remove_model_from_group(
    server_version: str, group_id: str, model_id: str,
) -> dict:
    """Remove a model from a tag. Mutating; the model itself is not deleted.

    The frameworks the tag propagated to the model stay selected on it.

    Args:
        group_id: the tag.
        model_id: the model to remove.
    """
    try:
        await _get_client().remove_model_from_tag(group_id, model_id)
        return {"removed": True, "group_id": group_id, "model_id": model_id}
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def list_model_groups(server_version: str, model_id: str) -> dict:
    """List the tags a given model belongs to. Read-only; no side effects.

    A model may belong to many tags. Returns ``{model_id, tags: [...]}``. Use
    ``list_groups`` for every tag in the workspace.

    Args:
        model_id: the model whose tags to list.
    """
    try:
        return await _get_client().list_model_tags(model_id)
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
    """Per-CO reachability verdicts, over this model alone or the composed
    tree. Read-only; derived each time, never stored.

    ``composed=False`` (default): derived from this model's own structure
    (components, ``asset.component_ids``, ``trust_boundary.passes``, each
    attacker's ``trust_boundary_ids`` and vector, assumption exclusion
    predicates), deterministic, the derivation an auditor re-runs.
    ``co_id`` returns one verdict (404 if absent or tombstoned). Returns
    ``{model_id, model_version, verdicts: [{co_id, kind, reason, narration,
    boundary_id?, assumption_id?}]}``; ``kind`` is ``reachable``,
    ``unreachable`` or ``indeterminate``.

    ``composed=True``: the same derivation over the model with everything
    it inherits from its ancestors, for a child on the composition tree.
    Paginated (``page``, ``page_size``); ``kind_filter`` keeps one kind;
    ``co_id`` is ignored. Returns ``{model_id, flag_enabled, verdicts:
    [{co_qid, asset_qid, attacker_qid, kind, reason}], total, page,
    page_size}``, empty with ``flag_enabled: false`` where composition is
    not available.

    An indeterminate verdict names the missing structure:
    ``attacker_unpositioned`` (``edit_attacker`` with
    ``trust_boundary_ids``), ``asset_unbounded``
    (``assign_to_components(target_type="asset")``), ``no_shared_boundary``
    (reposition the attacker, rescope the asset, or an ``add_assumption``
    exclusion), ``missing_entity`` (restore it, or remove the CO).
    ``model_coherence_report`` presents the same gaps as findings.
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

_RECOMPUTE_MODES = ("quote", "recompute", "retry_parked")


@mcp.tool()
async def recompute_verdicts(
    server_version: str,
    model_id: str,
    mode: Literal["quote", "recompute", "retry_parked"] = "quote",
) -> dict:
    """Estimate, force, or retry a model's verdict evaluation.

    - ``mode="quote"`` (default): read-only. The cost of a recompute,
      enqueueing nothing: ``{estimated_credits, computed_at, rate_version,
      informational, total_enqueueable, already_evaluated, governor}``.
      Subjects already carrying a verdict cost nothing, so it is an upper
      bound. Show the operator this number before recomputing: on a large
      model it runs to thousands of credits.
    - ``mode="recompute"``: mutating. Queues a fresh evaluation of every
      control's coverage verdict and every live objective's
      group-sufficiency verdict, bypassing quiet-period batching; usage is
      metered as it runs. Returns ``{model_id, model_version,
      enqueued_coverage, enqueued_group_sufficiency, total_enqueued,
      estimated_credits, quote, governor}``.
    - ``mode="retry_parked"``: re-runs only the verdicts a transient failure
      (outage, exhausted credits, timeout) parked, of every kind, including
      per-control sufficiency and coherence; nothing else is touched.
      Returns ``{model_id, model_version, retried_slots, governor}``.

    Work runs in the background; when ``governor.exhausted`` it is queued and
    resumes at ``governor.resets_at``, never dropped.

    A recompute evaluates COVERAGE and GROUP SUFFICIENCY only. A control at
    ``partially_verified``, or ``coherence_status: "pending"`` on an
    assertion, is not a reason to recompute: that verdict is computed on
    assertion write and read with ``get_sufficiency``. Recompute when
    control-to-CO mappings look wrong (``get_verdict_divergence``). One
    objective awaiting judgement is ``judge_objective``.
    """
    if mode not in _RECOMPUTE_MODES:
        raise ToolError(f"mode must be one of {', '.join(_RECOMPUTE_MODES)}.")
    try:
        client = _get_client()
        if mode == "quote":
            return _dump(await client.get_recompute_quote(model_id))
        if mode == "retry_parked":
            return _dump(await client.retry_verdicts(model_id))
        return _dump(await client.recompute_verdicts(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc

@mcp.tool()
async def judge_objective(
    server_version: str,
    model_id: str,
    co_id: str,
) -> dict:
    """Have one control objective's mitigation group judged. Mutating —
    queues background work and may consume credits.

    Use this for an objective whose ``risk_reason`` is ``awaiting_judgement``:
    it has a built mitigation group and nothing has decided whether that group
    covers the objective — never evaluated, evaluated against inputs that have
    since changed, or the answer parked. The objective is not short of
    controls, so generating or implementing more will not move it; what is
    missing is the judgement.

    **This is not a repair.** The judgement can come back insufficient, which
    moves the objective to ``coverage_gap`` / ``insufficient_by_design`` and
    names real work. That is the tool doing its job: it replaces "nobody has
    looked" with an answer, and the answer may be no.

    Scoped to ONE objective, which is the difference that matters against
    ``recompute_verdicts``: that tool force-enqueues every control's coverage
    verdict AND every live objective's group-sufficiency verdict, which on a
    large model runs to thousands of credits. This queues a single judgement.
    Any credits it consumes are metered at actuals as the work runs, like
    every other metered call — the account's usage is visible in its billing
    panel before and after.

    Judging runs in the BACKGROUND; the call returns as soon as the work is
    queued. Re-read ``get_mitigation_groups`` (or ``assess_model`` /
    ``get_risk_view``) shortly after to see the objective's new state. Calling
    again while a judgement is already queued is harmless and does not queue a
    second one.

    A refusal comes back as data rather than an error, so it can be relayed:

    - ``{queued: false, http_status: 409, ...}`` — controls are still being
      generated for this model. Poll ``get_control_generation_status`` until
      terminal, then call again.
    - ``{queued: false, http_status: 503, ...}`` — judging is unavailable on
      this deployment.
    - ``{queued: false, http_status: 402, code, message}`` — the balance this
      workspace bills to cannot cover the judgement.

    Args:
        model_id: ID of the threat model.
        co_id: ID of the control objective to have judged (e.g. "CO5").

    Returns ``{model_id, model_version, co_id, queued, state, hint,
    governor, billing}``. ``state`` is ``queued`` (a judgement is now in
    flight) or ``already_fresh`` (a current judgement already exists for this
    objective's present inputs — nothing was queued and nothing is charged).
    """
    if not model_id or not model_id.strip():
        raise ToolError("model_id is required and must be non-empty.")
    if not co_id or not co_id.strip():
        raise ToolError("co_id is required and must be non-empty.")
    try:
        return _dump(
            await _get_client().judge_objective(model_id.strip(), co_id.strip()),
        )
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
    """Entities a child model authored that look like ones it inherits.
    Read-only.

    Use on a child model in a recursive tree to find duplicates before they
    distort coverage; decide each with ``decide_reconciliation_candidate``.

    - ``disposition="active"`` (default): the open queue, paginated
      (``page``, ``page_size``). ``{model_id, flag_enabled, total, tiers:
      {certain, heuristic}, page, page_size, candidates: [{kind, own_qid,
      inherited_qid, tier, reasons}]}``. Tier ``certain`` is a deterministic
      match, safe to apply; ``heuristic`` is a fuzzy name/description match
      that needs review. Rejected pairs are left out.
    - ``disposition="rejected"``: the pairs recorded as NOT duplicates, oldest
      first and not paginated: ``{model_id, flag_enabled, rejections: [{id,
      model_id, kind, own_qid, inherited_qid, rejected_by, rejected_at}]}``.
      An ``id`` is what an unreject names.

    Where composition is not available both come back empty with
    ``flag_enabled: false``.
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
async def undo_composition_event(
    server_version: str,
    model_id: str,
    event_type: str,
    event_id: str,
    dry_run: bool = True,
) -> dict:
    """Preview, and on confirmation apply, the undo of a lift or split.

    ``event_type`` is ``lift`` or ``split``; ``event_id`` is the forward
    ``lift_applied`` / ``split_applied`` activity event's id, or the
    ``lift_id`` / ``split_id`` in its payload. ``model_id`` is the model the
    event was raised on (another model's event is 404).

    By default (``dry_run=True``) it is read-only: ``{plan, refusal}``, exactly
    one non-null. ``plan`` lists the inverse operations an undo would commit
    (lift: tombstone the LCA entity, restore the source copies, rewrite CO
    references; split: restore at the ancestor, tombstone the target
    copies). ``refusal`` lists why it cannot: state has moved since the event
    (assertions submitted on the entity, objectives referencing it, an
    edit). Show it to the operator.

    With ``dry_run=False`` it is mutating, after explicit confirmation: the
    divergence check runs again (409 with ``detail.refusal.reasons`` when it
    refuses), the inverse is persisted across every affected model, and a
    ``lift_undone`` / ``split_undone`` event citing ``original_event_id`` is
    recorded. Returns ``{undone_event_id, original_event_id,
    applied_state_ops, models}``; ``models`` is ``{lca_model,
    source_descendant_models}`` for a lift and ``{ancestor_model,
    descendant_models}`` for a split, each model its id, version and title.

    503 where composition is not available.
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
        if dry_run:
            if kind == "lift":
                return _dump(await client.preview_lift_undo(model_id, event_id))
            return _dump(await client.preview_split_undo(model_id, event_id))
        if kind == "lift":
            result = await client.undo_lift(model_id, event_id)
        else:
            result = await client.undo_split(model_id, event_id)
        return _without_models(_dump(result))
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
    ``get_functional_coverage``; for the actionable gaps pass it
    ``gaps_only=True``.

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
    """A model's controls, or one control. Read-only.

    Without ``control_id``: ``{controls, total, returned}``, the published
    set, filtered by ``status``, ``co_id`` and ``component_id`` and paged by
    ``offset`` / ``limit``. Orphaned controls (every mapped CO tombstoned)
    are left out unless ``include_orphaned=True``, soft-deleted ones unless
    ``include_deleted=True``. ``summary_only=True`` returns only id,
    description, status, verification_status, assertion_count, co_ids,
    assumption_groups and attestation_dependency. An empty list on a new
    model means its proposed build was never started
    (``get_control_generation_status``); while a build holds the model the
    list is the last published set, with a ``building`` marker.

    With ``control_id``: that control, with an ``orphaned`` flag; ``version``
    reads it as of a model version (0 = latest).

    An objective id on a control is an ATTACHMENT, not credit: only a member
    of a required mitigation group earns any, and a control that is
    defense-in-depth everywhere can be implemented and verified without
    moving an objective. Read ``get_mitigation_groups`` before evidence work.

    ``status`` is the operator's (``not_implemented`` / ``implemented`` /
    ``verified``); ``verification_status`` is the EVIDENCE: ``verified``
    (both tiers pass and the assertions cover the whole description),
    ``partially_verified`` (a tier failed, clauses are unproven, or an
    attestation EXPIRED — ``get_sufficiency`` says which; the fix is more
    assertions or a narrower description, never a recompute), ``pending``,
    ``unverified`` (none submitted). A for-all clause is credited only by a
    sound type bound with ``covers``; ``get_control_work_order`` lists what
    each clause needs. ``status="implemented"`` finds what still needs
    evidence. Only this model's own controls are listed; inherited ones are
    counted by ``assess_model``.
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
    every referenced component exists on the model. An asset's answer
    carries the model's id, version and title, and ``entities.assets`` the
    asset as it now stands.

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
            result = _entity_change(await client.assign_asset_to_components(
                model_id, target_id, parsed, change_reason.strip(),
            ), "asset", (target_id,))
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
      ``submit_assertions`` (``functional_test_id``) with TEST_EXISTS + TEST_ATTESTED
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
    or attacker anchor. It creates no new model version: the re-validation is
    queued and runs in the background, and the refreshed warnings appear on the
    next read of the model.

    May consume credits for the entities that need the deeper review; a model
    already in good shape costs nothing. Returns at once with
    ``{"accepted": true, "queued": <entities queued>, "model": {...}}``, where
    ``model`` is the id, version and title of the model as it stands before
    the re-validation lands.

    Args:
        model_id: ID of the threat model whose assets and attackers to
            re-validate.
    """
    try:
        return _without_models(_dump(await _get_client().revalidate_entities(model_id)))
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


# === Agent work orders, reconcile, proposals, design leverage, provenance ===


@mcp.tool()
async def get_control_work_order(
    server_version: str,
    model_id: str,
    control_id: str,
) -> dict:
    """The work order for one control: the ticket to read BEFORE
    implementing it. Read-only.

    Returns ``{model_id, model_version, control, objectives, max_tier,
    scan_brief, assertion_contract, acceptance_criteria, required_evidence,
    steps, reconcile_rules, delegation, open_proposals, provenance}``:
    where to look, what counts as proof (``assertion_contract``: the types
    by soundness class, the evidence and ``universal_rule``, the
    ``sound_types`` the platform takes, what to submit with, when the
    control counts as verified), what to do when the code disagrees with
    the model, what this agent may decide alone (``delegation``), and
    whether code or description is authoritative (``provenance``).

    Where the order names a required class for a clause,
    ``required_evidence`` holds one entry per such clause: its ``clause``,
    the ``clause_id`` to put in ``covers``, its ``quantifier``, the
    ``required_class``, what is ``missing``, and a ``suggested_submission``
    skeleton. The skeleton is a fill-in, not a submission: replace its
    ``<...>`` placeholders; one left unfilled is refused, by this client and
    again by the platform, since it would record a claim nothing backs. A
    for-all clause takes ``[by_construction, sound_over_approximation]``:
    prefer ``typed_boundary`` (the type the sinks accept, its
    constructors), else ``sink_default_deny`` (the sinks, the safe forms, a
    reviewed allowlist). When the bound evidence is the wrong CLASS,
    ``missing`` says so. ``acceptance_criteria`` is GENERATED from those
    entries, so a clause that must hold at every site reads as such and no
    number of tests closes it.

    A type's ``soundness`` is the class to branch on; ``behavioral`` is a
    compatibility field for readers written before the classes.
    """
    try:
        return await _get_client().get_control_work_order(model_id, control_id)
    except Exception as exc:
        raise _api_error(exc) from exc


def _parse_path_list(raw: Optional[str]) -> List[str]:
    """Split a comma- or newline-separated path list into a clean list."""
    if not raw:
        return []
    out: List[str] = []
    for chunk in raw.replace("\r", "\n").split("\n"):
        for item in chunk.split(","):
            item = item.strip()
            if item:
                out.append(item)
    return out


_RECONCILE_OBSERVATION_KINDS = (
    "mechanism_named", "component_present", "component_absent", "forbidden_behavior",
)


@mcp.tool()
async def reconcile_model(
    server_version: str,
    model_id: str,
    changed_paths: Optional[str] = None,
    repo_url: str = "",
    observations: Optional[str] = None,
) -> dict:
    """Reconcile a threat model with the code it describes. Call this after
    reading the code and before (or instead of) editing the model by hand:
    report what changed and what you observed, and the platform decides the
    consequence of each observation. Mutating only where the platform
    applies an observation (see below).

    Two inputs, both optional:

    - ``changed_paths``: the file paths that changed since the model's
      recorded commit. For a code-derived model compute them with
      ``git diff --name-only <commit_sha>..HEAD`` (the ``commit_sha`` from
      the model's provenance). The platform maps them onto components and
      reports which components changed, which paths no component claims,
      and whether a refresh is recommended.
    - ``observations``: what you saw in the code that the model does not
      say. Each observation lands in one of four buckets by ``kind``:

      * ``mechanism_named`` - the control's mechanism exists under another
        name (``subject_id`` = control id). Follow up with ``refine_control``
        using the ``codebase_findings`` returned in ``refine_suggested``.
      * ``component_present`` - the code has a component the model lacks;
        include a ``proposal`` (``{name, repo_url?, path?,
        trust_boundary_ids?}``).
      * ``component_absent`` - a modelled component has no code
        (``subject_id`` = component id).
      * ``forbidden_behavior`` - the code does something the model rules
        out (``subject_id`` = control id, or empty).

    The platform decides the consequence. Proposals are never applied on
    the agent's word, with one exception: a component change on a
    code-derived model (provenance ``kind="code"``) is applied immediately
    and queued for a person's review as ``applied_pending_review``. Every
    other proposal waits for ``decide_proposal``. Forbidden behaviors
    become findings. Observations the platform could not use come back in
    ``ignored`` with the reason.

    Args:
        model_id: ID of the threat model.
        changed_paths: Comma- or newline-separated file paths that changed
            since the model's recorded commit. Empty/None skips path mapping
            (``changed_paths`` in the response is then null).
        repo_url: Repository the paths belong to (optional; helps map paths
            in multi-repo models).
        observations: JSON string of an **array** of observation objects,
            each ``{kind, subject_id?, evidence?: {paths?: [], symbols?: [],
            note?: ""}, proposal?: {name, repo_url?, path?,
            trust_boundary_ids?}}`` with ``kind`` one of ``mechanism_named``,
            ``component_present``, ``component_absent``,
            ``forbidden_behavior``. Empty/None sends no observations.

    Returns ``{model_id, model_version, provenance{kind, authoritative,
    code_derived, ...}, changed_paths: null | {components_changed[{
    component_id, name, changed_files, sample_paths, live_controls}],
    unmapped_paths[], unmapped_count, refresh_recommended},
    refine_suggested[{control_id, current_description, open_assumptions,
    codebase_findings, next}], proposals[], findings[], ignored[{index,
    reason}]}``.
    """
    paths = _parse_path_list(changed_paths)
    parsed_obs: List[dict] = []
    if observations is not None and observations.strip():
        try:
            parsed_obs = json.loads(observations)
        except json.JSONDecodeError as exc:
            raise ToolError(
                "observations must be a JSON array of observation objects."
            ) from exc
        if not isinstance(parsed_obs, list):
            raise ToolError("observations must be a JSON array of observation objects.")
        for i, obs in enumerate(parsed_obs):
            if not isinstance(obs, dict):
                raise ToolError(f"observations[{i}] must be an object.")
            kind = obs.get("kind")
            if kind not in _RECONCILE_OBSERVATION_KINDS:
                raise ToolError(
                    f"observations[{i}].kind must be one of "
                    f"{', '.join(_RECONCILE_OBSERVATION_KINDS)}."
                )
            if "evidence" in obs and obs["evidence"] is not None and not isinstance(obs["evidence"], dict):
                raise ToolError(f"observations[{i}].evidence must be an object.")
            if "proposal" in obs and obs["proposal"] is not None and not isinstance(obs["proposal"], dict):
                raise ToolError(f"observations[{i}].proposal must be an object.")
    if not paths and not parsed_obs:
        raise ToolError("Provide changed_paths, observations, or both.")
    try:
        return await _get_client().reconcile_model(
            model_id, paths, repo_url=repo_url, observations=parsed_obs,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


_PROPOSAL_KINDS = ("add_component", "remove_component", "design_change", "assumption",
                   "drift_intent", "description_revision")


def _parse_json_object(raw: str, name: str, required: bool) -> dict:
    """Parse a JSON-object string tool param; empty is ``{}`` when optional."""
    if not raw or not raw.strip():
        if required:
            raise ToolError(f"{name} must be a JSON object.")
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolError(f"{name} must be a JSON object.") from exc
    if not isinstance(parsed, dict):
        raise ToolError(f"{name} must be a JSON object.")
    return parsed


@mcp.tool()
async def create_proposal(
    server_version: str,
    model_id: str,
    kind: str,
    payload: str,
    rationale: str,
    evidence: str = "",
) -> dict:
    """Raise a proposal to change a model's scope or design. Call this when
    the code or your analysis says the model should gain or lose a
    component, or that an attacker position or asset should be removed by
    design; do not edit the model directly for those changes. Mutating:
    persists a proposal record.

    A proposal is a change of scope or design. Raising one is not deciding
    it: a person (or an agent under a delegation rule that names the
    decision) decides it with ``decide_proposal``. Design changes are never
    applied automatically. Poll ``list_proposals`` for the outcome.

    Args:
        model_id: ID of the threat model.
        kind: One of ``add_component`` (payload ``{name, repo_url?, path?,
            trust_boundary_ids?}``), ``remove_component`` (payload
            ``{component_id}``), ``design_change`` (payload ``{target_kind:
            "attacker"|"asset", target_id, design_move}``; take ``design_move``
            from ``get_design_leverage``), ``assumption`` (payload ``{co_id,
            group_id, precondition, assumption_id?, gap?}``: a precondition
            about the environment that only something outside this system
            can meet, one declarative sentence; ``assumption_id`` names an
            existing assumption that states it). A precondition a person
            already rejected for that objective is refused.
            ``drift_intent`` (payload ``{finding_id, intent: "intended" |
            "defect", control_id?, head_commit?}``): whether a
            description-drift finding was intended (the description is
            behind the product) or a defect of the code, naming for a defect
            the control whose passing assertion closes it.
            ``description_revision`` (payload ``{description, commit_sha?,
            finding_ids?}``): the whole description revised to what the code
            at that commit does, addressing those drift findings; accepting it
            writes the new text and extracts the behavioural model again over
            it, billed to whoever accepts. A revision that changes the
            sentence of a finding decided a defect is accepted only by a
            person. Propose one where ``get_behavioural_model``'s
            ``drift.revision_suggested`` is true.
        payload: JSON object string with the fields for ``kind``.
        rationale: Why this change is right (what in the code or design
            supports it).
        evidence: Optional JSON object string, e.g. ``{paths: [], symbols:
            [], note: ""}``, pointing at what you saw.

    Returns ``{proposal, created}``.
    """
    if kind not in _PROPOSAL_KINDS:
        raise ToolError(f"kind must be one of {', '.join(_PROPOSAL_KINDS)}.")
    if not rationale.strip():
        raise ToolError("rationale is required.")
    parsed_payload = _parse_json_object(payload, "payload", required=True)
    parsed_evidence = _parse_json_object(evidence, "evidence", required=False)
    try:
        return await _get_client().create_proposal(
            model_id, kind, parsed_payload, rationale.strip(),
            evidence=parsed_evidence,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def list_proposals(
    server_version: str,
    model_id: str,
    status: str = "",
) -> dict:
    """List proposals and escalations on a model. Call this to poll the
    outcome of a proposal you raised, or of a judgment you were refused.
    Read-only; no side effects.

    Statuses: ``proposed`` and ``applied_pending_review`` are open;
    ``accepted``, ``rejected``, ``reverted``, ``superseded`` are closed.
    Kinds include ``add_component``, ``remove_component``,
    ``design_change``, ``assumption``, and ``decision_request``: an
    escalation of a judgment this agent was refused. A 403 from
    ``update_finding``, ``create_risk_acceptance``, ``submit_attestation``
    or ``decide_proposal`` carries an
    ``escalation_id``; that escalation appears here as a
    ``decision_request``. An attestation refused does not 403: the edit of
    ``edit_trust_boundary``, ``edit_attacker`` or ``add_attacker`` lands
    unattested and its answer's ``attestation`` carries the
    ``escalation_id``, bound to the content it was parked over (an edit of
    that content supersedes it). Poll it here until a person resolves it;
    do not retry the refused call.

    An open row may carry ``shows``: what accepting it does, as the person
    deciding it is shown it (a parked act on the behavioural model with each
    answer beside its question, whether accepting extracts and at what
    estimate; a revision's sentences removed and added; a drift finding's
    sentence). Words a program wrote are inside a bounded region, as data.

    Args:
        model_id: ID of the threat model.
        status: Optional status filter (one of the values above). Empty
            (default) returns every proposal.

    Returns ``{model_id, model_version, items[], count}``.
    """
    try:
        return await _get_client().list_proposals(model_id, status=status)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def decide_proposal(
    server_version: str,
    model_id: str,
    proposal_id: str,
    decision: str,
    note: str = "",
    expires_at: str = "",
    record_only: bool = False,
) -> dict:
    """Accept or reject a proposal. Call this only when the workspace's
    delegation policy names this decision for this agent at the proposal's
    tier (the ``delegation`` block of ``get_control_work_order`` says what
    you may decide). Mutating: closes the proposal and applies an accepted
    change.

    This is a judgment. The call is refused with HTTP 403 and an
    ``escalation_id`` unless the delegation policy permits it; the refusal
    parks the decision for a person as a ``decision_request``. Do not retry
    a refusal: report the ``escalation_id``, poll ``list_proposals`` for the
    outcome, and continue other work.

    Accepting an ``assumption`` proposal accepts the assumption: it is
    created if new, attested until ``expires_at`` and bound into the group
    that waited on it, which is then judged again. That is its own decision
    (``assumption_accepted``); a rule delegating proposal acceptance does not
    cover it. Rejecting one records the precondition as rejected for that
    objective, so it is not proposed again, and the objective keeps its gap.

    Args:
        model_id: ID of the threat model.
        proposal_id: ID of the proposal to decide.
        decision: ``accept`` or ``reject``.
        note: Optional note recorded with the decision.
        expires_at: ISO 8601 date an accepted assumption lapses (e.g.
            "2027-03-29T00:00:00Z"). Applies to accepting an ``assumption``
            proposal; omitted, the acceptance lasts a year.
        record_only: Accepting parked answers to behavioural questions
            starts the extraction they complete, billed to whoever accepts;
            True records them without it. Default False.

    Returns ``{proposal, effect}``.
    """
    if decision not in ("accept", "reject"):
        raise ToolError("decision must be 'accept' or 'reject'.")
    try:
        return await _get_client().decide_proposal(
            model_id, proposal_id, decision, note=note, expires_at=expires_at,
            **({"record_only": True} if record_only else {}),
        )
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def decide_drift_intent(
    server_version: str,
    model_id: str,
    finding_id: str,
    intent: str,
    control_id: str = "",
    head_commit: str = "",
    note: str = "",
) -> dict:
    """Decide whether a description-drift finding (the code reported to do
    more, or less, than a sentence of the description) was intended or is a
    defect of the code. Mutating; a judgment.

    ``intended``: the description is behind the product; revise it
    (``create_proposal`` kind ``description_revision``). ``defect``: the
    description is the design and the code is wrong; name in ``control_id``
    the control whose assertions check the behaviour as designed. The finding
    closes when one of its assertions passes verification at a commit not
    earlier than this decision, and while it stands an answer that would
    write the defect into the model is refused (409 ``drift_is_defect``).

    A program's decision is refused with 403 and an ``escalation_id`` unless
    the workspace's delegation policy names ``drift_intent_decided``: do not
    retry; report it, or raise a ``drift_intent`` proposal for a person.

    Args:
        model_id: ID of the threat model.
        finding_id: The description-drift finding (``list_findings``).
        intent: ``intended`` or ``defect``.
        control_id: For a defect, the control whose passing assertion closes it.
        head_commit: The commit you read the code at.
        note: Why.
    """
    if intent not in ("intended", "defect"):
        raise ToolError("intent must be 'intended' or 'defect'.")
    if intent == "defect" and not control_id.strip():
        raise ToolError("a defect names the control whose passing assertion closes it.")
    try:
        return await _get_client().decide_drift_intent(
            model_id, finding_id, intent, control_id=control_id.strip(),
            head_commit=head_commit.strip(), note=note)
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_design_leverage(
    server_version: str,
    model_id: str,
    include_design_moves: bool = False,
    top: int = 5,
) -> dict:
    """Rank what eliminating each attacker position or asset BY DESIGN
    would remove from the matrix. Call this when deciding whether to
    change the design instead of implementing controls: it shows which
    single design change retires the most critical and high at-risk
    objectives. Read-only; no side effects.

    Each row in ``ranked`` is an attacker or asset with the objectives its
    removal would take out of the matrix (``objectives_removed``, broken
    down by tier in ``removes``), how many of those are currently at risk
    (``removes_at_risk`` / ``removes_at_risk_by_tier``), and the controls
    that would be retired. Rows are ranked by critical, then high, at-risk
    objectives removed. ``design_move`` (a concrete change of design that
    would eliminate the row) is filled only when ``include_design_moves``
    is true. To act on a row, raise a ``design_change`` proposal with
    ``create_proposal``; never apply a design change yourself.

    Args:
        model_id: ID of the threat model.
        include_design_moves: Also author a ``design_move`` per row.
            Default False.
        top: Number of rows to return. Default 5.

    Returns ``{model_id, model_version, at_risk_total, objectives_total,
    ranked[{kind: "attacker"|"asset", id, name, objectives_removed,
    removes{critical, high, medium, low}, removes_at_risk,
    removes_at_risk_by_tier, controls_retired[], design_move}], next}``.
    """
    try:
        return await _get_client().get_design_leverage(
            model_id, include_design_moves=include_design_moves, top=top,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


_DECISION_KINDS = (
    "finding_dismissed",
    "finding_remediated",
    "risk_accepted",
    "not_applicable_declared",
    "proposal_accepted",
    "proposal_rejected",
    "proposal_reverted",
    "assumption_accepted",
    "behavioural_model_answered",
    "behavioural_model_confirmed",
    "behavioural_delta_declared",
    "behavioural_cross_check_dismissed",
    "behavioural_confirmation_withdrawn",
    "seal_attested",
    "position_attested",
    "privileges_attested",
    "extent_attested",
    "escalation_resolved",
    "drift_intent_decided",
    "description_revised",
    "inventory_pair_decided",
    "inventory_tag_declared",
)


@mcp.tool()
async def list_decisions(
    server_version: str,
    model_id: str,
    agent_only: bool = False,
    outside_policy_only: bool = False,
    decision: str = "",
    limit: int = 0,
) -> dict:
    """List the decision ledger of a model: every judgment recorded on it
    (finding dismissed or remediated, risk accepted, not-applicable
    declared, proposal accepted / rejected / reverted, assumption accepted,
    behavioural model answered / confirmed, a control's delta declared, a
    finding of its cross-check dismissed, a seal, position, privileges or
    surface extent attested, escalation resolved, an inventory pair decided
    or an entity's tags declared), newest first, with who made it and
    whether it was within the workspace's delegation policy. Read-only; no
    side effects.

    Call this BEFORE raising a proposal or asking for a judgment, so you
    do not propose what a person rejected or ask again for what was
    already decided.

    The ledger is append-only. There is no tool that edits it; to undo an
    accepted proposal, revert or re-decide, never edit the record. Rows
    with ``outcome == "refused"`` are judgments a program was refused;
    their escalation, if any, is in ``list_proposals``. ``agent`` is null
    for a person's decision.

    Args:
        model_id: ID of the threat model.
        agent_only: Only decisions made by a program (``agent`` not null).
            Default False.
        outside_policy_only: Only decisions made outside the delegation
            policy in force at the time (``within_policy`` false).
            Default False.
        decision: Optional kind filter, one of ``finding_dismissed``,
            ``finding_remediated``, ``risk_accepted``,
            ``not_applicable_declared``, ``proposal_accepted``,
            ``proposal_rejected``, ``proposal_reverted``,
            ``assumption_accepted``, ``behavioural_model_answered``
            (an answer, an element edit or a link declared),
            ``behavioural_model_confirmed``, ``behavioural_delta_declared``,
            ``behavioural_cross_check_dismissed`` (a person set aside a
            finding of a declaration's cross-check),
            ``behavioural_confirmation_withdrawn`` (a confirmation withdrawn
            by a report that the code does more than the description),
            ``seal_attested``, ``position_attested``, ``privileges_attested``,
            ``extent_attested``, ``escalation_resolved``,
            ``drift_intent_decided`` (whether a description-drift finding was
            intended or a defect of the code), ``description_revised`` (a
            revised description accepted), ``inventory_pair_decided`` (two
            inventory entries decided one entity or not),
            ``inventory_tag_declared`` (an entity's taxonomy tags declared).
            Empty (default) returns every kind.
        limit: Maximum rows to return. 0 (default) uses the server default.

    Returns ``{model_id, model_version, items[{id, decision, subject_kind,
    subject_id, outcome, principal_user_id, agent: null | {kind, client_id,
    name}, policy_version, within_policy, rationale, created_at}], count,
    total}``.
    """
    if decision and decision not in _DECISION_KINDS:
        raise ToolError(f"decision must be one of {', '.join(_DECISION_KINDS)}.")
    try:
        return await _get_client().list_decisions(
            model_id,
            agent_only=agent_only,
            outside_policy_only=outside_policy_only,
            decision=decision,
            limit=limit,
        )
    except Exception as exc:
        raise _api_error(exc) from exc


# === Behavioural model ===
#
# A behavioural model states what the system does: its elements, the actions
# on them and the zones they sit in, extracted from the model's description.
# The possible threats the platform finds are read from it.


def _json_value(raw: str, name: str, kind: type, example: str) -> Any:
    """``raw`` parsed as JSON of type ``kind``, or a refusal that shows the
    shape expected."""
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ToolError(f"{name} must be valid JSON, e.g. {example}") from exc
    if not isinstance(value, kind):
        raise ToolError(f"{name} must be a JSON {'array' if kind is list else 'object'}, e.g. {example}")
    return value


#: The reads of the behavioural model, and the bounds the API takes for
#: them: a wait of at most 50 seconds, a page of at most 200 questions (50 by
#: default), and the threats read's page of at most 200 objectives (25 by
#: default).
_BEHAVIOURAL_VIEWS = ("full", "status", "questions")
_WAIT_MAX_SECONDS = 50
_QUESTIONS_PAGE_DEFAULT = 50
_THREATS_PAGE_DEFAULT = 25
_PAGE_MAX = 200
#: The longest one read of a wait lasts, so progress reaches the client
#: between reads.
_WAIT_SLICE_SECONDS = 10


def _extraction_job(read: dict) -> Optional[dict]:
    job = (read.get("extraction") or {}).get("job") if isinstance(read, dict) else None
    return job if isinstance(job, dict) else None


def _job_signature(job: Optional[dict]) -> tuple:
    """What a wait watches of the extraction job, as the API does: its state,
    its pass and the calls it has completed."""
    if job is None:
        return (None,)
    progress = job.get("progress") or {}
    return (job.get("state"), progress.get("pass"), progress.get("calls_completed"))


def _job_message(job: Optional[dict]) -> str:
    """The extraction job in words, as a progress notification carries it:
    ``call 3 of 5: actions``, with the estimated finish once there is one."""
    if job is None:
        return "extraction finished"
    state = job.get("state") or ""
    if state != "running":
        return f"extraction {state}" + (f": {job['error']}" if job.get("error") else "")
    progress = job.get("progress") or {}
    completed = int(progress.get("calls_completed") or 0)
    call = completed + (1 if progress.get("call_started_at") else 0)
    if not call:
        return "extraction running"
    expected = progress.get("calls_expected")
    message = f"call {call}" + (f" of {expected}" if expected else "")
    if progress.get("pass"):
        message += f": {progress['pass']}"
    if progress.get("estimated_finish"):
        message += f", estimated finish {progress['estimated_finish']}"
    return message


async def _wait_for_extraction(client: MipitiClient, model_id: str, wait_seconds: int,
                               ctx: Context) -> None:
    """Wait up to ``wait_seconds`` for the model's extraction job to change
    its state, pass or calls completed, reading it a slice at a time and
    reporting each read through the client's progress channel. Returns at
    once when no job is queued or running: a failed one moves only when it
    is asked for again."""
    deadline = time.monotonic() + wait_seconds
    job = _extraction_job(await client.get_behavioural_model(model_id, view="status"))
    if job is None or job.get("state") not in ("queued", "running"):
        return
    seen = _job_signature(job)
    sent = 1
    await _safe_report_progress(ctx, sent, None, _job_message(job))
    while True:
        left = int(deadline - time.monotonic())
        if left < 1:
            return
        job = _extraction_job(await client.get_behavioural_model(
            model_id, view="status", wait_seconds=min(_WAIT_SLICE_SECONDS, left)))
        sent += 1
        await _safe_report_progress(ctx, sent, None, _job_message(job))
        if _job_signature(job) != seen:
            return


@mcp.tool()
async def get_behavioural_model(
    server_version: str,
    model_id: str,
    ctx: Context,
    view: Literal["full", "status", "questions"] = "full",
    wait_seconds: int = 0,
    offset: int = 0,
    limit: int = _QUESTIONS_PAGE_DEFAULT,
) -> dict:
    """Read a model's behavioural model: what the system does, as elements,
    actions and zones taken from its description. Read-only.

    ``status``: ``none`` (``extract_behavioural_model`` gives it one),
    ``needs_answers``, ``extracted``, ``confirmed``, ``stale`` (the
    description changed since) or ``extracting``. ``questions`` are the open
    ones, answered with ``answer_behavioural_questions``; one carrying
    ``structured`` takes a structured answer, one with ``awaiting_fix`` was
    answered. ``pending_answers``: collected, not extracted. ``ir_hash`` is
    what ``confirm_behavioural_model`` names. ``waiting_on``:
    ``extraction``, ``acceptance``, ``answers``, ``generation`` or
    ``nothing``. ``extraction.job``: the extraction running in the
    background (null when none), its ``progress`` (pass, calls done and
    expected, estimated finish); ``extraction.dropped_elements``: what it
    could not keep, with the sentence to answer. ``generation_ready``: call
    ``generate_from_behavioural_model``.

    ``view="status"`` serves no IR and no questions: use it to follow an
    extraction. ``view="questions"``: that and the open questions from
    ``offset``, ``limit`` of them (default 50, at most 200), with ``total``
    and ``next_offset``. ``wait_seconds`` (0 to 50) waits for the job's
    state, pass or calls completed to change, sending progress ("call 3 of
    5: actions") meanwhile; at once when no job runs. Read again after
    ``poll_after_seconds``.

    Args:
        model_id: ID of the threat model.
        view: ``full`` (default), ``status`` or ``questions``.
        wait_seconds: 0 (default) answers at once.
        offset: ``questions`` view only.
        limit: ``questions`` view only.
    """
    if view not in _BEHAVIOURAL_VIEWS:
        raise ToolError(f"view must be one of {', '.join(_BEHAVIOURAL_VIEWS)}.")
    if not 0 <= wait_seconds <= _WAIT_MAX_SECONDS:
        raise ToolError(f"wait_seconds must be between 0 and {_WAIT_MAX_SECONDS}.")
    if offset < 0 or not 1 <= limit <= _PAGE_MAX:
        raise ToolError(f"offset must be 0 or more and limit between 1 and {_PAGE_MAX}.")
    try:
        client = _get_client()
        if wait_seconds:
            await _wait_for_extraction(client, model_id, wait_seconds, ctx)
        if view == "questions":
            return _dump(await client.get_behavioural_model(
                model_id, view=view, offset=offset, limit=limit))
        return _dump(await client.get_behavioural_model(model_id, view=view))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def extract_behavioural_model(
    server_version: str,
    model_id: str,
    confirm_estimate: bool = False,
    model_version: Optional[int] = None,
    set_revision: Optional[int] = None,
) -> dict:
    """Give a model that has no behavioural model one. Mutating only with
    ``confirm_estimate=True``; a paid action then.

    The extraction is paid for by whoever requests it, so it is estimated
    first and the estimate is RELAYED TO THE PERSON before it is confirmed.
    Never confirm on your own.

    1. Call with ``confirm_estimate=False`` (the default): nothing is charged
       or written. The answer carries the ``estimate`` (the extraction, the
       existing controls' deltas and checks, the link-matching call and the
       re-judgement, by part), the ``model_version`` and ``set_revision`` the
       model stands at, and ``notices`` on what the extraction changes:
       judgements of the groups the threats reach are asked again, and
       posture can move down as well as up. Show all of it to the person.
    2. Once they agree, call with ``confirm_estimate=True`` and those two
       values. The extraction is queued and the call returns at once
       (``queued``, ``extraction.job``): it can take an hour on a long
       description. Poll ``get_behavioural_model`` until ``extraction.job``
       is null; a new model version then holds the result (its ``status``
       may be ``needs_answers``). Read the proposals with
       ``get_behavioural_links``.

    Refusals come back as data, ``{confirmed: false, http_status, code,
    message}``: 409 ``has_behavioural_model`` (read it with
    ``get_behavioural_model``), 409 ``extraction_running`` (one is queued or
    running: poll it), 409 ``review_stale`` (the model or its controls
    changed since the estimate: confirm again with the values returned), 402
    (the balance cannot cover the estimate). A 404 means the caller may not
    start paid actions on the model.

    Args:
        model_id: ID of the threat model.
        confirm_estimate: False (default) estimates; True extracts.
        model_version: With ``confirm_estimate=True``: the estimate's value.
        set_revision: With ``confirm_estimate=True``: the estimate's value.
    """
    try:
        return _dump(await _get_client().extract_behavioural_model(
            model_id, confirm_estimate=confirm_estimate,
            model_version=model_version, set_revision=set_revision))
    except Exception as exc:
        raise _api_error(exc) from exc


_ANSWER_DISPOSITIONS = ("fact", "not_needed", "not_behaviour", "unknown", "as_stated")


@mcp.tool()
async def answer_behavioural_questions(
    server_version: str,
    model_id: str,
    answers: str = "[]",
    extract_now: bool = False,
    dry_run: bool = False,
) -> dict:
    """Answer open behavioural questions, many in one call. Mutating; creates
    a model version.

    Answer only from what the code or the owner shows; say ``unknown``
    rather than guess, in a sentence or two. An extraction runs once every
    owner question has an answer, or on ``extract_now=True`` (with no
    answers, refused 409 ``questions_open`` while one is open, and 409
    ``extraction_running`` while one is queued or running, or with no answer
    since it started: poll it), billed to the caller (402 when short).

    ``dry_run=True`` records nothing (no version, no escalation) and returns
    ``outcome``: whether the answers extract (``extracts``, ``estimate``),
    the questions left or ``raised``. Dry-run, answer what is raised, then
    submit once.

    An answer is a fact (``text``), or a ``disposition`` its question lists:
    ``not_needed``, ``not_behaviour``, ``unknown``, ``as_stated``; ``text``
    is then a note. A question about the model's own structure carries
    ``structured``: answer with ``structured`` naming the ids offered,
    ``{"classes": [...]}`` or ``{"public": true}``, ``{"zones": {id:
    zone}}``, ``{"zone": z}``, ``{"actions": [...]}``, ``{"changes": {field:
    [actions]}}``, ``{"receivers": [...]}``, ``{"elements": [id |
    {"id", "secret": true}]}`` (a zone's contents: an id not offered is a
    new element there; ``not_needed`` says it holds nothing). An offer with
    ``new_zones``
    takes a zone it does not list, one with ``new_actors`` a receiver it
    does not list, each added (409 ``id_in_use`` when the id names something
    else). It edits the model at once. Where the code does more or less than
    the sentence, add ``contradicts: {"direction": "code_does_more" |
    "code_does_less", "quote"?}`` (409 ``drift_is_defect`` over a defect's
    sentence).

    A program's answer is a judgment: refused with 403 and an
    ``escalation_id`` unless delegated. Do not retry; poll
    ``list_proposals``.

    With an extraction asked for, ``queued`` is true: follow it with
    ``get_behavioural_model(view="status", wait_seconds=50)``.

    Args:
        model_id: ID of the threat model.
        answers: JSON array of ``{"question_id", "text"?, "disposition"?,
            "structured"?, "contradicts"?}``, e.g. '[{"question_id": "q1",
            "text": "Only the owner deletes."}, {"question_id": "q3",
            "structured": {"classes": ["org_admin"]}}]'.
        extract_now: Extract now, with the answers collected.
        dry_run: Return what the answers would do (``outcome``) and record
            nothing. Default False.
    """
    parsed = _json_value(
        answers, "answers", list,
        '[{"question_id": "q1", "text": "Only the owner can delete a record."}]')
    for a in parsed:
        if not (isinstance(a, dict) and str(a.get("question_id", "")).strip()):
            raise ToolError("each answer needs a non-empty question_id.")
        disposition = str(a.get("disposition") or "fact")
        if disposition not in _ANSWER_DISPOSITIONS:
            raise ToolError(
                f"disposition must be one of {', '.join(_ANSWER_DISPOSITIONS)}.")
        structured = a.get("structured")
        if structured is not None and not isinstance(structured, dict):
            raise ToolError("structured is an object naming the ids the question's "
                            "structured offer lists.")
        if disposition == "fact" and structured is None \
                and not str(a.get("text", "")).strip():
            raise ToolError("a fact needs a non-empty text, or a structured answer; "
                            "name a disposition to answer without one.")
        contradicts = a.get("contradicts")
        if contradicts is not None and not (
                isinstance(contradicts, dict)
                and contradicts.get("direction") in ("code_does_more", "code_does_less")):
            raise ToolError("contradicts is {\"direction\": \"code_does_more\" | "
                            "\"code_does_less\", \"quote\"?: \"...\"}.")
    if not parsed and not extract_now:
        raise ToolError("Give at least one answer, or pass extract_now=True.")
    try:
        return _dump(await _get_client().answer_behavioural_questions(
            model_id, parsed, extract_now=extract_now,
            **({"dry_run": True} if dry_run else {})))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def edit_behavioural_element(
    server_version: str,
    model_id: str,
    collection: str,
    element: str,
) -> dict:
    """Replace, or add, one element of a model's behavioural model. Mutating;
    creates a model version (none when the edit changes nothing).

    The element is kept as a person wrote it, so a later extraction keeps it.
    It changes the model's ``ir_hash``, which voids a confirmation: confirm
    again with ``confirm_behavioural_model``. The result must still be a
    valid model (422 otherwise), and a build holding the model refuses it
    (409).

    A program's edit is a judgment. Unless the workspace's delegation policy
    admits it, it is refused with 403 and an ``escalation_id`` and parked for
    a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns the behavioural model as it now stands, with ``changed``.

    Args:
        model_id: ID of the threat model.
        collection: The collection of ``get_behavioural_model``'s ``ir`` the
            element belongs to.
        element: JSON object, the whole element including its ``id``; it
            replaces the element of that id, or adds one.
    """
    parsed = _json_value(element, "element", dict, '{"id": "e1", ...}')
    if not str(parsed.get("id", "")).strip():
        raise ToolError("element needs an id.")
    if not collection.strip():
        raise ToolError("collection is required.")
    try:
        return _dump(await _get_client().edit_behavioural_element(
            model_id, collection.strip(), parsed))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def confirm_behavioural_model(
    server_version: str,
    model_id: str,
    ir_hash: str,
    note: str = "",
) -> dict:
    """Confirm a model's behavioural model as reviewed. Mutating; creates a
    model version.

    Confirm only the model whose ``ir_hash`` was reviewed, which is the one
    ``get_behavioural_model`` returns. Refused with 409: ``review_stale``
    (the model is not that hash now), ``stale`` (the description changed since
    it was extracted) or ``needs_answers`` (an owner question is open). An
    edit voids a confirmation.

    A program's confirmation is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Args:
        model_id: ID of the threat model.
        ir_hash: The ``ir_hash`` reviewed.
        note: Optional note recorded with the confirmation.
    """
    if not ir_hash.strip():
        raise ToolError("ir_hash is required.")
    try:
        return _dump(await _get_client().confirm_behavioural_model(
            model_id, ir_hash.strip(), note=note))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_behavioural_links(server_version: str, model_id: str) -> dict:
    """Read the links from a behavioural model's elements and zones to the
    model's assets and trust boundaries. Read-only; no side effects.

    Returns ``{nodes, links, proposals, proposals_hash, questions, repair}``:
    each link says whether it counts toward the analysis; ``proposals`` are
    matches a person is shown (an empty ``entity_id`` is a node nothing
    matched); ``proposals_hash`` is what ``accept_behavioural_link_proposals``
    names; ``questions`` are the open link questions (also on
    ``get_review_queue`` as ``behavioural_link`` rows). A link is declared
    for one node with ``declare_behavioural_link``.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_behavioural_links(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def declare_behavioural_link(
    server_version: str,
    model_id: str,
    node_id: str,
    entity_id: str,
    component_id: str = "",
) -> dict:
    """Declare the asset or trust boundary a behavioural element or zone is.
    Mutating; creates no model version.

    The link is checked on every read: one whose asset lacks the property the
    element carries is kept and asked about. A link that counts changes what
    the analysis reaches, so the judgements it re-keys are queued, charged to
    the caller.

    A program's declaration is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns the links as ``get_behavioural_links`` does, with ``declared``.

    Args:
        model_id: ID of the threat model.
        node_id: The element or zone, from ``get_behavioural_links``.
        entity_id: The asset or trust boundary it is.
        component_id: Optional component the node belongs to.
    """
    if not node_id.strip() or not entity_id.strip():
        raise ToolError("node_id and entity_id are required.")
    try:
        return _dump(await _get_client().declare_behavioural_link(
            model_id, node_id.strip(), entity_id.strip(),
            component_id=component_id.strip()))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def accept_behavioural_link_proposals(
    server_version: str,
    model_id: str,
    proposals_hash: str,
) -> dict:
    """Declare every link proposal as shown, in one act. Mutating; creates no
    model version.

    Relay the proposals to the person first: read them with
    ``get_behavioural_links`` and name its ``proposals_hash``, which is the
    set reviewed. Refused with 409 ``review_stale`` when a proposal has
    changed since, and with 422 ``no_proposals`` when there is none. The
    judgements the links re-key are queued, charged to the caller.

    A program's acceptance is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns the links as ``get_behavioural_links`` does, with ``declared``.

    Args:
        model_id: ID of the threat model.
        proposals_hash: The ``proposals_hash`` reviewed.
    """
    if not proposals_hash.strip():
        raise ToolError("proposals_hash is required.")
    try:
        return _dump(await _get_client().accept_behavioural_link_proposals(
            model_id, proposals_hash.strip()))
    except Exception as exc:
        raise _api_error(exc) from exc


def _class_list(raw: str) -> list[str]:
    """Comma-separated credential class ids, as a list without blanks."""
    return [c.strip() for c in (raw or "").split(",") if c.strip()]


@mcp.tool()
async def get_behavioural_attackers(server_version: str, model_id: str) -> dict:
    """Read the attacker closure of a model: the attackers its behavioural
    model says are missing from the inventory, and what its attackers hold.
    Read-only: no model is called and nothing is written.

    Returns ``{applies, credential_classes, proposals, dismissed,
    dismissed_zones, reported, splits, dismissed_splits, questions}``.
    ``applies`` is false where the closure is not offered (a model with no
    inventory, or whose behavioural model decides nothing yet);
    ``computing`` while what the threats reach is still being analysed, when
    nothing is proposed. Each of ``proposals`` is an attacker no attacker of
    the inventory stands for: its ``kind`` (``own``: a class proposed on its
    own; ``grouped``: a part of the zones nobody stands at, the zones of one
    capability, with an ``entries`` row per zone), ``credential_classes``,
    ``privileges_required``, ``capability``, ``objectives`` and ``zones``;
    add it with ``add_proposed_attacker`` or dismiss it, or some zones of a
    part, with ``dismiss_proposed_attacker``. Two parts may hold the same
    classes: name one by a ``zone`` of it. Each of ``splits`` is an attacker
    standing for zones of several capabilities, offered split into its
    ``parts`` (each listed as a proposal is), with ``objectives_added``,
    ``objectives_removed`` and ``ratings``: split it with
    ``split_grouped_attacker`` or keep it whole with ``keep_attacker_whole``.
    ``dismissed``, ``dismissed_zones`` and ``dismissed_splits`` carry
    ``reason``, ``dismissed_by`` and ``dismissed_at``. ``reported`` lists
    narrower holders beside an attacker that stands for them. ``questions``
    ask what an attacker holds: answer each with
    ``answer_attacker_credentials``. Relay the proposals and splits to the
    person before acting on them.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_behavioural_attackers(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def answer_attacker_credentials(
    server_version: str,
    model_id: str,
    attacker_id: str,
    credential_classes: str = "",
) -> dict:
    """Say which of the behavioural model's credential classes an attacker
    holds. Mutating; creates a model version.

    Answer from what the code or the owner shows. Empty means it holds no
    credential. Its privileges follow from what it holds, by rule: ``None``
    with none, ``High`` when a class may invoke an action that writes what
    decides authority, ``Low`` otherwise; ``edit_attacker`` then refuses a
    privileges change (409 ``privileges_from_holdings``). A holder of a
    per-tenant class is placed at every tenant-isolation boundary,
    suggested. Refused with 422 ``unknown_class`` (a class the model does not
    have), 409 ``closure_not_offered`` (``get_behavioural_attackers`` reads
    ``applies: false``), 404 ``no_attacker``.

    A program's answer is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns ``{model_id, model_version, applies, credential_classes, counts,
    attacker}``: how many proposals, dismissals and questions the closure now
    holds (read them with ``get_behavioural_attackers``) and the ``attacker``
    as it now stands.

    Args:
        model_id: ID of the threat model.
        attacker_id: The attacker (e.g. "T3").
        credential_classes: Comma-separated class ids from
            ``credential_classes``; empty for none.
    """
    if not attacker_id.strip():
        raise ToolError("attacker_id is required.")
    try:
        return _closure_change(_dump(await _get_client().answer_attacker_credentials(
            model_id, attacker_id.strip(), _class_list(credential_classes))))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def add_proposed_attacker(
    server_version: str,
    model_id: str,
    credential_classes: str = "",
    zone: str = "",
) -> dict:
    """Add the attacker the attacker closure proposes for a credential set.
    Mutating; creates a model version.

    Name the proposal by its ``credential_classes`` as
    ``get_behavioural_attackers`` lists it (a dismissed one may be added),
    and a part of the zones nobody stands at by one of its ``zones`` where
    another proposal holds the same classes.
    The attacker holds them, with the privileges they give and no position
    but the tenant-isolation boundaries a per-tenant holder is placed at.
    It is rated as ``add_attacker`` rates: one call before the write,
    charged to the caller, its privileges the ones it holds gives. Where no
    rating answers, or when a person accepts a parked addition, it is added
    unrated (``rating_source: "unrated"``), and
    ``reevaluate_threat_model_factors`` with ``unrated_only`` rates it.
    Refused with 409 ``not_proposed`` when no attacker is proposed for
    exactly that set now (read the attackers again), 409
    ``ambiguous_proposal`` when several are and no ``zone`` names one (its
    ``zones`` lists each), 409 ``closure_not_offered``, 422
    ``unknown_class``.

    A program's addition is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns ``{model_id, model_version, applies, credential_classes, counts,
    added, rating_source}``: how many proposals, dismissals and questions the
    closure now holds, ``added``, the new attacker's id, and whether a
    rating answered (``unrated`` when none did).

    Args:
        model_id: ID of the threat model.
        credential_classes: Comma-separated class ids of the proposal; empty
            for the one holding none.
        zone: A zone of the part to add, where two proposals hold the same
            classes; empty otherwise.
    """
    try:
        return _closure_change(_dump(await _get_client().add_proposed_attacker(
            model_id, _class_list(credential_classes),
            **({"zone": zone.strip()} if zone.strip() else {}))))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def dismiss_proposed_attacker(
    server_version: str,
    model_id: str,
    reason: str,
    credential_classes: str = "",
    zones: str = "",
    zone: str = "",
) -> dict:
    """Dismiss the attacker the attacker closure proposes for a credential
    set, with why, or some zones of a part of the zones nobody stands at.
    Mutating; creates a model version.

    The dismissal is kept on the model: the proposal is no longer offered
    while it stands. ``zones`` names zones of a part (its ``kind`` is
    ``grouped``) that no attacker reaches: those alone are dismissed, and the
    part stands for the rest; ``zone`` names the part where two proposals
    hold the same classes. Refused with 409 ``not_proposed`` (no attacker is
    proposed for exactly that set now), 409 ``ambiguous_proposal`` (name a
    ``zone``), 409 ``dismissed_already``, 409 ``closure_not_offered``, 422
    ``unknown_class``, 422 ``unknown_zone`` (a zone the part does not offer
    now), 422 ``zones_of_own`` (zones of a class proposed on its own).

    A program's dismissal is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns ``{model_id, model_version, applies, credential_classes, counts,
    dismissed_set, dismissed_zones_now?}``: how many proposals, dismissals and
    questions the closure now holds, and what was dismissed.

    Args:
        model_id: ID of the threat model.
        reason: Why the attacker does not apply (required).
        credential_classes: Comma-separated class ids of the proposal; empty
            for the one holding none.
        zones: Comma-separated zones of the part to dismiss alone; empty
            dismisses the proposal whole.
        zone: A zone of the part, where two proposals hold the same classes;
            empty otherwise.
    """
    if not reason.strip():
        raise ToolError("reason is required: say why the attacker does not apply.")
    named_zones = _class_list(zones)
    try:
        return _closure_change(_dump(await _get_client().dismiss_proposed_attacker(
            model_id, _class_list(credential_classes), reason.strip(),
            **({"zones": named_zones} if named_zones else {}),
            **({"zone": zone.strip()} if zone.strip() else {}))))
    except Exception as exc:
        raise _api_error(exc) from exc


def _parts(raw: str) -> list[list[str]]:
    """Parts as ``a,b;c;d``: each part's zones comma-separated, parts
    separated by semicolons, without blanks."""
    return [p for p in (_class_list(part) for part in (raw or "").split(";")) if p]


@mcp.tool()
async def split_grouped_attacker(
    server_version: str,
    model_id: str,
    attacker_id: str,
    parts: str,
) -> dict:
    """Split an attacker that stands for zones of several capabilities into
    the parts ``get_behavioural_attackers`` offers under ``splits``.
    Mutating; creates a model version.

    Name each part by its ``zones`` as the offer lists them, which is the
    split reviewed. In one write, each part is added holding what its zones
    hold, its holdings attested, stating its zones, and rated as
    ``add_attacker`` rates (one call per part before the write, charged to
    the caller: ``ratings`` says how many); every control mapping of the
    attacker's objective of an asset moves to each part's objective of that
    asset with the same privilege (they owe the same obligations); and the
    attacker is removed. Relay the offer to the person first. Refused with
    409 ``split_not_offered`` (read the attackers again), 409
    ``review_stale`` (the parts changed: read them again), 409
    ``closure_not_offered``.

    A program's split is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns ``{model_id, model_version, applies, credential_classes, counts,
    split, added, moved}``: the closure's counts, the attacker split, the
    parts' ids and the objectives whose control mappings moved.

    Args:
        model_id: ID of the threat model.
        attacker_id: The attacker to split (e.g. "T7").
        parts: Each part's zones, comma-separated, the parts separated by
            semicolons (e.g. "host;vendor_a;partner").
    """
    if not attacker_id.strip():
        raise ToolError("attacker_id is required.")
    named = _parts(parts)
    if len(named) < 2:
        raise ToolError("parts is required: name each part's zones as the offer lists them.")
    try:
        return _closure_change(_dump(await _get_client().split_grouped_attacker(
            model_id, attacker_id.strip(), named)))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def keep_attacker_whole(
    server_version: str,
    model_id: str,
    attacker_id: str,
    reason: str,
) -> dict:
    """Keep an attacker offered for a split whole, with why. Mutating;
    creates a model version.

    The decision is kept on the model: the split is no longer offered while
    it stands, and the attacker is left as it is. Refused with 409
    ``split_not_offered``, 409 ``dismissed_already``.

    A program's decision is a judgment. Unless the workspace's delegation
    policy admits it, it is refused with 403 and an ``escalation_id`` and
    parked for a person. Do not retry: report the ``escalation_id`` and poll
    ``list_proposals``.

    Returns ``{model_id, model_version, applies, credential_classes, counts,
    dismissed_split}``.

    Args:
        model_id: ID of the threat model.
        attacker_id: The attacker to keep whole.
        reason: Why it is one capability (required).
    """
    if not attacker_id.strip():
        raise ToolError("attacker_id is required.")
    if not reason.strip():
        raise ToolError("reason is required: say why the attacker is one capability.")
    try:
        return _closure_change(_dump(await _get_client().keep_attacker_whole(
            model_id, attacker_id.strip(), reason.strip())))
    except Exception as exc:
        raise _api_error(exc) from exc


# === Inventory judgements ===
#
# What the per-entity checks found about a model's inventory: entries that may
# be one entity, and the taxonomy primitives each entity answers. Nothing here
# merges, removes or rewrites an entity.

_INVENTORY_KINDS = ("asset", "attacker")


@mcp.tool()
async def get_inventory_judgements(server_version: str, model_id: str) -> dict:
    """Read what the per-entity checks found about a model's inventory.
    Read-only: no model is called and nothing is queued.

    Returns ``{model_id, version, duplicates, tags}``. ``duplicates``, per
    kind (``assets``, ``attackers``): ``groups`` (shown as one entity: both
    sides' current checks say so, their texts are identical, or a person
    decided it), ``disputed`` and ``one_sided`` (one check says the same and
    the other does not, or only one side answered), ``overlaps`` (part and
    whole), ``decided`` (the decisions in force), ``status`` (``complete``
    when every pair a check is owed for is covered, ``partial`` with
    ``uncovered`` counting the rest as queued, failed or never asked,
    ``not_evaluated`` with a ``reason``) and ``legacy`` (a report from
    before the per-entity checks). ``tags``: the entities whose tags are
    neither current nor declared (``unchecked``) and the declarations in
    force. The same rows reach ``get_review_queue`` as
    ``inventory_judgement``.

    Relay a disputed pair to the person; ``decide_inventory_pair`` records
    the decision and ``request_inventory_checks`` asks for the checks owed.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_inventory_judgements(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def request_inventory_checks(server_version: str, model_id: str) -> dict:
    """Queue the checks a model's inventory lacks: the tag check of every
    entity whose tags are not current, and the duplicate check of every entry
    on a pair no current check covers. Mutating: queues background work.

    Those the platform made stale are recorded as its own request, the rest
    under the caller. Returns ``{model_id, queued, platform}``: the checks
    queued by kind, and the platform's share. Read the results with
    ``get_inventory_judgements`` once they land.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().request_inventory_checks(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def decide_inventory_pair(
    server_version: str,
    model_id: str,
    entity_kind: Literal["asset", "attacker"],
    a: str,
    b: str,
    verdict: Literal["same", "different"],
    rationale: str = "",
) -> dict:
    """Decide that two entries of a model's inventory are, or are not, one
    entity. Mutating; creates no model version; a judgment.

    The decision is bound to both entries' texts: while it stands it replaces
    the checks' answers for the pair, and an edit of either entry voids it.
    ``same`` keeps the pair shown until a person removes one of the two
    (``remove_entity``); nothing is merged. Refused 422 ``two_elements`` for
    two assets that are each an element of the behavioural model (two
    elements are two things), 422 ``same_entity``, 404 ``unknown_entity``.

    A program's decision is refused with 403 and an ``escalation_id`` unless
    the workspace's delegation policy names ``inventory_pair_decided``.
    Do not retry: report the ``escalation_id`` and poll ``list_proposals``.

    Returns ``{pair, entity_kind, verdict, decided_at, objectives}``,
    ``objectives`` counting those resting on the two entries.

    Args:
        model_id: ID of the threat model.
        entity_kind: ``asset`` or ``attacker``.
        a: One entry's id (e.g. "A-12").
        b: The other entry's id.
        verdict: ``same`` or ``different``.
        rationale: Why (at most 2000 characters).
    """
    if entity_kind not in _INVENTORY_KINDS:
        raise ToolError(f"entity_kind must be one of {', '.join(_INVENTORY_KINDS)}.")
    if verdict not in ("same", "different"):
        raise ToolError("verdict must be 'same' or 'different'.")
    if not a.strip() or not b.strip():
        raise ToolError("a and b are required: the two entries' ids.")
    if len(rationale) > 2000:
        raise ToolError("rationale is at most 2000 characters.")
    try:
        return _dump(await _get_client().decide_inventory_pair(
            model_id, entity_kind, a.strip(), b.strip(), verdict, rationale=rationale))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def declare_inventory_tags(
    server_version: str,
    model_id: str,
    entity_kind: Literal["asset", "attacker"],
    entity_id: str,
    tags: str = "[]",
    rationale: str = "",
) -> dict:
    """Declare the taxonomy primitives an entity of a model's inventory
    answers. Mutating; creates no model version; a judgment.

    The declaration is bound to the entity's text: it witnesses each
    primitive whatever the tagger answers, and an edit of the entity voids
    it. Every pair must be one the taxonomy admits for the kind (422
    ``inadmissible_tag``); an empty list declares that the entity answers
    none. 404 ``unknown_entity``.

    A program's declaration is refused with 403 and an ``escalation_id``
    unless the workspace's delegation policy names ``inventory_tag_declared``.
    Do not retry: report the ``escalation_id`` and poll ``list_proposals``.

    Returns ``{entity_id, entity_kind, tags, declared_at}``.

    Args:
        model_id: ID of the threat model.
        entity_kind: ``asset`` or ``attacker``.
        entity_id: The entity (e.g. "T-04").
        tags: JSON array of ``{"primitive", "implied_type"}``.
        rationale: Why (at most 2000 characters).
    """
    if entity_kind not in _INVENTORY_KINDS:
        raise ToolError(f"entity_kind must be one of {', '.join(_INVENTORY_KINDS)}.")
    if not entity_id.strip():
        raise ToolError("entity_id is required.")
    if len(rationale) > 2000:
        raise ToolError("rationale is at most 2000 characters.")
    parsed = _json_value(tags, "tags", list,
                         '[{"primitive": "...", "implied_type": "..."}]')
    for t in parsed:
        if not (isinstance(t, dict) and str(t.get("primitive", "")).strip()
                and str(t.get("implied_type", "")).strip()):
            raise ToolError("each tag is an object with a primitive and an implied_type.")
    try:
        return _dump(await _get_client().declare_inventory_tags(
            model_id, entity_kind, entity_id.strip(), parsed, rationale=rationale))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def apply_entity_proposals(
    server_version: str,
    model_id: str,
    proposals: str,
) -> dict:
    """Apply the corrections the quality check proposed for assets and
    attackers. Mutating: creates one new model version for the whole batch.

    An asset or attacker the check finds defective carries a proposed
    correction of its words: read it as ``quality`` on ``get_entity`` (or in
    the build proposal's flagged entities, or the review queue's
    ``entity_quality`` row), where ``outcome`` is ``defect``, ``proposed``
    holds the corrected fields and ``input_hash`` names the verdict. Applying
    it is an edit of the entity's own words (an asset's name, description and
    security properties; an attacker's capability, position and archetype):
    it never moves a position, credentials, a rating or components, and the
    corrected text is checked again as any edit is. A ``defect`` may carry no
    ``proposed``: the correction the check found named internal identifiers
    of the behavioural model rather than the system's words, and was
    withheld; its warning says so.

    Each entity reports one ``outcome``: ``applied``; ``rejected`` (the
    correction reads as a different entity, or duplicates one, or names
    internal identifiers of the behavioural model, which ``reason`` lists:
    edit or answer the entity so that its check runs again, for a correction
    in words); ``stale``
    (the entity, or what it is judged with, changed since the verdict: read
    it again); ``none`` (no correction stands); ``unavailable`` (the identity
    check could not answer: try again). One entity never stops the others.

    Returns ``{results: [{entity_id, outcome, reason?}], version?}``, the
    model version written when anything was applied.

    Args:
        model_id: ID of the threat model.
        proposals: JSON array of ``{"entity_id", "input_hash"}``, each
            ``input_hash`` as the verdict was read.
    """
    parsed = _json_value(proposals, "proposals", list,
                         '[{"entity_id": "A-03", "input_hash": "..."}]')
    if not parsed:
        raise ToolError("proposals names at least one entity.")
    for p in parsed:
        if not (isinstance(p, dict) and str(p.get("entity_id", "")).strip()
                and str(p.get("input_hash", "")).strip()):
            raise ToolError("each proposal is an object with an entity_id and an input_hash.")
    try:
        answer = await _get_client().apply_entity_proposals(
            model_id, [{"entity_id": str(p["entity_id"]).strip(),
                        "input_hash": str(p["input_hash"]).strip()} for p in parsed])
    except Exception as exc:
        raise _api_error(exc) from exc
    return _without_models(_dump(answer)) if isinstance(answer, dict) else answer


@mcp.tool()
async def check_entity_quality(
    server_version: str,
    model_id: str,
    entity_ids: str = "",
    confirm_estimate: bool = False,
) -> dict:
    """Ask for the quality check of the assets and attackers you name (every
    one when you name none) that have no current verdict: an entity whose
    ``quality`` reads ``unchecked``, or one changed since its last check.
    Without ``confirm_estimate`` it only estimates; with it, the checks are
    queued and run in the background. Creates no model version.

    Checking may be paid. Call it first without ``confirm_estimate``, RELAY
    THE ESTIMATE TO THE PERSON, and confirm only when they agree; never
    confirm on your own. The answer says where each named entity stands:
    ``current`` (its verdict answers it as it stands; it is not checked
    again: to dispute it, answer its flag with ``answer_entity_question``),
    ``checking`` (its check is queued already), ``answered`` (a stored
    verdict answers it and is served again, at no cost), ``platform_scope``
    (made stale by a change to the platform; checked at Mipiti's cost) and
    ``customer_scope`` (checked at the caller's cost; ``estimate`` gives an
    upper bound, the deeper review running only where the first pass flags).
    A confirmation the caller's balance cannot cover is refused with 402 and
    queues nothing; an id naming no asset or attacker of the model is refused
    400 ``unknown_entity``. Read each entity again with ``get_entity`` for its
    verdict once it lands. To ask every entity again whatever is stored, use
    ``revalidate_entity_quality``.

    Returns ``{platform_scope, customer_scope, current, checking, answered,
    estimate, billing, confirmed, queued, message}``.

    Args:
        model_id: ID of the threat model.
        entity_ids: JSON array of asset and attacker ids (e.g. ``["A-17",
            "T-04"]``); empty for every entity.
        confirm_estimate: Queue the checks the estimate describes.
    """
    ids: list = []
    if entity_ids.strip():
        ids = _json_value(entity_ids, "entity_ids", list, '["A-17", "T-04"]')
        if not all(isinstance(i, str) and i.strip() for i in ids):
            raise ToolError("entity_ids is a JSON array of entity ids.")
        ids = [i.strip() for i in ids]
    try:
        return _dump(await _get_client().check_entity_quality(
            model_id, ids, confirm_estimate=confirm_estimate))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def answer_entity_question(
    server_version: str,
    model_id: str,
    entity_id: str,
    text: str,
    input_hash: str,
) -> dict:
    """Answer, with a fact, the flag the quality check raised about an asset
    or attacker. Mutating; creates no model version.

    An entity's ``quality`` (on ``get_entity``, the build proposal's flagged
    entities or the review queue's ``entity_quality`` row) carries the
    verdict's ``outcome`` and ``input_hash``. Any flag may be answered:
    ``question`` (answer its ``question``), ``defect`` or ``invalid`` (answer
    its ``warning``, for instance where it reads a true claim as not
    established and the documentation or the code establishes it). Answer
    from the documentation or the code, stating what the system does and
    where that is shown; never guess, and never weaken a true claim to clear
    a flag. The answer is kept with the entity, shown to every later check of
    it, and queues that entity's check again (and no other's). It decides
    nothing: the verdict stands until that check runs, and the check may
    still flag the entity, or propose a correction to apply with
    ``apply_entity_proposals``. Where a call's response is lost, read the
    entity before answering again.

    Refused 409 ``stale`` when the entity, or what it is judged with, changed
    since the verdict (read it again), 409 ``not_flagged`` when no question,
    defect or invalid verdict stands, 404 for an entity the model does not
    hold.

    Returns ``{entity_id, answer_id, answered_at, question, queued}``.

    Args:
        model_id: ID of the threat model.
        entity_id: The asset or attacker (e.g. "T-04").
        text: The answer (at most 4000 characters).
        input_hash: The verdict's ``input_hash`` as it was read.
    """
    if not entity_id.strip():
        raise ToolError("entity_id is required.")
    if not text.strip():
        raise ToolError("text is required: the answer.")
    if len(text) > 4000:
        raise ToolError("text is at most 4000 characters.")
    if not input_hash.strip():
        raise ToolError("input_hash is required: the verdict's, as it was read.")
    try:
        return _dump(await _get_client().answer_entity_question(
            model_id, entity_id.strip(), text.strip(), input_hash.strip()))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_control_delta(
    server_version: str,
    model_id: str,
    control_id: str,
) -> dict:
    """Read the delta of a control: the edits to the behavioural model that
    the control's own text commits to. Read-only; no side effects.

    The delta is served for the control's text as it stands. ``status`` is
    ``absent`` (none), ``pending`` (not checked yet), ``checked``, ``failed``
    or ``declared`` (a person declared it). Returns ``{status, edits,
    unexpressed, applies, expressible, declared_by, rendered, unquoted,
    second_reading, declaration, cross_check, ...}``: ``rendered`` is each
    edit in words beside its quotes, ``unquoted`` the text no quote reaches.

    Once a person declares the delta, the control's sufficiency is judged
    against the declaration's commitments, not a reading of its text, and
    ``cross_check`` says whether the text may commit to more than they
    state: ``completed`` (false until the control's next sufficiency
    evaluation asks it) and ``findings``, each ``dismissed`` or open. The
    control reads sufficient only once its cross-check completed and every
    finding is dismissed. RELAY OPEN FINDINGS TO THE PERSON: dismissing one
    is a person's act, made in the app, never a program's; the other exit
    is a new draft declared again.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control (e.g. "CTRL-01").
    """
    try:
        return _dump(await _get_client().get_control_delta(model_id, control_id))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def submit_control_delta(
    server_version: str,
    model_id: str,
    control_id: str,
    edits: str,
    unexpressed: str = "[]",
) -> dict:
    """Submit a draft of a control's delta: edits to the behavioural model,
    each quoting the control's own text. Mutating; writes no control, set
    revision or model version.

    Each edit's quote must be found in the control's text (a quote's
    ``source`` defaults to the control), and ``unexpressed`` lists what the
    text commits to that no edit states. An edit that does not check is
    refused (422 ``delta_refused``) with its failures.

    A submission is a draft, never a declaration: it is checked against the
    text by one call billed to the caller (402 when the balance is short), so
    it can never make the analysis credit a control alone, and a program's
    never replaces a delta a person declared (409 ``declared_by_person``).
    A person declares a draft with ``declare_control_delta``.

    Returns the delta as ``get_control_delta`` does, with ``check_ran``.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        edits: JSON array of edit objects, each with a ``trace`` of quotes
            from the control's text.
        unexpressed: JSON array of ``{"kind", "quote", "note"}``.
    """
    parsed_edits = _json_value(edits, "edits", list, '[{"trace": [{"quote": "..."}], ...}]')
    parsed_unexpressed = _json_value(
        unexpressed, "unexpressed", list, '[{"kind": "...", "quote": "...", "note": ""}]')
    try:
        return _dump(await _get_client().submit_control_delta(
            model_id, control_id, parsed_edits, parsed_unexpressed))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def request_delta_second_reading(
    server_version: str,
    model_id: str,
    control_ids: str,
    confirm_estimate: bool = False,
) -> dict:
    """Read controls' text into deltas a second time, by a call not shown the
    drafts: a delta is declared only once its draft has been read twice.

    Without ``confirm_estimate`` nothing is charged or written: the result
    lists the controls it would read, those it skips (``no_draft``, or
    ``read`` already) and the estimate, which must be RELAYED TO THE PERSON
    first. Never confirm on your own. With it the reading is made, billed to
    the caller (402 when the balance is short), and each control's outcome
    is returned (``usable``, ``unusable``, ``failed``, ``unavailable``).
    Refused with 409 ``generation_active`` while a build holds the model.

    Args:
        model_id: ID of the threat model.
        control_ids: Comma-separated control IDs, at most 30.
        confirm_estimate: True to make the reading after the person agreed.
    """
    ids = [c.strip() for c in (control_ids or "").split(",") if c.strip()]
    if not ids:
        raise ToolError("control_ids is required: comma-separated control IDs.")
    try:
        return _dump(await _get_client().request_delta_second_reading(
            model_id, ids, confirm_estimate=confirm_estimate))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def declare_control_delta(
    server_version: str,
    model_id: str,
    control_id: str,
    nothing_spans: str = "[]",
    resolutions: str = "[]",
    placements: str = "[]",
    declaration_hash: str = "",
    confirm: bool = False,
) -> dict:
    """Prepare the declaration of a control's delta as served: the act that
    makes it the control's specification. Declaring is a person's act, never
    a program's.

    Without ``confirm`` (the default) this is the preview, and nothing is
    written: the declaration the given spans and resolutions make, its
    ``declaration_hash``, each edit in words beside its quotes, the second
    reading's ``differences`` and those still ``open``, the text no quote
    reaches (``unquoted``), the spans the text's notes suggest as committing
    to nothing, what declaring does, and ``blocking`` (what stops it). Relay
    the preview to the person: the differences, and which text commits to
    nothing, are theirs to decide.

    With ``confirm`` and the ``declaration_hash`` previewed, a program's call
    is always refused with 403 and an ``escalation_id``, whatever the
    workspace delegates: it is parked for a person, who sees what it declares
    and accepts or rejects it. Do not retry: report the ``escalation_id`` and
    poll ``list_proposals``. A parked declaration is withdrawn once the delta
    it names changes.

    Args:
        model_id: ID of the threat model.
        control_id: ID of the control.
        nothing_spans: JSON array of ``{"start", "end"}`` spans of the
            control's text, in code points, that commit to nothing.
        resolutions: JSON array of ``{"start", "end", "choice"}``, one per
            difference, in order: ``choice`` is ``draft``, ``second`` or
            ``written`` (with ``edits``).
        placements: JSON array of ``{"item", "index", "span", "start",
            "end"}`` naming which occurrence a repeated quote stands at.
        declaration_hash: The hash the preview returned.
        confirm: True to declare (a person's act).
    """
    spans = _json_value(nothing_spans, "nothing_spans", list, '[{"start": 0, "end": 12}]')
    chosen = _json_value(resolutions, "resolutions", list,
                         '[{"start": 0, "end": 12, "choice": "draft"}]')
    placed = _json_value(placements, "placements", list,
                         '[{"item": "edit", "index": 0, "span": 0, "start": 0, "end": 12}]')
    if confirm and not declaration_hash.strip():
        raise ToolError("declaration_hash is required to confirm: preview first.")
    try:
        return _dump(await _get_client().declare_control_delta(
            model_id, control_id, nothing_spans=spans, resolutions=chosen,
            placements=placed, declaration_hash=declaration_hash.strip(),
            confirm=confirm))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_behavioural_threats(
    server_version: str,
    model_id: str,
    co_id: str = "",
    offset: int = 0,
    limit: int = _THREATS_PAGE_DEFAULT,
    standing: str = "",
) -> dict:
    """Read the possible threats the behavioural analysis finds for each
    control objective of a model. Read-only: nothing is judged, written or
    paid for.

    The analysis runs over the model with no controls applied. Per objective
    it returns its ``standing``, each obligation's ``result``, the ``threats``
    (rule, obligation, elements), the ``default_questions`` whose answers
    would remove them, and the ``grounds`` the analysis rests on. Returns
    ``decides: false`` while the behavioural model is absent, asks an owner
    question, or has not been extracted.

    A page at a time, in the model's order of objectives: ``offset`` and
    ``limit`` (default 25, at most 200), ``co_id`` one objective (404
    ``unknown_objective`` for one the model does not hold live),
    ``standing`` only the objectives of that standing (``possible_threat``,
    ``undecided``, ...). The answer carries ``total`` (the objectives
    matching), ``next_offset`` (where the next page starts, null at the end)
    and ``truncated`` (the page was cut short to stay under the size a
    client can take; read on from ``next_offset``).

    A possible threat is not a finding yet. RELAY IT TO THE PERSON with its
    default questions first: an answer that settles a default removes the
    threat, and only a threat the person confirms is worth a control. Answer
    with ``answer_behavioural_questions``.

    Args:
        model_id: ID of the threat model.
        co_id: One objective (e.g. "CO5"); empty for every one.
        offset: The first objective of the page (default 0).
        limit: Objectives per page (default 25, at most 200).
        standing: Only objectives of this standing; empty for every one.
    """
    if offset < 0 or not 1 <= limit <= _PAGE_MAX:
        raise ToolError(f"offset must be 0 or more and limit between 1 and {_PAGE_MAX}.")
    if len(co_id) > 128 or len(standing) > 64:
        raise ToolError("co_id is at most 128 characters and standing at most 64.")
    try:
        return _dump(await _get_client().get_behavioural_threats(
            model_id, co_id=co_id.strip(), offset=offset, limit=limit,
            standing=standing.strip()))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def request_model_check(
    server_version: str,
    model_id: str,
    confirm_estimate: bool = False,
    model_version: Optional[int] = None,
    set_revision: Optional[int] = None,
    obligations: str = "",
    scope: str = "",
) -> dict:
    """Request a model check of the obligations the behavioural analysis
    could not settle. Mutating only with ``confirm_estimate=True``; a paid
    action then.

    A check is paid for by whoever requests it, so it is estimated first and
    the estimate is RELAYED TO THE PERSON before it is confirmed.
    Never confirm on your own.

    1. Call with ``confirm_estimate=False`` (the default): nothing runs or is
       charged. The answer carries the ``obligations`` it would cover (each
       with its completion ``prediction``), the ``scope``, the ``cones``
       (each module, its runs, and ``remedies`` / ``not_run`` where it may
       not complete or fits no runner), the ``estimate``, the
       ``model_version`` and ``set_revision`` the model stands at, and
       ``notices`` on what a check does. Show all of it to the person. With
       nothing to check, the ``message`` says so: name ``obligations`` to
       check some anyway.
    2. Once they agree, call with ``confirm_estimate=True`` and those two
       values. The check is queued (``confirmed: true``, ``job_id``,
       ``status: "queued"``); poll ``get_model_check`` until ``terminal``.

    Refusals come back as data, ``{confirmed: false, http_status, code,
    message}``: 409 ``not_confirmed`` (confirm the behavioural model first,
    after reviewing it), ``differences_open`` (answer the open questions an
    earlier check raised), ``check_active`` (one is live: read it),
    ``generation_active`` (a build holds the model), ``review_stale`` (the
    model or its controls changed since the estimate: confirm again with
    the values returned), ``no_runner_size`` (every module is larger than
    any runner holds: answer the defaults it rests on, or narrow the scope
    or the obligations); 503 ``not_priced`` or ``no_runner_pool`` (checks
    cannot run here yet); 402 (the balance cannot cover the estimate). A 404
    means model checks are not available for the model, or the caller may
    not start paid actions on it.

    Args:
        model_id: ID of the threat model.
        confirm_estimate: False (default) estimates; True queues the check.
        model_version: With ``confirm_estimate=True``: the estimate's value.
        set_revision: With ``confirm_estimate=True``: the estimate's value.
        obligations: Optional comma-separated obligation ids to cover in
            place of the default (the unsettled ones the controls' groups
            reach).
        scope: Optional JSON object lowering some of the scope's constants,
            the keys the estimate's ``scope`` reports (e.g.
            ``{"domain": 1, "horizon": 4}``); each must be a non-negative
            integer at most the declared value, and those left out keep it
            (400 ``bad_scope`` otherwise).
    """
    parsed_obligations = [o.strip() for o in obligations.split(",") if o.strip()]
    parsed_scope = (_json_value(scope, "scope", dict, '{"domain": 1, "horizon": 4}')
                    if scope.strip() else None)
    try:
        return _dump(await _get_client().request_model_check(
            model_id, confirm_estimate=confirm_estimate,
            model_version=model_version, set_revision=set_revision,
            obligations=parsed_obligations, scope=parsed_scope))
    except Exception as exc:
        raise _api_error(exc) from exc


@mcp.tool()
async def get_model_check(server_version: str, model_id: str) -> dict:
    """Read a model's model check: the live one, else the latest. Read-only.

    ``status`` is ``queued``, ``extracting`` (the independent extraction),
    ``running``, ``pausing``, ``paused``, ``differences`` (the independent
    extraction disagreed with the confirmed model: ``cross_check.questions``
    are the questions to answer with ``answer_behavioural_questions``, and no
    model check ran), ``complete``, ``incomplete``, ``failed``,
    ``discarded``, or ``none`` when the model has never had one. ``terminal``
    says whether it has stopped. Beside it: the ``obligations`` and
    ``scope`` it covers, the ``estimate`` confirmed, the ``results`` of its
    runs, ``machine_seconds`` and ``error_message``. A result that did not
    complete reports no violation up to the depth reached and credits
    nothing.

    Args:
        model_id: ID of the threat model.
    """
    try:
        return _dump(await _get_client().get_model_check(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


_MODEL_CHECK_ACTIONS = ("pause", "resume", "discard")


@mcp.tool()
async def manage_model_check(
    server_version: str,
    model_id: str,
    action: Literal["pause", "resume", "discard"],
) -> dict:
    """Pause, resume or discard a model's live model check. Mutating.

    - ``action="pause"``: a queued check pauses at once, a running one at its
      next stage (``pausing`` until then). Idempotent. What it already ran is
      charged. Returns ``{paused: true, job_id, status}``.
    - ``action="resume"``: a paused check resumes at the stage it stopped in.
      Returns ``{resumed: true, job_id, status: "queued"}``.
    - ``action="discard"``: drops a queued or paused check; a running one is
      refused until it is paused. What it already ran is charged. Returns
      ``{discarded: true, job_id, status: "discarded"}``.

    A refusal comes back as data, ``{paused|resumed|discarded: false,
    http_status: 409, code, message}``: ``not_running`` (no check is live),
    ``pause_in_progress`` (still stopping: resume once it reads ``paused``),
    ``not_paused``, ``pause_first`` (pause a running check before
    discarding it).

    Args:
        model_id: ID of the threat model.
        action: "pause", "resume" or "discard".
    """
    if action not in _MODEL_CHECK_ACTIONS:
        raise ToolError(f"action must be one of {', '.join(_MODEL_CHECK_ACTIONS)}.")
    try:
        client = _get_client()
        if action == "pause":
            return _dump(await client.pause_model_check(model_id))
        if action == "resume":
            return _dump(await client.resume_model_check(model_id))
        return _dump(await client.discard_model_check(model_id))
    except Exception as exc:
        raise _api_error(exc) from exc


# ------------------------------------------------------------------
# The catalog and its version (every tool is registered above)
# ------------------------------------------------------------------

CATALOG = catalog.current(mcp, _INSTRUCTION_PARTS)
CATALOG_VERSION = catalog.version_of(CATALOG)
_SERVER_VERSION = os.environ.get("SERVER_VERSION") or CATALOG_VERSION
mcp.instructions = build_instructions("pro")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Console script entry point (mipiti-mcp command)."""
    mcp.run()


if __name__ == "__main__":
    main()

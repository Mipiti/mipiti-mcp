"""Canonical assertion type schema.

Single source of truth for assertion types: their required and optional
params, param descriptions and value formats, an example per type, and the
soundness class of the fact each type reports. Consumed by:

- MCP server: generates the submit_assertions docstring and refuses a
  malformed submission before it leaves the client
- Backend validation: imports required param lists, value formats and the
  soundness class table
- CI verifier: holds its evidence classes equal to the ones declared here
- Documentation: generates the assertion type reference
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Soundness classes
# ---------------------------------------------------------------------------

# Each evidence type reports one kind of fact, and that kind bounds what a
# passing verdict can establish. The class is declared once, here, by the
# fact reported -- never by how a check is implemented or what tool runs
# it -- and the platform and the CI verifier hold their own tables equal to
# this one, so nothing downstream infers strength from a type name, a
# parameter or a file path. Ordered weakest to strongest.
SOUNDNESS_CLASSES: tuple[str, ...] = (
    "presence",
    "under_approximating_scan",
    "existential_witness",
    "sound_over_approximation",
    "by_construction",
)

SOUNDNESS_RANK: dict[str, int] = {c: i for i, c in enumerate(SOUNDNESS_CLASSES)}

# What a passing verdict of each class establishes, as the fact reported.
SOUNDNESS_MEANING: dict[str, str] = {
    "presence": (
        "a named construct, configuration value, dependency, file or pattern "
        "occurrence exists in the tree. Establishes existence, not behaviour; "
        "a test file existing is presence."
    ),
    "under_approximating_scan": (
        "a syntactic scan over a scope with no false-positive guarantee. A "
        "clean result proves the absence of the syntactic form only, never of "
        "the behaviour."
    ),
    "existential_witness": (
        "a signed statement that a named execution ran and passed at this "
        "commit. Proves the path it drove and nothing beyond it."
    ),
    "sound_over_approximation": (
        "every site in a declared scope that can violate the property was "
        "enumerated, and each is a declared safe form or a reviewed exception. "
        "Sound modulo the declared sink list."
    ),
    "by_construction": (
        "the sink accepts only a declared boundary type, and every construction "
        "site of that type is default-denied. The property holds for every "
        "value that can reach the sink."
    ),
}

# The classes that can credit a clause quantified over every entry of a
# surface (a for-all clause). A witness of any weaker class proves at most
# the path it drove, so it can only ever credit an existential clause; an
# attestation is a responsible party's claim and never substitutes.
SOUND_CLASSES: tuple[str, ...] = ("sound_over_approximation", "by_construction")


# ---------------------------------------------------------------------------
# Parameter specifications
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParamSpec:
    """Specification for an assertion parameter.

    ``pattern`` is an anchored regular expression a scalar string value must
    match when present. For a JSON array value, ``structure`` is ``"array"``
    and the item schema is the remaining fields: ``min_items`` is the
    smallest accepted length; ``enum`` restricts every item to one of the
    listed strings, each at most once; ``item_pattern`` is an anchored
    regular expression every string item must match; ``required_keys``
    names the keys every item (then an object) must carry with a non-empty
    string value; ``key_enums`` restricts named keys of each object item to
    the listed values when the key is present. An array param with none of
    ``enum`` / ``item_pattern`` / ``required_keys`` accepts non-empty
    strings.

    Every format here is the one definition of the value's shape, applied
    by the MCP server before a submission leaves the client and by the
    platform when it arrives, so both refuse the same malformed value with
    the same message.
    """

    name: str
    description: str
    required: bool = True
    example: str = ""
    pattern: str = ""
    structure: str = ""
    min_items: int = 0
    enum: tuple[str, ...] = ()
    item_pattern: str = ""
    required_keys: tuple[str, ...] = ()
    key_enums: tuple[tuple[str, tuple[str, ...]], ...] = ()


# The construct kinds a mechanism may name explicitly (``<file>::<kind>:<name>``).
# This tuple is the one vocabulary: the verifier's definition locator and
# disable adapters and the platform's anchor matcher agree with it exactly,
# and a checker on each side asserts that they do.
MECHANISM_KINDS = (
    "function", "method", "class", "struct", "impl",
    "module", "task", "always", "initial", "property", "sequence", "assert",
    "entity", "architecture", "process", "procedure",
    "interface", "package", "program",
)

# A mechanism reference: a repo-relative file (with an extension, no ``:``,
# not ``../``), ``::``, then a symbol (``name``, ``Owner.leaf``) optionally
# preceded by a kind from ``MECHANISM_KINDS`` and a single ``:``.
MECHANISM_PATTERN = (
    r"^(?!\.\.?/)(?=\S)[^:\r\n]*[^:\s]\.[A-Za-z0-9_+-]+::"
    r"(?:(?:" + "|".join(MECHANISM_KINDS) + r"):)?"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$"
)

# The forms a value may take at a guarded sink position and still be safe
# under a default-deny witness. Anything outside this vocabulary is a
# violation unless the site is allowlisted; there is no taint reasoning.
SAFE_FORMS: tuple[str, ...] = (
    "literal",            # a literal at the position
    "named_constant",     # a name bound once, at module / class / package
                          # scope, to a literal; an HDL parameter, localparam
                          # or constant
    "literal_concat",     # a concatenation whose every operand is safe; a
                          # template with any expression part is a violation
    "parameter_binding",  # a data structure written at the site, carrying
                          # the data beside a fixed statement; read from the
                          # value's own shape, never from the position it
                          # occupies
)

# What a declared sink is. Software and hardware sources are covered by the
# same vocabulary: ``assign`` is a store to a named target (an HDL blocking
# or non-blocking assignment, a field store) and ``instantiate`` a module
# instantiation or ``new``.
SINK_KINDS: tuple[str, ...] = ("call", "constructor", "macro", "assign", "instantiate")

# A scope entry: a repo-relative path, directory or glob. Not absolute, no
# ``..`` segment, no leading or trailing whitespace, one line.
SCOPE_ENTRY_PATTERN = r"^(?!/)(?!\.\.(?:/|$))(?!\s)(?:(?!/\.\.(?:/|$))[^\r\n])*[^\s]\Z"

# A type or callee name, optionally qualified (``pkg.Type``, ``ns::Type``);
# a leading ``$`` admits HDL system tasks.
_NAME_PATTERN = r"^\$?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)\$?[A-Za-z_][A-Za-z0-9_]*)*\Z"

# One sentence, one line, stated in full.
_SENTENCE_PATTERN = r"^(?=\S)[^\r\n]{10,1000}(?<=\S)\Z"


def _array_violation(p: "ParamSpec", value: Any) -> "str | None":
    """Why ``value`` fails ``p``'s item schema, or ``None`` when it passes."""
    if not isinstance(value, list):
        return "expected a JSON array"
    if len(value) < p.min_items:
        return f"at least {p.min_items} item(s) required"
    seen: set = set()
    for i, item in enumerate(value):
        if p.enum:
            if not isinstance(item, str) or item not in p.enum:
                return f"item {i} is not one of {list(p.enum)}"
            if item in seen:
                return f"item {i} repeats {item!r}"
            seen.add(item)
        elif p.required_keys:
            if not isinstance(item, dict):
                return f"item {i} is not an object"
            for key in p.required_keys:
                if not isinstance(item.get(key), str) or not item[key].strip():
                    return f"item {i} lacks {key!r}"
            for key, allowed in p.key_enums:
                if key in item and item[key] not in allowed:
                    return f"item {i} key {key!r} is not one of {list(allowed)}"
        elif p.item_pattern:
            if not isinstance(item, str) or not re.match(p.item_pattern, item):
                return f"item {i} is not in the accepted form"
        elif not isinstance(item, str) or not item.strip():
            return f"item {i} is not a non-empty string"
    return None


def validate_param_formats(type_name: str, params: "dict") -> "list[str]":
    """Errors for params whose declared format the value does not match.

    Pure over the catalogue; the platform and the MCP server both call it.
    A param the type does not declare, or one with neither a ``pattern``
    nor an array structure, is not judged here.
    """
    spec = next((t for t in ASSERTION_TYPES if t.name == type_name), None)
    if spec is None:
        return []
    errors: list[str] = []
    for p in spec.params:
        if p.name not in (params or {}):
            continue
        value = params[p.name]
        if p.structure == "array":
            reason = _array_violation(p, value)
        elif p.pattern:
            if isinstance(value, str) and re.match(p.pattern, value):
                reason = None
            else:
                reason = "" if isinstance(value, str) else "not a string"
        else:
            continue
        if reason is None:
            continue
        hint = f" e.g. {p.example}" if p.example else ""
        detail = f" ({reason})" if reason else ""
        errors.append(
            f"Param '{p.name}' for type '{type_name}' is not in the accepted form{hint}: {value!r}{detail}"
        )
    return errors


def missing_required_params(type_name: str, params: "dict") -> "list[str]":
    """Errors for required params the submission does not carry.

    ``validate_param_formats`` judges the params that are present and says
    nothing about the ones that are absent, so a submission built by naming
    one type and filling another type's parameter set passes every format
    check and is refused only on arrival. The declared params are the one
    definition of what a type requires, so the absence check reads them here
    and reports it in the platform's own words. ``target`` stands in for
    ``file`` on the types that declare it, so a submission carrying one is
    never asked for the other. A type the catalogue does not publish declares
    no params and requires nothing.
    """
    spec = next((t for t in ASSERTION_TYPES if t.name == type_name), None)
    if spec is None:
        return []
    supplied = params if isinstance(params, dict) else {}
    has_target = supplied.get("target") is not None
    return [
        f"Missing required param '{p.name}' for type '{type_name}'"
        for p in spec.params
        if p.required
        and not (p.name == "file" and has_target)
        and p.name not in supplied
    ]


# ---------------------------------------------------------------------------
# Evidence-to-clause binding (``covers``)
# ---------------------------------------------------------------------------

# A type-independent top-level field on a submitted assertion (beside type,
# params, description and repo -- never inside params): the objective ids
# (``CO-NN``; ``CO12`` and ``CO-12`` name the same objective) or clause ids
# (``cls_`` + 12 hex) the evidence is declared to prove. An objective ref
# binds the clause of a single-clause control and scopes the review of a
# multi-clause one; a clause ref binds exactly that clause. The accepted form
# is one definition, applied before a submission leaves the client and again
# on arrival, so both refuse the same value with the same sentence.
COVERS_PATTERN = r"^(?:CO-?\d{1,4}|cls_[0-9a-f]{12})$"
COVERS_MAX = 16

_COVERS_HINT = "an objective id (CO-NN) or a clause id (cls_ + 12 hex)"


def covers_key(value: str) -> str:
    """The identity of one ``covers`` entry: objective refs collapse to
    ``CO-<number>`` so the two accepted spellings compare equal; clause
    ids are their own key."""
    m = re.match(r"^CO-?(\d{1,4})$", value)
    return f"CO-{int(m.group(1))}" if m else value


def validate_covers(values: Any) -> "list[str]":
    """Errors for a ``covers`` value: type, count, per-entry form, duplicates.

    Pure over the catalogue; applied by the MCP server before a submission
    leaves and by the platform on arrival, so both refuse the same value
    with the same message. ``None`` is an absent declaration and passes.
    """
    if values is None:
        return []
    if not isinstance(values, list):
        return [f"covers must be a JSON array, each entry {_COVERS_HINT}: {values!r}"]
    errors: list[str] = []
    if len(values) > COVERS_MAX:
        errors.append(f"covers carries {len(values)} entries; at most {COVERS_MAX} are accepted")
    seen: dict[str, str] = {}
    for i, v in enumerate(values):
        if not isinstance(v, str) or not re.match(COVERS_PATTERN, v):
            errors.append(f"covers[{i}] is not {_COVERS_HINT}: {v!r}")
            continue
        key = covers_key(v)
        if key in seen:
            same = "" if seen[key] == v else f" (the same objective as {seen[key]!r})"
            errors.append(f"covers[{i}] repeats {v!r}{same}")
        else:
            seen[key] = v
    return errors


# ---------------------------------------------------------------------------
# Type specifications
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssertionTypeSpec:
    """Full specification for an assertion type.

    ``soundness`` is the class of the fact the type reports, one of
    ``SOUNDNESS_CLASSES``; it is required, and the catalogue refuses to
    import with a type whose class is missing or unknown.
    """

    name: str
    description: str
    soundness: str
    params: tuple[ParamSpec, ...] = ()
    example: dict[str, Any] | None = None

    @property
    def required_params(self) -> list[str]:
        return [p.name for p in self.params if p.required]

    @property
    def optional_params(self) -> list[str]:
        return [p.name for p in self.params if not p.required]


# -- File path param (reused across many types) --
_FILE = ParamSpec("file", "File path relative to project root", example="backend/app/auth.py")
# Platform-content targets. An assertion may name platform-held content
# instead of a repository file; ``feature_description`` is the model's
# feature description. Both the platform (at submission) and the CI runner
# (at verification) accept exactly these values.
ASSERTION_TARGETS: tuple[str, ...] = ("feature_description",)

# ``target`` replaces ``file`` for an assertion whose content under
# verification is platform-held. A type carries ``target`` only when both
# conjuncts hold: (1) its tier-1 predicate is a caller-supplied regex
# evaluated over arbitrary text, with no source-language structure; and
# (2) its tier-2 criterion and schema description are defined over the
# matched text itself, not over the role the scanned artifact plays in the
# running system. Code-syntax types fail (1): their criterion is stated
# about code — a definition, a call, a decorator, an import — and their
# tier-2 template asks an implementation question, so a design
# specification is not a subject they are defined over. ``no_plaintext_secret``
# fails (2), since its schema text and tier-2 criterion bind its subject to
# a file. The platform derives which types accept a target from this schema
# (see ``TARGET_CAPABLE_TYPES``), so the ``file`` requirement in the schema
# is satisfied by ``target`` on exactly those types.
_TARGET = ParamSpec(
    "target",
    "Platform content to verify instead of a repository file. Valid values: "
    + ", ".join(f'"{t}"' for t in ASSERTION_TARGETS)
    + ". Mutually exclusive with file, which it replaces",
    required=False,
    example=ASSERTION_TARGETS[0],
)
_RTL_FILE = ParamSpec("file", "File path relative to project root", example="rtl/aes_core.sv")

# -- Params shared by the sound witness types --
_SCOPE = ParamSpec(
    "scope",
    "Repo-relative paths, directories or globs naming every source file the "
    "property lives in. Exact: a file in scope that cannot be parsed, or "
    "whose language has no parser, fails the check; a scope that matches "
    "nothing proves nothing. No absolute paths, no `..`.",
    example='["src/db/**/*.py", "src/api/queries.py"]',
    structure="array", min_items=1, item_pattern=SCOPE_ENTRY_PATTERN,
)
_SINKS = ParamSpec(
    "sinks",
    "The sinks through which the property could be violated, each "
    "`{callee, kind?, positions?}`: `callee` is the leaf name of the call, "
    "constructor, macro, assignment target or instantiated module, matched "
    "on any receiver; `kind` is one of " + ", ".join(SINK_KINDS) + " (default "
    "call; `assign` is a store to a named target such as an HDL blocking or "
    "non-blocking assignment, `instantiate` a module instantiation or `new`); "
    "`positions` lists the guarded argument positions (0-based index or "
    "keyword name), every position when omitted. Sound modulo this list: a "
    "sink reached under a name absent from `sinks` and `wrappers` is not "
    "enumerated.",
    example='[{"callee": "execute", "positions": [0]}]',
    structure="array", min_items=1, required_keys=("callee",),
    key_enums=(("kind", SINK_KINDS),),
)
_ALLOWLIST = ParamSpec(
    "allowlist",
    "Reviewed exceptions, each `{file, site, callee, reason, reviewed_by}`; "
    "`site` locates the flagged site (a line or a symbol). Every entry must "
    "match a site the check flags -- a stale entry fails the check -- and "
    "the allowlist content is part of the evidence hash, so an edit reopens "
    "review.",
    required=False,
    example='[{"file": "src/db/admin.py", "site": "42", "callee": "execute", '
            '"reason": "table name from a fixed enum", "reviewed_by": "a.reviewer"}]',
    structure="array", required_keys=("file", "site", "callee", "reason", "reviewed_by"),
)
_WRAPPERS = ParamSpec(
    "wrappers",
    "Names of functions, methods or modules that front a declared sink under "
    "a different name (an interface method, a helper in another package). "
    "Wrappers inside `scope` that pass a parameter into a guarded position "
    "are discovered without being named; declare the ones the check cannot "
    "see.",
    required=False,
    example='["run_query"]',
    structure="array", item_pattern=_NAME_PATTERN,
)
_PROPERTY = ParamSpec(
    "property",
    "One sentence stating the property the sinks realise (the clause this "
    "witness proves). Read by the semantic review of sink adequacy and by "
    "alignment, never by the mechanical check.",
    example="Every SQL statement reaches the driver with data bound as parameters, never interpolated.",
    pattern=_SENTENCE_PATTERN,
)


ASSERTION_TYPES: tuple[AssertionTypeSpec, ...] = (
    # -- Sound witnesses (credit a for-all clause when bound to it) --
    AssertionTypeSpec(
        name="typed_boundary",
        soundness="by_construction",
        description=(
            "Every guarded sink position in `scope` receives a value whose "
            "static form is a construction of `boundary_type` through one of "
            "the declared `constructors`, and every construction site of that "
            "type in scope receives only literal or named-constant arguments "
            "or is an allowlisted site with a reviewed reason; the sink cannot "
            "be reached with a value built any other way. Software and "
            "hardware sources alike: a sink is a call, a constructor, a macro, "
            "a store to a named target or a module instantiation. The strongest "
            "class: state it first when a clause ranges over every entry of a "
            "surface, and bind it to that clause with `covers`. Residual: "
            "construction is tracked by name -- a value counts as constructed "
            "when it is a call to a declared constructor or a name bound once "
            "to one -- and a signed construction statement from your own "
            "build (a probe that builds the type from a non-literal and must "
            "fail to compile) upgrades that residual. Every unclassifiable "
            "site is a violation; a scope that matches nothing proves nothing."
        ),
        params=(
            _SCOPE,
            _SINKS,
            ParamSpec(
                "boundary_type",
                "The type the sinks accept, optionally qualified "
                "(`SafeSql`, `sql.Identifier`, `pkg::safe_addr_t`).",
                example="SafeSql",
                pattern=_NAME_PATTERN,
            ),
            ParamSpec(
                "constructors",
                "The names (optionally qualified) through which a "
                "`boundary_type` value may be built; every other construction "
                "is a violation.",
                example='["SafeSql.literal", "SafeSql.identifier"]',
                structure="array", min_items=1, item_pattern=_NAME_PATTERN,
            ),
            _ALLOWLIST,
            _WRAPPERS,
            _PROPERTY,
        ),
    ),
    AssertionTypeSpec(
        name="sink_default_deny",
        soundness="sound_over_approximation",
        description=(
            "Over every source file in `scope`, every site of a declared sink "
            "receives, at each guarded position, only a form the `safe_forms` "
            "vocabulary accepts or is an allowlisted site with a reviewed "
            "reason; every site the check could not classify counts as a "
            "violation; a scope that matches nothing proves nothing. Software "
            "and hardware sources alike: a sink is a call, a constructor, a "
            "macro, a store to a named target (an HDL blocking or non-blocking "
            "assignment, a field store) or a module instantiation, and "
            "wrappers in scope that forward a parameter into a guarded "
            "position are sinks too. Sound modulo the sink list: a sink "
            "reached under a name absent from `sinks` and `wrappers` is not "
            "enumerated, and the semantic review asks whether the declared "
            "sinks are the ones through which `property` could be violated in "
            "the code shown. Credits a for-all clause when bound to it with "
            "`covers`; prefer typed_boundary where the sinks accept a boundary "
            "type."
        ),
        params=(
            _SCOPE,
            _SINKS,
            ParamSpec(
                "safe_forms",
                "The forms accepted at a guarded position, a non-empty subset "
                "of " + ", ".join(SAFE_FORMS) + ": `literal`; `named_constant` "
                "(a name bound once at module, class or package scope to a "
                "literal, or an HDL parameter, localparam or constant); "
                "`literal_concat` (every operand safe; a template with any "
                "expression part is a violation); `parameter_binding` (a data "
                "structure written at the site, carrying the data beside a "
                "fixed statement -- read from the value's own shape, never "
                "from the position it occupies). What `parameter_binding` "
                "establishes is that the statement reaching the sink is "
                "fixed, so admit it only for a sink that takes the structure "
                "as data; where a sink reads one of its entries as the "
                "statement, the form that proves the property is a boundary "
                "type. No taint reasoning: anything else is a violation.",
                example='["parameter_binding", "literal"]',
                structure="array", min_items=1, enum=SAFE_FORMS,
            ),
            _ALLOWLIST,
            _WRAPPERS,
            _PROPERTY,
        ),
    ),

    # -- Code structure --
    AssertionTypeSpec(
        name="function_exists",
        soundness="presence",
        description=(
            "Check that a function or method exists in a file. Supports "
            "Python, JavaScript, TypeScript, Go, Rust, Swift, Java, C#. "
            "Presence only: a test file's function existing proves nothing "
            "ran and never anchors a test."
        ),
        params=(
            _FILE,
            ParamSpec("name", "Function or method name", example="verify_token"),
        ),
    ),
    AssertionTypeSpec(
        name="class_exists",
        soundness="presence",
        description=(
            "Check that a class, struct, or interface exists in a file. "
            "Presence only: a test file's class existing proves nothing ran "
            "and never anchors a test."
        ),
        params=(
            _FILE,
            ParamSpec("name", "Class, struct, or interface name", example="UserIdentity"),
        ),
    ),
    AssertionTypeSpec(
        name="decorator_present",
        soundness="presence",
        description="Check that a decorator is applied to a function (Python).",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="protected_route"),
            ParamSpec("decorator", "Decorator name (without @)", example="require_auth"),
        ),
    ),
    AssertionTypeSpec(
        name="function_calls",
        soundness="presence",
        description="Check that a function calls another function.",
        params=(
            _FILE,
            ParamSpec("caller", "Calling function name", example="login"),
            ParamSpec("callee", "Called function name", example="hash_password"),
        ),
    ),
    AssertionTypeSpec(
        name="import_present",
        soundness="presence",
        description="Check that a module is imported in a file. Supports Python, JavaScript, Go, Rust.",
        params=(
            _FILE,
            ParamSpec("module", "Module or package name", example="hashlib"),
        ),
    ),

    # -- File-based --
    AssertionTypeSpec(
        name="file_exists",
        soundness="presence",
        description="Check that a file exists at the given path.",
        params=(_FILE,),
    ),
    AssertionTypeSpec(
        name="file_hash",
        soundness="presence",
        description="Check that a file's hash matches an expected value. Use scope_file/scope_start/scope_end to reference the code that pins this hash (e.g., a deploy script that verifies the file's integrity).",
        params=(
            _FILE,
            ParamSpec("algorithm", "Hash algorithm: sha256, sha384, sha512, md5", example="sha256"),
            ParamSpec("expected_hash", "Expected hex-encoded hash", example="a1b2c3..."),
            ParamSpec("scope_file", "File containing code that references/checks this hash. Tier 2 reviews this code to verify the hash check is meaningful.", example="deploy/verify.py"),
            ParamSpec("scope_start", "Regex marking start of the relevant code section in scope_file.", required=False, example="def verify_config"),
            ParamSpec("scope_end", "Regex marking end of the relevant code section in scope_file.", required=False, example="^def |\\Z"),
        ),
    ),
    AssertionTypeSpec(
        name="pattern_matches",
        soundness="under_approximating_scan",
        description=(
            "Check that a regex pattern exists in a file. Uses RE2 syntax (no "
            "backreferences, lookahead, or lookbehind). A syntactic scan: a "
            "match proves only that the text occurs, not that the code behaves "
            "as the pattern suggests, and it says nothing about sites the "
            "pattern does not describe."
        ),
        params=(
            _FILE,
            ParamSpec("pattern", "RE2 regex pattern to search for", example="force_https\\s*=\\s*true"),
            ParamSpec("scope_start", "Regex pattern marking the start of the search scope within the file. Only content between scope_start and scope_end is searched.", required=False, example="class.*Client"),
            ParamSpec("scope_end", "Regex pattern marking the end of the search scope. Defaults to end of file if omitted.", required=False, example="^class |\\Z"),
            ParamSpec("multiline", "If true, ^ and $ match line boundaries instead of string boundaries. Default: false.", required=False, example="true"),
            ParamSpec("dotall", "If true, . matches newlines, enabling patterns that span multiple lines. Default: false.", required=False, example="true"),
            _TARGET,
        ),
    ),
    AssertionTypeSpec(
        name="pattern_absent",
        soundness="under_approximating_scan",
        description=(
            "Check that a regex pattern does NOT exist in a file. Uses RE2 "
            "syntax (no backreferences, lookahead, or lookbehind). A "
            "syntactic scan: a clean result proves the absence of that "
            "syntactic form in that file only, never the absence of the "
            "behaviour by another spelling or in another file."
        ),
        params=(
            _FILE,
            ParamSpec("pattern", "RE2 regex pattern that must be absent", example="verify\\s*=\\s*False"),
            ParamSpec("scope_start", "Regex pattern marking the start of the search scope within the file. Only content between scope_start and scope_end is checked for absence.", required=False, example="class.*Client"),
            ParamSpec("scope_end", "Regex pattern marking the end of the search scope. Defaults to end of file if omitted.", required=False, example="^class |\\Z"),
            ParamSpec("multiline", "If true, ^ and $ match line boundaries instead of string boundaries. Default: false.", required=False, example="true"),
            ParamSpec("dotall", "If true, . matches newlines, enabling patterns that span multiple lines. Default: false.", required=False, example="true"),
            _TARGET,
        ),
    ),
    AssertionTypeSpec(
        name="no_plaintext_secret",
        soundness="under_approximating_scan",
        description=(
            "Check that no plaintext secrets matching given patterns exist in "
            "a file. Patterns use RE2 syntax (no backreferences, lookahead, or "
            "lookbehind). A syntactic scan: a clean result proves only that "
            "none of the given patterns occurs in that file."
        ),
        params=(
            _FILE,
            ParamSpec("patterns", "JSON array of regex patterns to check for secrets", example='["password\\\\s*=\\\\s*[\'\\"].*[\'\\"]"]'),
        ),
    ),

    # -- Configuration --
    AssertionTypeSpec(
        name="config_key_exists",
        soundness="presence",
        description="Check that a config key exists. Supports JSON, YAML, TOML, INI, .env files. Use dot notation for nested keys.",
        params=(
            _FILE,
            ParamSpec("key", "Config key (dot notation for nested)", example="database.host"),
        ),
    ),
    AssertionTypeSpec(
        name="config_value_matches",
        soundness="presence",
        description="Check that a config value matches a regex pattern. Uses RE2 syntax (no backreferences, lookahead, or lookbehind).",
        params=(
            _FILE,
            ParamSpec("key", "Config key (dot notation for nested)", example="http_service.force_https"),
            ParamSpec("pattern", "RE2 regex pattern the value must match", example="True|true"),
        ),
    ),
    AssertionTypeSpec(
        name="env_var_referenced",
        soundness="presence",
        description="Check that an environment variable is referenced in a file. Detects os.environ, process.env, ${VAR}, $VAR, etc.",
        params=(
            _FILE,
            ParamSpec("variable", "Environment variable name", example="DATABASE_URL"),
        ),
    ),

    # -- Dependencies --
    AssertionTypeSpec(
        name="dependency_exists",
        soundness="presence",
        description="Check that a package exists in a dependency manifest. Supports requirements.txt, package.json, Cargo.toml, go.mod, pyproject.toml, pom.xml.",
        params=(
            ParamSpec("manifest", "Path to dependency manifest file", example="requirements.txt"),
            ParamSpec("package", "Package name", example="cryptography"),
        ),
    ),
    AssertionTypeSpec(
        name="dependency_version",
        soundness="presence",
        description="Check that a package version satisfies a constraint. Uses PEP 440 syntax for Python, semver for JS.",
        params=(
            ParamSpec("manifest", "Path to dependency manifest file", example="requirements.txt"),
            ParamSpec("package", "Package name", example="cryptography"),
            ParamSpec("constraint", "Version constraint (PEP 440 or semver)", example=">=41.0.0"),
        ),
    ),

    # -- Semantic (tier 1: structural check, tier 2: AI verification) --
    AssertionTypeSpec(
        name="parameter_validated",
        soundness="presence",
        description="Check that a function validates a specific parameter. Tier 1 checks existence, tier 2 uses AI to verify validation logic.",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="create_user"),
            ParamSpec("parameter", "Parameter name that should be validated", example="email"),
        ),
    ),
    AssertionTypeSpec(
        name="error_handled",
        soundness="presence",
        description="Check that a function has error handling (try/catch/except, Go error checks, Rust Result).",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="query_database"),
        ),
    ),
    AssertionTypeSpec(
        name="middleware_registered",
        soundness="presence",
        description="Check that middleware is registered in a file. Detects .use(), .add_middleware(), @decorator patterns.",
        params=(
            _FILE,
            ParamSpec("middleware", "Middleware name or class", example="CORSMiddleware"),
        ),
    ),
    AssertionTypeSpec(
        name="http_header_set",
        soundness="presence",
        description="Check that an HTTP header is set or referenced in a file.",
        params=(
            _FILE,
            ParamSpec("header", "HTTP header name", example="Strict-Transport-Security"),
        ),
    ),

    # -- Tests --
    AssertionTypeSpec(
        name="test_exists",
        soundness="presence",
        description=(
            "Check that files matching a glob pattern exist. Proves nothing "
            "ran: a test file in the tree is presence, not a passing test. "
            "Use test_attested for the run."
        ),
        params=(
            ParamSpec("pattern", "Glob pattern for test files", example="tests/test_auth*.py"),
        ),
    ),
    AssertionTypeSpec(
        name="test_attested",
        soundness="existential_witness",
        description=(
            "Check a signed statement from your CI that a named test ran and "
            "passed, against the commit under verification. Proves the test "
            "passed in this repository's workflow at this commit -- the path "
            "it drove, and nothing beyond it: an existential witness credits "
            "a clause about one behaviour, never a clause that ranges over "
            "every entry of a surface (that needs typed_boundary or "
            "sink_default_deny). Use it for a behavioral clause, beside a "
            "structural assertion for the mechanism. Name that mechanism in "
            "`mechanism` so the evidence is bound to it; a test-backed "
            "citation with no structural anchor on the control does not "
            "cover a runtime clause, and a clause worded as configuration "
            "still needs the test. The attestation records the test's "
            "definition; a later change to the test withdraws the accepted "
            "verdict until the test is reviewed again. `mipiti-verify "
            "attest-tests --coverage <coverage.json>` records what the test "
            "reached and `mipiti-verify attest-dependence` records whether it "
            "fails with the mechanism disabled; a runtime clause is credited "
            "on those facts, not on the test's name. An unsigned statement, "
            "or a run nobody attested, still covers the clause but is "
            "reported as a claim rather than a witness. "
            "Verification reads the statement and runs nothing: "
            "add 'mipiti-verify attest-tests --junit <report>' to the job that "
            "already runs your tests, after them. A run that selected no "
            "tests, or in which nothing passed, is refused."
        ),
        params=(
            ParamSpec(
                "test",
                "Name of the test the attestation must contain",
                example="test_rejects_expired_token",
            ),
            ParamSpec(
                "env",
                "Environment the attested run must have had: a mapping of "
                "variable name to required value, null meaning the variable "
                "must have been unset. The run records only the names your "
                "CI nominates when attesting; a run that recorded none fails "
                "this check.",
                required=False,
                example='{"FEATURE_AUTH": "on"}',
            ),
            ParamSpec(
                "mechanism",
                "The mechanism this test exercises, as "
                "`<repo-relative file>::<symbol>` (`app/auth.py::require_token`, "
                "`app/auth.py::Auth.check`), or `<file>::<kind>:<name>` where the "
                "bare name is ambiguous or the mechanism is a hardware construct "
                "(`rtl/alu.sv::module:alu`, `rtl/fsm.sv::always:seq_logic`). "
                "Binding rule: the value must equal the file plus the identifying "
                "param of a structural assertion on the same control: `name` "
                "(function_exists, class_exists, module_exists, signal_exists, "
                "sva_assertion_present), `function` (decorator_present, "
                "parameter_validated, error_handled), `middleware` "
                "(middleware_registered), `key` (config_key_exists, "
                "config_value_matches; a source kwarg such as "
                "`allow_origin_regex=` counts), `module` (import_present), "
                "`callee` or `caller` (function_calls), `header`, `variable`, "
                "`package` (with the manifest as the file), `child` or `parent`, "
                "`port`, `parameter`, `signal`. pattern_matches, pattern_absent, "
                "file_hash and no_plaintext_secret name no symbol and anchor any "
                "mechanism in their file. A test file is never a mechanism and "
                "never an anchor. The platform credits a runtime clause with "
                "this test only when that anchor exists and passes tier 1; a "
                "test with no anchor leaves the clause insufficient, and the "
                "sufficiency report lists the exact values it accepts. "
                "Re-submitting the same test with a different `mechanism` "
                "replaces the earlier row rather than adding a second one. With "
                "CI-attested coverage (`attest-tests --coverage` or "
                "`attest-reach`) and dependence (`attest-dependence`) the clause "
                "is credited only when the test reached the mechanism and fails "
                "without it. Omit only when the control has exactly one "
                "structural assertion; then that one is the anchor.",
                required=False,
                pattern=MECHANISM_PATTERN,
                example="app/auth.py::require_token",
            ),
        ),
    ),

    # -- RTL / hardware (Verilog & SystemVerilog) --
    AssertionTypeSpec(
        name="module_exists",
        soundness="presence",
        description="Check that a Verilog/SystemVerilog module (or primitive/program) is declared in a file.",
        params=(
            _RTL_FILE,
            ParamSpec("name", "Module name", example="aes_key_expand"),
        ),
    ),
    AssertionTypeSpec(
        name="module_instantiated",
        soundness="presence",
        description="Check that a module directly instantiates another module inside its module...endmodule body.",
        params=(
            _RTL_FILE,
            ParamSpec("parent", "Enclosing module name", example="soc_top"),
            ParamSpec("child", "Instantiated module name", example="aes_core"),
        ),
    ),
    AssertionTypeSpec(
        name="port_exists",
        soundness="presence",
        description="Check that a module declares a port, optionally with a specific direction. Detects ANSI header and non-ANSI body declarations.",
        params=(
            _RTL_FILE,
            ParamSpec("module", "Module name", example="aes_core"),
            ParamSpec("port", "Port name", example="key_clear"),
            ParamSpec("direction", "Port direction: input, output, or inout", required=False, example="input"),
        ),
    ),
    AssertionTypeSpec(
        name="parameter_defined",
        soundness="presence",
        description="Check that a parameter or localparam is declared, optionally that its assigned value matches a regex (RE2 syntax).",
        params=(
            _RTL_FILE,
            ParamSpec("parameter", "Parameter or localparam name", example="KEY_WIDTH"),
            ParamSpec("module", "Module to scope the search to (whole file if omitted)", required=False, example="aes_core"),
            ParamSpec("pattern", "RE2 regex the assigned value must match", required=False, example="256"),
        ),
    ),
    AssertionTypeSpec(
        name="signal_exists",
        soundness="presence",
        description="Check that a net or variable (wire, reg, logic, bit) is declared.",
        params=(
            _RTL_FILE,
            ParamSpec("name", "Signal name", example="key_valid"),
            ParamSpec("module", "Module to scope the search to (whole file if omitted)", required=False, example="aes_core"),
            ParamSpec("kind", "Declaration kind: wire, reg, logic, or bit", required=False, example="logic"),
        ),
    ),
    AssertionTypeSpec(
        name="sva_assertion_present",
        soundness="presence",
        description="Check that a named SystemVerilog assertion is present: a property declaration, or a labelled assert/assume/cover statement.",
        params=(
            _RTL_FILE,
            ParamSpec("name", "Property name or assertion label", example="p_key_cleared_on_reset"),
        ),
    ),
    AssertionTypeSpec(
        name="register_reset",
        soundness="presence",
        description="Check that a register is assigned on a reset path. Tier 1 finds an always block that references the reset and assigns the signal; tier 2 uses AI to verify the register resets to a safe, known value.",
        params=(
            _RTL_FILE,
            ParamSpec("signal", "Register/signal name that must be reset", example="key_reg"),
            ParamSpec("reset", "Reset signal name (common rst/reset names detected if omitted)", required=False, example="rst_n"),
        ),
    ),
)


def _check_catalogue() -> None:
    """The invariants a well-formed catalogue holds, checked at import so a
    type with a missing or unknown soundness class, or a malformed param
    schema, cannot be published."""
    names: set[str] = set()
    for t in ASSERTION_TYPES:
        if t.name in names:
            raise ValueError(f"assertion type {t.name!r} is declared twice")
        names.add(t.name)
        if t.soundness not in SOUNDNESS_CLASSES:
            raise ValueError(
                f"assertion type {t.name!r} declares soundness {t.soundness!r}, "
                f"not one of {list(SOUNDNESS_CLASSES)}"
            )
        param_names = [p.name for p in t.params]
        if len(set(param_names)) != len(param_names):
            raise ValueError(f"assertion type {t.name!r} declares a param twice")
        for p in t.params:
            if p.structure not in ("", "array"):
                raise ValueError(f"{t.name}.{p.name}: unknown structure {p.structure!r}")
            if p.structure == "array" and p.pattern:
                raise ValueError(f"{t.name}.{p.name}: an array param declares an item schema, not a pattern")
            if p.min_items < 0:
                raise ValueError(f"{t.name}.{p.name}: min_items must be non-negative")
            if len(set(p.enum)) != len(p.enum):
                raise ValueError(f"{t.name}.{p.name}: enum repeats a value")
            keys = [k for k, _ in p.key_enums]
            if len(set(keys)) != len(keys):
                raise ValueError(f"{t.name}.{p.name}: key_enums names a key twice")
        if t.soundness in SOUND_CLASSES and ({"file", "target"} & set(param_names)):
            # A sound witness ranges over a declared scope, never one file,
            # and its subject is never platform-held text.
            raise ValueError(f"sound witness {t.name!r} must not declare file or target")


_check_catalogue()

# -- Derived lookups --

ASSERTION_TYPE_NAMES: frozenset[str] = frozenset(t.name for t in ASSERTION_TYPES)

ASSERTION_PARAM_SCHEMAS: dict[str, list[str]] = {
    t.name: t.required_params for t in ASSERTION_TYPES
}

# The soundness class per type, and the lookup the platform and the CI
# verifier read instead of keeping their own lists.
SOUNDNESS_BY_TYPE: dict[str, str] = {t.name: t.soundness for t in ASSERTION_TYPES}


def soundness_of(name: str) -> str:
    """The soundness class declared for ``name``; ``KeyError`` for a type
    the catalogue does not publish."""
    return SOUNDNESS_BY_TYPE[name]


def soundness_rank_of(name: str) -> int:
    """The declared class's rank, weakest 0 to strongest 4."""
    return SOUNDNESS_RANK[soundness_of(name)]


# Types on which ``target`` may replace ``file``. Derived from the specs so
# the documented shape and the enforced shape cannot diverge.
TARGET_CAPABLE_TYPES: frozenset[str] = frozenset(
    t.name for t in ASSERTION_TYPES if any(p.name == "target" for p in t.params)
)

# Types whose declared class can credit a for-all clause. Derived, so the
# table and the rule cannot disagree.
SOUND_TYPES: tuple[str, ...] = tuple(t.name for t in ASSERTION_TYPES if t.soundness in SOUND_CLASSES)


def _types_by_class() -> "list[tuple[str, list[AssertionTypeSpec]]]":
    """The types grouped by class, strongest class first, each group in
    catalogue order."""
    groups: list[tuple[str, list[AssertionTypeSpec]]] = []
    for cls in reversed(SOUNDNESS_CLASSES):
        members = [t for t in ASSERTION_TYPES if t.soundness == cls]
        if members:
            groups.append((cls, members))
    return groups


def format_for_docstring() -> str:
    """Generate a human-readable assertion type reference for tool docstrings."""
    lines = []
    for t in ASSERTION_TYPES:
        req = ", ".join(
            f"{p.name} ({p.description})" for p in t.params if p.required
        )
        opt_params = [p for p in t.params if not p.required]
        opt = ""
        if opt_params:
            opt = "; optional: " + ", ".join(
                f"{p.name} ({p.description})" for p in opt_params
            )
        lines.append(f"  - {t.name} [{t.soundness}]: {t.description} Params: {req}{opt}")
    return "\n".join(lines)


def format_compact() -> str:
    """One short line per type -- the name and its params -- under a heading
    per soundness class, strongest class first.

    A tool description is prose that a client may truncate, so the full
    reference cannot be the only place the contract lives. This form is small
    enough to survive intact and carries what a caller needs to construct a
    valid assertion and to pick the class a clause needs; ``describe_types``
    supplies the rest on demand.
    """
    lines = []
    for cls, members in _types_by_class():
        lines.append(f"  [{cls}]")
        for t in members:
            line = f"  - {t.name}({', '.join(t.required_params)})"
            if t.optional_params:
                line += f" [opt: {', '.join(t.optional_params)}]"
            lines.append(line)
    return "\n".join(lines)


def _describe_param(p: ParamSpec) -> dict:
    out: dict[str, Any] = {"name": p.name, "description": p.description, "example": p.example}
    if p.pattern:
        out["pattern"] = p.pattern
    if p.structure == "array":
        out["structure"] = "array"
        schema: dict[str, Any] = {"min_items": p.min_items}
        if p.enum:
            schema["enum"] = list(p.enum)
        if p.item_pattern:
            schema["item_pattern"] = p.item_pattern
        if p.required_keys:
            schema["required_keys"] = list(p.required_keys)
        if p.key_enums:
            schema["key_enums"] = {k: list(v) for k, v in p.key_enums}
        out["item_schema"] = schema
    return out


def describe_soundness_classes() -> list:
    """The class vocabulary as data: name, rank, what a pass establishes,
    and whether the class can credit a for-all clause."""
    return [
        {
            "name": cls,
            "rank": SOUNDNESS_RANK[cls],
            "meaning": SOUNDNESS_MEANING[cls],
            "credits_for_all": cls in SOUND_CLASSES,
        }
        for cls in SOUNDNESS_CLASSES
    ]


def describe_types(names: "list[str] | None" = None) -> list:
    """Structured catalogue, for callers that need descriptions and examples.

    Returned as data rather than prose so it cannot be truncated into a
    half-list that reads as complete. Each entry carries the type's
    soundness class; an array-valued param carries its item schema.
    """
    wanted = {n.strip() for n in names if n and n.strip()} if names else None
    out = []
    for t in ASSERTION_TYPES:
        if wanted is not None and t.name not in wanted:
            continue
        out.append({
            "type": t.name,
            "soundness": t.soundness,
            "description": t.description,
            "required_params": [_describe_param(p) for p in t.params if p.required],
            "optional_params": [_describe_param(p) for p in t.params if not p.required],
            "example": t.example,
        })
    return out

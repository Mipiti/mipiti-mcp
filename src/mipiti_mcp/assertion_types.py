"""Canonical assertion type schema.

Single source of truth for assertion types, their required/optional params,
param descriptions, and examples. Consumed by:

- MCP server: generates submit_assertions docstring
- Backend validation: imports required param lists
- Documentation: generates assertion type reference
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParamSpec:
    """Specification for an assertion parameter.

    ``pattern`` is an anchored regular expression the value must match when
    present; it is the one definition of the value's format, applied by the
    MCP server before a submission leaves the client and by the platform when
    it arrives, so both refuse the same malformed value with the same message.
    """

    name: str
    description: str
    required: bool = True
    example: str = ""
    pattern: str = ""


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


def validate_param_formats(type_name: str, params: "dict") -> "list[str]":
    """Errors for params whose declared ``pattern`` the value does not match.

    Pure over the catalogue; the platform and the MCP server both call it.
    A param the type does not declare, or one with no pattern, is not judged
    here.
    """
    import re as _re

    spec = next((t for t in ASSERTION_TYPES if t.name == type_name), None)
    if spec is None:
        return []
    errors: list[str] = []
    for p in spec.params:
        if not p.pattern or p.name not in (params or {}):
            continue
        value = params[p.name]
        if not isinstance(value, str) or not _re.match(p.pattern, value):
            hint = f" e.g. {p.example}" if p.example else ""
            errors.append(
                f"Param '{p.name}' for type '{type_name}' is not in the accepted form{hint}: {value!r}"
            )
    return errors


@dataclass(frozen=True)
class AssertionTypeSpec:
    """Full specification for an assertion type."""

    name: str
    description: str
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


ASSERTION_TYPES: tuple[AssertionTypeSpec, ...] = (
    # -- Code structure --
    AssertionTypeSpec(
        name="function_exists",
        description="Check that a function or method exists in a file. Supports Python, JavaScript, TypeScript, Go, Rust, Swift, Java, C#.",
        params=(
            _FILE,
            ParamSpec("name", "Function or method name", example="verify_token"),
        ),
    ),
    AssertionTypeSpec(
        name="class_exists",
        description="Check that a class, struct, or interface exists in a file.",
        params=(
            _FILE,
            ParamSpec("name", "Class, struct, or interface name", example="UserIdentity"),
        ),
    ),
    AssertionTypeSpec(
        name="decorator_present",
        description="Check that a decorator is applied to a function (Python).",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="protected_route"),
            ParamSpec("decorator", "Decorator name (without @)", example="require_auth"),
        ),
    ),
    AssertionTypeSpec(
        name="function_calls",
        description="Check that a function calls another function.",
        params=(
            _FILE,
            ParamSpec("caller", "Calling function name", example="login"),
            ParamSpec("callee", "Called function name", example="hash_password"),
        ),
    ),
    AssertionTypeSpec(
        name="import_present",
        description="Check that a module is imported in a file. Supports Python, JavaScript, Go, Rust.",
        params=(
            _FILE,
            ParamSpec("module", "Module or package name", example="hashlib"),
        ),
    ),

    # -- File-based --
    AssertionTypeSpec(
        name="file_exists",
        description="Check that a file exists at the given path.",
        params=(_FILE,),
    ),
    AssertionTypeSpec(
        name="file_hash",
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
        description="Check that a regex pattern exists in a file. Uses RE2 syntax (no backreferences, lookahead, or lookbehind).",
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
        description="Check that a regex pattern does NOT exist in a file. Uses RE2 syntax (no backreferences, lookahead, or lookbehind).",
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
        description="Check that no plaintext secrets matching given patterns exist in a file. Patterns use RE2 syntax (no backreferences, lookahead, or lookbehind).",
        params=(
            _FILE,
            ParamSpec("patterns", "JSON array of regex patterns to check for secrets", example='["password\\\\s*=\\\\s*[\'\\"].*[\'\\"]"]'),
        ),
    ),

    # -- Configuration --
    AssertionTypeSpec(
        name="config_key_exists",
        description="Check that a config key exists. Supports JSON, YAML, TOML, INI, .env files. Use dot notation for nested keys.",
        params=(
            _FILE,
            ParamSpec("key", "Config key (dot notation for nested)", example="database.host"),
        ),
    ),
    AssertionTypeSpec(
        name="config_value_matches",
        description="Check that a config value matches a regex pattern. Uses RE2 syntax (no backreferences, lookahead, or lookbehind).",
        params=(
            _FILE,
            ParamSpec("key", "Config key (dot notation for nested)", example="http_service.force_https"),
            ParamSpec("pattern", "RE2 regex pattern the value must match", example="True|true"),
        ),
    ),
    AssertionTypeSpec(
        name="env_var_referenced",
        description="Check that an environment variable is referenced in a file. Detects os.environ, process.env, ${VAR}, $VAR, etc.",
        params=(
            _FILE,
            ParamSpec("variable", "Environment variable name", example="DATABASE_URL"),
        ),
    ),

    # -- Dependencies --
    AssertionTypeSpec(
        name="dependency_exists",
        description="Check that a package exists in a dependency manifest. Supports requirements.txt, package.json, Cargo.toml, go.mod, pyproject.toml, pom.xml.",
        params=(
            ParamSpec("manifest", "Path to dependency manifest file", example="requirements.txt"),
            ParamSpec("package", "Package name", example="cryptography"),
        ),
    ),
    AssertionTypeSpec(
        name="dependency_version",
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
        description="Check that a function validates a specific parameter. Tier 1 checks existence, tier 2 uses AI to verify validation logic.",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="create_user"),
            ParamSpec("parameter", "Parameter name that should be validated", example="email"),
        ),
    ),
    AssertionTypeSpec(
        name="error_handled",
        description="Check that a function has error handling (try/catch/except, Go error checks, Rust Result).",
        params=(
            _FILE,
            ParamSpec("function", "Function name", example="query_database"),
        ),
    ),
    AssertionTypeSpec(
        name="middleware_registered",
        description="Check that middleware is registered in a file. Detects .use(), .add_middleware(), @decorator patterns.",
        params=(
            _FILE,
            ParamSpec("middleware", "Middleware name or class", example="CORSMiddleware"),
        ),
    ),
    AssertionTypeSpec(
        name="http_header_set",
        description="Check that an HTTP header is set or referenced in a file.",
        params=(
            _FILE,
            ParamSpec("header", "HTTP header name", example="Strict-Transport-Security"),
        ),
    ),

    # -- Tests --
    AssertionTypeSpec(
        name="test_exists",
        description="Check that test files matching a glob pattern exist.",
        params=(
            ParamSpec("pattern", "Glob pattern for test files", example="tests/test_auth*.py"),
        ),
    ),
    AssertionTypeSpec(
        name="test_attested",
        description=(
            "Check a signed statement from your CI that a named test ran and "
            "passed, against the commit under verification. Proves the test "
            "passed in this repository's workflow at this commit; use it for "
            "a behavioral clause, beside a structural assertion for the "
            "mechanism. Name that mechanism in `mechanism` so the evidence "
            "is bound to it. The attestation records the test's definition; "
            "a later change to the test withdraws the accepted verdict until "
            "the test is reviewed again. `mipiti-verify attest-tests "
            "--coverage <coverage.json>` records what the test reached and "
            "`mipiti-verify attest-dependence` records whether it fails with "
            "the mechanism disabled; a runtime clause is credited on those "
            "facts, not on the test's name. "
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
                "`<repo-relative file>::<symbol>` (a function, class, or "
                "`Class.method`), or `<file>::<kind>:<name>` where the bare "
                "name is ambiguous or the mechanism is a hardware construct "
                "(`rtl/alu.sv::module:alu`, `rtl/fsm.sv::always:seq_logic`, "
                "`hdl/ctl.vhd::process:p_ctl`). Matches a structural "
                "assertion on the same control (for example a "
                "`function_exists` or `module_exists` on that file and name) "
                "and names the anchor the test's evidence is bound to: the "
                "platform credits a runtime clause with this test only when "
                "the anchor exists, and, when the CI run attests coverage "
                "(`attest-tests --coverage` or `attest-reach`) and "
                "dependence (`attest-dependence`), only when the test reached "
                "the mechanism and fails without it. Omit only when the "
                "control has exactly one structural assertion; then that one "
                "is the anchor.",
                required=False,
                pattern=MECHANISM_PATTERN,
                example="app/auth.py::require_token",
            ),
        ),
    ),

    # -- RTL / hardware (Verilog & SystemVerilog) --
    AssertionTypeSpec(
        name="module_exists",
        description="Check that a Verilog/SystemVerilog module (or primitive/program) is declared in a file.",
        params=(
            _RTL_FILE,
            ParamSpec("name", "Module name", example="aes_key_expand"),
        ),
    ),
    AssertionTypeSpec(
        name="module_instantiated",
        description="Check that a module directly instantiates another module inside its module...endmodule body.",
        params=(
            _RTL_FILE,
            ParamSpec("parent", "Enclosing module name", example="soc_top"),
            ParamSpec("child", "Instantiated module name", example="aes_core"),
        ),
    ),
    AssertionTypeSpec(
        name="port_exists",
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
        description="Check that a named SystemVerilog assertion is present: a property declaration, or a labelled assert/assume/cover statement.",
        params=(
            _RTL_FILE,
            ParamSpec("name", "Property name or assertion label", example="p_key_cleared_on_reset"),
        ),
    ),
    AssertionTypeSpec(
        name="register_reset",
        description="Check that a register is assigned on a reset path. Tier 1 finds an always block that references the reset and assigns the signal; tier 2 uses AI to verify the register resets to a safe, known value.",
        params=(
            _RTL_FILE,
            ParamSpec("signal", "Register/signal name that must be reset", example="key_reg"),
            ParamSpec("reset", "Reset signal name (common rst/reset names detected if omitted)", required=False, example="rst_n"),
        ),
    ),
)

# -- Derived lookups --

ASSERTION_TYPE_NAMES: frozenset[str] = frozenset(t.name for t in ASSERTION_TYPES)



ASSERTION_PARAM_SCHEMAS: dict[str, list[str]] = {
    t.name: t.required_params for t in ASSERTION_TYPES
}

# Types on which ``target`` may replace ``file``. Derived from the specs so
# the documented shape and the enforced shape cannot diverge.
TARGET_CAPABLE_TYPES: frozenset[str] = frozenset(
    t.name for t in ASSERTION_TYPES if any(p.name == "target" for p in t.params)
)


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
        lines.append(f"  - {t.name}: {t.description} Params: {req}{opt}")
    return "\n".join(lines)


def format_compact() -> str:
    """One short line per type: the name and its required params.

    A tool description is prose that a client may truncate, so the full
    reference cannot be the only place the contract lives. This form is small
    enough to survive intact and carries what a caller needs to construct a
    valid assertion; ``describe_types`` supplies the rest on demand.
    """
    lines = []
    for t in ASSERTION_TYPES:
        line = f"  - {t.name}({', '.join(t.required_params)})"
        if t.optional_params:
            line += f" [opt: {', '.join(t.optional_params)}]"
        lines.append(line)
    return "\n".join(lines)


def describe_types(names: "list[str] | None" = None) -> list:
    """Structured catalogue, for callers that need descriptions and examples.

    Returned as data rather than prose so it cannot be truncated into a
    half-list that reads as complete.
    """
    wanted = {n.strip() for n in names if n and n.strip()} if names else None
    out = []
    for t in ASSERTION_TYPES:
        if wanted is not None and t.name not in wanted:
            continue
        out.append({
            "type": t.name,
            "description": t.description,
            "required_params": [
                {"name": p.name, "description": p.description, "example": p.example}
                for p in t.params if p.required
            ],
            "optional_params": [
                {"name": p.name, "description": p.description, "example": p.example}
                for p in t.params if not p.required
            ],
            "example": t.example,
        })
    return out

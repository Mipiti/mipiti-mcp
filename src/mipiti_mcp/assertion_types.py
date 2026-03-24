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
    """Specification for an assertion parameter."""

    name: str
    description: str
    required: bool = True
    example: str = ""


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
        description="Check that a regex pattern exists in a file. Uses Python regex syntax.",
        params=(
            _FILE,
            ParamSpec("pattern", "Python regex pattern to search for", example="force_https\\s*=\\s*true"),
            ParamSpec("scope_start", "Regex pattern marking the start of the search scope within the file. Only content between scope_start and scope_end is searched.", required=False, example="class.*Client"),
            ParamSpec("scope_end", "Regex pattern marking the end of the search scope. Defaults to end of file if omitted.", required=False, example="^class |\\Z"),
            ParamSpec("multiline", "If true, ^ and $ match line boundaries instead of string boundaries (re.MULTILINE). Default: false.", required=False, example="true"),
            ParamSpec("dotall", "If true, . matches newlines, enabling patterns that span multiple lines (re.DOTALL). Default: false.", required=False, example="true"),
        ),
    ),
    AssertionTypeSpec(
        name="pattern_absent",
        description="Check that a regex pattern does NOT exist in a file. Uses Python regex syntax.",
        params=(
            _FILE,
            ParamSpec("pattern", "Python regex pattern that must be absent", example="verify\\s*=\\s*False"),
            ParamSpec("scope_start", "Regex pattern marking the start of the search scope within the file. Only content between scope_start and scope_end is checked for absence.", required=False, example="class.*Client"),
            ParamSpec("scope_end", "Regex pattern marking the end of the search scope. Defaults to end of file if omitted.", required=False, example="^class |\\Z"),
            ParamSpec("multiline", "If true, ^ and $ match line boundaries instead of string boundaries (re.MULTILINE). Default: false.", required=False, example="true"),
            ParamSpec("dotall", "If true, . matches newlines, enabling patterns that span multiple lines (re.DOTALL). Default: false.", required=False, example="true"),
        ),
    ),
    AssertionTypeSpec(
        name="no_plaintext_secret",
        description="Check that no plaintext secrets matching given patterns exist in a file.",
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
        description="Check that a config value matches a regex pattern.",
        params=(
            _FILE,
            ParamSpec("key", "Config key (dot notation for nested)", example="http_service.force_https"),
            ParamSpec("pattern", "Regex pattern the value must match", example="True|true"),
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
        name="test_passes",
        description="Run tests matching a pattern and verify they pass. Auto-detects pytest, npm test, cargo test.",
        params=(
            ParamSpec("pattern", "Test name or pattern to match", example="test_auth"),
        ),
    ),
)

# -- Derived lookups --

ASSERTION_TYPE_NAMES: frozenset[str] = frozenset(t.name for t in ASSERTION_TYPES)

ASSERTION_PARAM_SCHEMAS: dict[str, list[str]] = {
    t.name: t.required_params for t in ASSERTION_TYPES
}


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

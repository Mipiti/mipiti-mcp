#!/usr/bin/env python3
"""Regenerate dependency lockfiles with SHA-256 hashes.

Run after changing dependencies in pyproject.toml (or the build/audit
input files):
    python lock-deps.py

Produces four hash-pinned lockfiles, all installable with
`pip install --require-hashes`:
  - requirements.lock        runtime deps (from pyproject.toml)
  - requirements-all.lock    runtime + dev extras (from pyproject.toml)
  - requirements-build.lock  build toolchain (from requirements-build.in)
  - requirements-audit.lock  pinned pip-audit (from requirements-audit.in)
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def run(args: list[str]) -> None:
    subprocess.check_call([sys.executable, "-m", "uv", "pip", "compile", *args], cwd=ROOT)


def strip_self_reference(path: Path) -> None:
    """Remove the mipiti-mcp self-referencing file:// line from lockfile."""
    lines = path.read_text().splitlines(keepends=True)
    filtered = []
    skip_next_via = False
    for line in lines:
        if line.startswith("# WARNING") and "hashed" in line:
            skip_next_via = True
            continue
        if line.startswith("# Consider using"):
            continue
        if line.startswith("mipiti-mcp"):
            skip_next_via = True
            continue
        if skip_next_via and line.strip().startswith("# via"):
            skip_next_via = False
            continue
        skip_next_via = False
        filtered.append(line)
    path.write_text("".join(filtered))


def main() -> None:
    # Target 3.11 (our requires-python floor) so the lock is valid on the
    # lowest supported interpreter and transitive deps that only ship on
    # older Pythons are still resolved. --universal resolves across all
    # platforms so platform-conditional transitives (e.g. keyring's Linux-only
    # SecretStorage/jeepney, Windows pywin32-ctypes) are pinned with hashes —
    # required for --require-hashes installs on a CI platform other than the
    # one the lock was compiled on.
    common = ["--universal", "--generate-hashes", "--strip-extras", "--python-version=3.11"]

    print("Compiling requirements.lock ...")
    run([*common, "-o", "requirements.lock", "pyproject.toml"])

    print("Compiling requirements-all.lock ...")
    run([*common, "--extra=dev", "-o", "requirements-all.lock", "pyproject.toml"])
    strip_self_reference(ROOT / "requirements-all.lock")

    print("Compiling requirements-build.lock ...")
    run([
        "--universal",
        "--generate-hashes",
        "--python-version=3.11",
        "-o",
        "requirements-build.lock",
        "requirements-build.in",
    ])

    print("Compiling requirements-audit.lock ...")
    run([
        "--universal",
        "--generate-hashes",
        "--python-version=3.11",
        "-o",
        "requirements-audit.lock",
        "requirements-audit.in",
    ])

    print("Done. Review and commit the four lockfiles.")


if __name__ == "__main__":
    main()

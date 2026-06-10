#!/usr/bin/env bash
# canonical-counts.sh — single source of truth for numeric facts cited
# in this repo's docs (README.md etc.).
#
# Same shape as the parent repo's scripts/canonical-counts.sh, scoped
# to mipiti-mcp's own truths. Each metric is a function returning the
# canonical count to stdout.
#
# Usage:
#   source scripts/canonical-counts.sh
#   echo "MCP tools: $(mcp_tool_count)"

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# MCP tool count: number of @mcp.tool() decorators registered on the
# server. The hosted /mcp endpoint imports this same package so the
# parent's canonical-counts.sh reads the same file via the submodule
# pointer — counts agree by construction at any pinned SHA.
mcp_tool_count() {
  grep -c '^@mcp.tool' "$REPO_ROOT/src/mipiti_mcp/server.py"
}

# Assertion type count: number of AssertionTypeSpec entries in the
# canonical assertion schema. The backend and mipiti-verify consume
# this same schema, so docs citing "N assertion types" stay in sync
# with the package by construction.
assertion_type_count() {
  grep -c '^    AssertionTypeSpec(' "$REPO_ROOT/src/mipiti_mcp/assertion_types.py"
}

# Package version (PyPI release tag).
package_version() {
  grep -E '^version[[:space:]]*=' "$REPO_ROOT/pyproject.toml" \
    | head -1 \
    | sed -E 's/.*"([^"]+)".*/\1/'
}

emit_all_counts() {
  cat <<EOF
mcp_tool_count=$(mcp_tool_count)
assertion_type_count=$(assertion_type_count)
package_version="$(package_version)"
EOF
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  emit_all_counts
fi

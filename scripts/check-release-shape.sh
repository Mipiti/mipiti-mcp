#!/usr/bin/env bash
# check-release-shape.sh — assert that the tree about to be published is a
# genuine release of this repository.
#
# A release is produced by the parent repository's release pipeline, which
# opens a version-bump PR that changes exactly the `version = "..."` line of
# pyproject.toml and adds the version's CHANGELOG.md section, squash-merges
# it onto main as `chore: release vX.Y.Z`, and tags the merged commit
# `vX.Y.Z`. The publish workflow accepts nothing else: every property of
# that shape is checked here, and any deviation fails closed before a
# package is built.
#
# Invariants enforced (all must hold):
#   1. The tag `v<version>` exists and is an ancestor of origin/main.
#   2. The tree being built is the tag's commit (HEAD == tag commit).
#   3. pyproject.toml's `version` equals the tag's version.
#   4. The tag commit has one parent and touches only CHANGELOG.md and
#      pyproject.toml: in pyproject.toml a single version-line replacement
#      to <version>, in CHANGELOG.md one added block, removing nothing,
#      whose first non-blank line is `## [<version>] - YYYY-MM-DD`.
#   5. The tag commit's subject is `chore: release v<version>`, allowing
#      the ` (#NNN)` suffix a squash-merge appends.
#
# Usage:
#   scripts/check-release-shape.sh <tag>            # e.g. v0.72.0
#   RELEASE_HEAD=<sha> scripts/check-release-shape.sh <tag>   # test hook
#
# RELEASE_HEAD overrides the commit compared against the tag (defaults to
# HEAD) so the check can be exercised against arbitrary commits locally.
# MAIN_REF overrides the branch the tag must be reachable from (defaults
# to origin/main).
#
# Exit: 0 when every invariant holds, 1 otherwise. Failures are reported
# as GitHub Actions `::error::` annotations so they surface on the run.

set -euo pipefail

TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "::error::check-release-shape: a tag argument is required"
  exit 1
fi

MAIN_REF="${MAIN_REF:-origin/main}"

fail() {
  echo "::error::$1"
  exit 1
}

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "tag '$TAG' is not of the form vX.Y.Z" ;;
esac
VERSION="${TAG#v}"
if ! printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  fail "tag '$TAG' is not of the form vX.Y.Z"
fi

# 1. The tag exists and is on main.
TAG_COMMIT=$(git rev-parse -q --verify "refs/tags/${TAG}^{commit}" 2>/dev/null || true)
if [ -z "$TAG_COMMIT" ]; then
  fail "tag '$TAG' does not exist in this repository"
fi
if ! git rev-parse -q --verify "${MAIN_REF}^{commit}" >/dev/null 2>&1; then
  fail "branch '$MAIN_REF' is not available; the check needs the full history of main"
fi
if ! git merge-base --is-ancestor "$TAG_COMMIT" "$MAIN_REF"; then
  fail "tag '$TAG' ($TAG_COMMIT) is not reachable from $MAIN_REF"
fi

# 2. The tree being built is the tagged commit.
HEAD_COMMIT=$(git rev-parse "${RELEASE_HEAD:-HEAD}^{commit}")
if [ "$HEAD_COMMIT" != "$TAG_COMMIT" ]; then
  fail "the checked-out commit $HEAD_COMMIT is not the commit tagged $TAG ($TAG_COMMIT); run the workflow from the tag itself"
fi

# 3. pyproject.toml carries the tag's version.
PY_VERSION=$(git show "${TAG_COMMIT}:pyproject.toml" | sed -nE 's/^version = "([^"]*)"$/\1/p')
if [ "$(printf '%s\n' "$PY_VERSION" | wc -l | tr -d ' ')" != "1" ] || [ -z "$PY_VERSION" ]; then
  fail "pyproject.toml at $TAG does not carry exactly one 'version = \"...\"' line"
fi
if [ "$PY_VERSION" != "$VERSION" ]; then
  fail "tag $TAG does not match pyproject.toml version '$PY_VERSION'"
fi

# 4. The release commit changes the version line of pyproject.toml and adds
#    the version's CHANGELOG.md section, and nothing else.
PARENTS=$(git rev-list --parents -n 1 "$TAG_COMMIT" | wc -w | tr -d ' ')
if [ "$PARENTS" != "2" ]; then
  fail "release commit $TAG_COMMIT must have exactly one parent (found $((PARENTS - 1)))"
fi
CHANGED=$(git diff --name-only "${TAG_COMMIT}^" "$TAG_COMMIT" | tr '\n' ' ')
if [ "$CHANGED" != "CHANGELOG.md pyproject.toml " ]; then
  fail "release commit $TAG_COMMIT must change only CHANGELOG.md and pyproject.toml; it changes: $CHANGED"
fi
SECTION=$(git diff --unified=0 "${TAG_COMMIT}^" "$TAG_COMMIT" -- CHANGELOG.md | grep -E '^(@@|[-+])' | grep -vE '^(\+\+\+|---) ' || true)
# The first added line that is not blank: a diff may place the block's
# surrounding blank line on either side of it.
FIRST_ADDED=$(printf '%s\n' "$SECTION" | grep -m1 -E '^\+.' || true)
VERSION_RE=$(printf '%s' "$VERSION" | sed 's/\./\\./g')
if [ "$(printf '%s\n' "$SECTION" | grep -c '^@@')" != "1" ] \
   || printf '%s\n' "$SECTION" | grep -qE '^-' \
   || ! printf '%s\n' "$FIRST_ADDED" | grep -qxE "\+## \[${VERSION_RE}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}"; then
  fail "release commit $TAG_COMMIT must add only the CHANGELOG.md section for $VERSION, as one block opening with its heading"
fi
# Every changed line, with the file headers stripped.
HUNK=$(git diff --unified=0 "${TAG_COMMIT}^" "$TAG_COMMIT" -- pyproject.toml | grep -E '^[-+]' | grep -vE '^(\+\+\+|---) ' || true)
EXPECTED_ADD="+version = \"${VERSION}\""
ADDED=$(printf '%s\n' "$HUNK" | grep -E '^\+' || true)
REMOVED=$(printf '%s\n' "$HUNK" | grep -E '^-' || true)
if [ "$ADDED" != "$EXPECTED_ADD" ]; then
  fail "release commit $TAG_COMMIT must add exactly one line, '$EXPECTED_ADD'"
fi
if ! printf '%s' "$REMOVED" | grep -qE '^-version = "[0-9]+\.[0-9]+\.[0-9]+"$' \
   || [ "$(printf '%s\n' "$REMOVED" | wc -l | tr -d ' ')" != "1" ]; then
  fail "release commit $TAG_COMMIT must remove exactly one previous version line"
fi

# 5. The release commit's subject is the pipeline's bump message.
SUBJECT=$(git log -1 --format=%s "$TAG_COMMIT" | sed -E 's/ \(#[0-9]+\)$//')
if [ "$SUBJECT" != "chore: release v${VERSION}" ]; then
  fail "release commit subject '$SUBJECT' is not 'chore: release v${VERSION}'"
fi

echo "release shape verified: $TAG -> $TAG_COMMIT (pyproject.toml version $PY_VERSION)"
